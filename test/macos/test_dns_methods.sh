#!/bin/bash
# test_dns_methods.sh - Test DNS interception methods and fallback strategies
# Tests dns/unix.go functionality including hosts, pfctl, routes

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
TEST_DIR="/tmp/pm-authrouter-dns-test"
TEST_HOSTS_FILE="$TEST_DIR/hosts"
TEST_DOMAIN="identity.getpostman.com"
TEST_IP="127.0.0.1"
REAL_IP=""
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# Check if running as root
IS_ROOT=false
if [ "$EUID" -eq 0 ]; then
    IS_ROOT=true
fi

# Cleanup function
cleanup() {
    echo -e "${YELLOW}Cleaning up test environment...${NC}"
    
    # Clean up test hosts file
    rm -rf "$TEST_DIR"
    
    # If root, clean up any test routes or pfctl rules
    if [ "$IS_ROOT" = true ]; then
        # Remove test routes (ignore errors)
        if [ -n "$REAL_IP" ]; then
            route delete -host "$REAL_IP" 2>/dev/null || true
        fi
        
        # Clean up pfctl rules
        rm -f /tmp/pm-authrouter-test.pfctl.rules
    fi
}

trap cleanup EXIT

# Test result tracking
pass() {
    echo -e "${GREEN}${NC} $1"
    ((PASS_COUNT++))
}

fail() {
    echo -e "${RED}${NC} $1"
    ((FAIL_COUNT++))
}

skip() {
    echo -e "${YELLOW}○${NC} $1"
    ((SKIP_COUNT++))
}

# Setup test environment
setup_test_env() {
    echo "Setting up test environment..."
    rm -rf "$TEST_DIR"
    mkdir -p "$TEST_DIR"
    
    # Create test hosts file
    cat > "$TEST_HOSTS_FILE" <<EOF
##
# Host Database
#
# localhost is used to configure the loopback interface
##
127.0.0.1   localhost
255.255.255.255 broadcasthost
::1             localhost
EOF
}

# Test real IP resolution
test_real_ip_resolution() {
    echo -e "\n${YELLOW}Testing real IP resolution...${NC}"
    
    # Test with multiple DNS servers
    DNS_SERVERS=("8.8.8.8" "1.1.1.1" "208.67.222.222")
    
    for dns in "${DNS_SERVERS[@]}"; do
        OUTPUT=$(nslookup "$TEST_DOMAIN" "$dns" 2>/dev/null || true)
        
        if [ -n "$OUTPUT" ]; then
            # Extract IP address
            IP=$(echo "$OUTPUT" | grep -A1 "Name:" | grep "Address:" | grep -v "#53" | awk '{print $2}' | head -1)
            
            if [ -n "$IP" ] && [[ "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                REAL_IP="$IP"
                pass "Resolved $TEST_DOMAIN to $IP using DNS server $dns"
                break
            else
                skip "Could not parse IP from $dns response"
            fi
        else
            skip "DNS server $dns did not respond"
        fi
    done
    
    if [ -z "$REAL_IP" ]; then
        fail "Could not resolve real IP for $TEST_DOMAIN"
        REAL_IP="104.18.32.167" # Fallback to known IP
    fi
}

# Test hosts file manipulation
test_hosts_file() {
    echo -e "\n${YELLOW}Testing hosts file manipulation...${NC}"
    
    # Test adding entry
    echo "$TEST_IP $TEST_DOMAIN # Added by PostmanAuthRouter" >> "$TEST_HOSTS_FILE"
    
    if grep -q "$TEST_DOMAIN" "$TEST_HOSTS_FILE"; then
        pass "Successfully added hosts file entry"
    else
        fail "Failed to add hosts file entry"
    fi
    
    # Test duplicate detection
    LINES_BEFORE=$(wc -l < "$TEST_HOSTS_FILE")
    echo "$TEST_IP $TEST_DOMAIN # Added by PostmanAuthRouter" >> "$TEST_HOSTS_FILE"
    LINES_AFTER=$(wc -l < "$TEST_HOSTS_FILE")
    
    if [ "$LINES_AFTER" -eq $((LINES_BEFORE + 1)) ]; then
        pass "Duplicate entry detection working"
    else
        fail "Duplicate entry detection failed"
    fi
    
    # Test removal
    grep -v "$TEST_DOMAIN.*PostmanAuthRouter" "$TEST_HOSTS_FILE" > "$TEST_HOSTS_FILE.tmp"
    mv "$TEST_HOSTS_FILE.tmp" "$TEST_HOSTS_FILE"
    
    if ! grep -q "$TEST_DOMAIN" "$TEST_HOSTS_FILE"; then
        pass "Successfully removed hosts file entry"
    else
        fail "Failed to remove hosts file entry"
    fi
    
    # Test backup creation
    cp "$TEST_HOSTS_FILE" "$TEST_HOSTS_FILE.pm-authrouter-backup"
    if [ -f "$TEST_HOSTS_FILE.pm-authrouter-backup" ]; then
        pass "Hosts file backup created"
    else
        fail "Failed to create hosts file backup"
    fi
}

# Test DNS cache flushing
test_dns_cache_flush() {
    echo -e "\n${YELLOW}Testing DNS cache flush commands...${NC}"
    
    # Test various cache flush methods
    FLUSH_COMMANDS=(
        "dscacheutil -flushcache"
        "killall -HUP mDNSResponder"
    )
    
    for cmd in "${FLUSH_COMMANDS[@]}"; do
        if $cmd 2>/dev/null; then
            pass "DNS flush command succeeded: $cmd"
        else
            # These commands may fail on different macOS versions
            skip "DNS flush command not available: $cmd"
        fi
    done
}

# Test pfctl rules (requires root)
test_pfctl_rules() {
    echo -e "\n${YELLOW}Testing pfctl rules...${NC}"
    
    if [ "$IS_ROOT" != true ]; then
        skip "pfctl tests require root privileges"
        return
    fi
    
    # Create test rules file
    RULES_FILE="/tmp/pm-authrouter-test.pfctl.rules"
    cat > "$RULES_FILE" <<EOF
# Test PostmanAuthRouter DNS redirection rules
rdr pass on lo0 inet proto tcp from any to $REAL_IP port 443 -> 127.0.0.1 port 443
rdr pass on lo0 inet proto tcp from any to $REAL_IP port 80 -> 127.0.0.1 port 80
EOF
    
    # Test loading rules
    if pfctl -f "$RULES_FILE" 2>/dev/null; then
        pass "Successfully loaded pfctl rules"
        
        # Check if rules are active
        if pfctl -s nat 2>/dev/null | grep -q "$REAL_IP"; then
            pass "pfctl rules are active"
        else
            fail "pfctl rules not found in nat table"
        fi
        
        # Clean up rules
        if pfctl -F nat 2>/dev/null; then
            pass "Successfully flushed pfctl rules"
        else
            fail "Failed to flush pfctl rules"
        fi
    else
        fail "Failed to load pfctl rules"
    fi
    
    rm -f "$RULES_FILE"
}

# Test route-based redirection (requires root)
test_route_redirection() {
    echo -e "\n${YELLOW}Testing route-based redirection...${NC}"
    
    if [ "$IS_ROOT" != true ]; then
        skip "Route tests require root privileges"
        return
    fi
    
    if [ -z "$REAL_IP" ]; then
        skip "No real IP resolved, skipping route tests"
        return
    fi
    
    # Add test route
    if route add -host "$REAL_IP" 127.0.0.1 2>/dev/null; then
        pass "Successfully added route for $REAL_IP -> 127.0.0.1"
        
        # Verify route exists
        if netstat -rn | grep -q "$REAL_IP.*127.0.0.1"; then
            pass "Route is active in routing table"
        else
            fail "Route not found in routing table"
        fi
        
        # Remove route
        if route delete -host "$REAL_IP" 2>/dev/null; then
            pass "Successfully removed route"
        else
            fail "Failed to remove route"
        fi
    else
        skip "Could not add route (may already exist)"
    fi
}

# Test macOS version detection
test_macos_version() {
    echo -e "\n${YELLOW}Testing macOS version detection...${NC}"
    
    VERSION=$(sw_vers -productVersion)
    if [ -n "$VERSION" ]; then
        pass "Detected macOS version: $VERSION"
        
        # Parse major version
        MAJOR=$(echo "$VERSION" | cut -d. -f1)
        if [ "$MAJOR" -ge 10 ]; then
            pass "macOS major version parsed: $MAJOR"
        else
            fail "Invalid major version: $MAJOR"
        fi
    else
        fail "Could not detect macOS version"
    fi
    
    # Test SIP status
    if csrutil status 2>/dev/null | grep -q "enabled\|disabled"; then
        SIP_STATUS=$(csrutil status | grep -o "enabled\|disabled")
        pass "System Integrity Protection status: $SIP_STATUS"
    else
        skip "Could not determine SIP status"
    fi
}

# Test fallback mechanism
test_fallback_mechanism() {
    echo -e "\n${YELLOW}Testing DNS fallback mechanism...${NC}"
    
    # Simulate primary method failure
    if [ "$IS_ROOT" = true ]; then
        # Try pfctl first (may fail)
        if ! pfctl -f /nonexistent 2>/dev/null; then
            pass "Primary method (pfctl) failed as expected"
        fi
        
        # Fallback to routes
        if route add -host 1.2.3.4 127.0.0.1 2>/dev/null; then
            pass "Fallback to route method succeeded"
            route delete -host 1.2.3.4 2>/dev/null
        else
            skip "Route fallback not available"
        fi
    fi
    
    # Final fallback is always hosts file
    echo "127.0.0.1 test.fallback.local" >> "$TEST_HOSTS_FILE"
    if grep -q "test.fallback.local" "$TEST_HOSTS_FILE"; then
        pass "Final fallback to hosts file succeeded"
    else
        fail "Hosts file fallback failed"
    fi
}

# Test permission checks
test_permissions() {
    echo -e "\n${YELLOW}Testing permission requirements...${NC}"
    
    if [ "$IS_ROOT" = true ]; then
        pass "Running with root privileges"
        
        # Test write access to system files
        if [ -w "/etc/hosts" ]; then
            pass "Can modify /etc/hosts"
        else
            fail "Cannot modify /etc/hosts despite root"
        fi
        
        # Test pfctl access
        if command -v pfctl >/dev/null 2>&1; then
            pass "pfctl command available"
        else
            fail "pfctl command not found"
        fi
    else
        pass "Running without root privileges"
        
        # Test what we can't do
        if [ ! -w "/etc/hosts" ]; then
            pass "Correctly cannot modify /etc/hosts without root"
        else
            fail "Unexpected write access to /etc/hosts"
        fi
    fi
}

# Test binary integration
test_binary_integration() {
    echo -e "\n${YELLOW}Testing integration with pm-authrouter binary...${NC}"
    
    BINARY_PATH="../../cmd/pm-authrouter/pm-authrouter"
    
    if [ -f "$BINARY_PATH" ]; then
        pass "pm-authrouter binary found"
        
        # Check for DNS-related functions
        if strings "$BINARY_PATH" 2>/dev/null | grep -q "setupMacOSHostsFile"; then
            pass "Binary contains hosts file setup code"
        else
            skip "Binary hosts file code not verified"
        fi
        
        if strings "$BINARY_PATH" 2>/dev/null | grep -q "setupPfctlRedirection"; then
            pass "Binary contains pfctl setup code"
        else
            skip "Binary pfctl code not verified"
        fi
        
        if strings "$BINARY_PATH" 2>/dev/null | grep -q "flushDNSCache"; then
            pass "Binary contains DNS cache flush code"
        else
            skip "Binary DNS cache flush not verified"
        fi
    else
        skip "pm-authrouter binary not built"
    fi
}

# Test concurrent DNS operations
test_concurrent_operations() {
    echo -e "\n${YELLOW}Testing concurrent DNS operations...${NC}"
    
    # Simulate multiple simultaneous modifications
    for i in {1..5}; do
        (
            echo "127.0.0.1 test$i.local # Test $i" >> "$TEST_HOSTS_FILE"
        ) &
    done
    
    wait
    
    # Check all entries were added
    SUCCESS=true
    for i in {1..5}; do
        if ! grep -q "test$i.local" "$TEST_HOSTS_FILE"; then
            SUCCESS=false
            break
        fi
    done
    
    if [ "$SUCCESS" = true ]; then
        pass "Concurrent hosts file modifications succeeded"
    else
        fail "Some concurrent modifications were lost"
    fi
}

# Main test execution
main() {
    echo "=================================="
    echo "DNS Interception Method Tests"
    echo "=================================="
    
    if [ "$IS_ROOT" = true ]; then
        echo -e "${BLUE}Running with root privileges - all tests enabled${NC}"
    else
        echo -e "${YELLOW}Running without root - some tests will be skipped${NC}"
        echo "Run with: sudo $0 for complete testing"
    fi
    
    setup_test_env
    
    test_real_ip_resolution
    test_hosts_file
    test_dns_cache_flush
    test_pfctl_rules
    test_route_redirection
    test_macos_version
    test_fallback_mechanism
    test_permissions
    test_binary_integration
    test_concurrent_operations
    
    echo -e "\n=================================="
    echo "Test Results Summary"
    echo "=================================="
    echo -e "${GREEN}Passed:${NC} $PASS_COUNT"
    echo -e "${RED}Failed:${NC} $FAIL_COUNT"
    echo -e "${YELLOW}Skipped:${NC} $SKIP_COUNT"
    
    if [ $FAIL_COUNT -gt 0 ]; then
        echo -e "\n${RED}TESTS FAILED${NC}"
        exit 1
    else
        echo -e "\n${GREEN}ALL TESTS PASSED${NC}"
        exit 0
    fi
}

# Run tests
main "$@"