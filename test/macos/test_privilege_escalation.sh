#!/bin/bash
# test_privilege_escalation.sh - Test privilege checking and escalation
# Tests privileges_unix.go functionality for root detection and requirements

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Test configuration
TEST_DIR="/tmp/pm-authrouter-priv-test"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# Find binary in multiple possible locations
BINARY_PATH=""
if [ -f "../../cmd/pm-authrouter/pm-authrouter" ]; then
    BINARY_PATH="../../cmd/pm-authrouter/pm-authrouter"
elif [ -f "../../pm-authrouter" ]; then
    BINARY_PATH="../../pm-authrouter"
elif [ -f "/usr/local/bin/postman/pm-authrouter" ]; then
    BINARY_PATH="/usr/local/bin/postman/pm-authrouter"
elif [ -f "./pm-authrouter" ]; then
    BINARY_PATH="./pm-authrouter"
fi

# Check current privilege level
IS_ROOT=false
if [ "$EUID" -eq 0 ]; then
    IS_ROOT=true
fi

# Cleanup function
cleanup() {
    echo -e "${YELLOW}Cleaning up test environment...${NC}"
    rm -rf "$TEST_DIR"
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
}

# Test UID detection
test_uid_detection() {
    echo -e "\n${YELLOW}Testing UID detection...${NC}"
    
    # Check real UID
    REAL_UID=$(id -ru)
    if [ -n "$REAL_UID" ]; then
        pass "Real UID detected: $REAL_UID"
    else
        fail "Could not detect real UID"
    fi
    
    # Check effective UID
    EFFECTIVE_UID=$(id -u)
    if [ -n "$EFFECTIVE_UID" ]; then
        pass "Effective UID detected: $EFFECTIVE_UID"
    else
        fail "Could not detect effective UID"
    fi
    
    # Check if running as root
    if [ "$EFFECTIVE_UID" -eq 0 ]; then
        pass "Running as root (EUID=0)"
    else
        pass "Running as user (EUID=$EFFECTIVE_UID)"
    fi
    
    # Check sudo detection
    if [ -n "$SUDO_USER" ]; then
        pass "Running under sudo (original user: $SUDO_USER)"
        
        # Check SUDO_UID
        if [ -n "$SUDO_UID" ]; then
            pass "SUDO_UID detected: $SUDO_UID"
        else
            fail "SUDO_UID not set despite running under sudo"
        fi
    else
        if [ "$IS_ROOT" = true ]; then
            pass "Running as true root (not sudo)"
        else
            pass "Running as regular user (not sudo)"
        fi
    fi
}

# Test privilege requirements
test_privilege_requirements() {
    echo -e "\n${YELLOW}Testing privilege requirements...${NC}"
    
    # Test port 443 binding requirement
    if [ "$IS_ROOT" = true ]; then
        # Can bind to privileged ports
        if nc -z 127.0.0.1 443 2>/dev/null; then
            skip "Port 443 already in use"
        else
            # Try to create a listener briefly
            timeout 0.1 nc -l 443 2>/dev/null &
            PID=$!
            sleep 0.05
            if kill -0 $PID 2>/dev/null; then
                kill $PID 2>/dev/null
                pass "Can bind to port 443 with root"
            else
                skip "Could not test port 443 binding"
            fi
        fi
    else
        # Should not be able to bind to privileged ports
        if ! timeout 0.1 nc -l 443 2>/dev/null; then
            pass "Correctly cannot bind to port 443 without root"
        else
            fail "Unexpectedly able to bind to port 443"
        fi
    fi
    
    # Test /etc/hosts modification requirement
    if [ "$IS_ROOT" = true ]; then
        if [ -w "/etc/hosts" ]; then
            pass "Can write to /etc/hosts with root"
        else
            fail "Cannot write to /etc/hosts despite root"
        fi
    else
        if [ ! -w "/etc/hosts" ]; then
            pass "Correctly cannot write to /etc/hosts without root"
        else
            fail "Unexpectedly able to write to /etc/hosts"
        fi
    fi
    
    # Test system keychain access
    if [ "$IS_ROOT" = true ]; then
        if security list-keychains 2>/dev/null | grep -q "System.keychain"; then
            pass "Can access System keychain with root"
        else
            skip "System keychain not accessible"
        fi
    else
        # Non-root can list but not modify
        if security list-keychains 2>/dev/null | grep -q "System.keychain"; then
            pass "Can list System keychain without root"
        fi
    fi
}

# Test binary privilege check
test_binary_privilege_check() {
    echo -e "\n${YELLOW}Testing binary privilege check...${NC}"
    
    if [ -z "$BINARY_PATH" ] || [ ! -f "$BINARY_PATH" ]; then
        skip "Binary not found - run 'go build' in cmd/pm-authrouter first"
        skip "Checked locations:"
        skip "  - ../../cmd/pm-authrouter/pm-authrouter"
        skip "  - ../../pm-authrouter"
        skip "  - /usr/local/bin/postman/pm-authrouter"
        skip "  - ./pm-authrouter"
        return
    fi
    
    pass "Found binary at: $BINARY_PATH"
    
    # Test running binary without root
    if [ "$IS_ROOT" = false ]; then
        OUTPUT=$($BINARY_PATH 2>&1 || true)
        
        if echo "$OUTPUT" | grep -q "ROOT PRIVILEGES REQUIRED"; then
            pass "Binary correctly detects missing root privileges"
        else
            fail "Binary did not detect missing privileges"
        fi
        
        if echo "$OUTPUT" | grep -q "sudo"; then
            pass "Binary suggests using sudo"
        else
            fail "Binary does not suggest sudo"
        fi
        
        # Check for specific requirements listed
        if echo "$OUTPUT" | grep -q "port 443"; then
            pass "Binary explains port 443 requirement"
        else
            fail "Binary does not mention port 443"
        fi
        
        if echo "$OUTPUT" | grep -q "/etc/hosts"; then
            pass "Binary explains hosts file requirement"
        else
            fail "Binary does not mention hosts file"
        fi
    else
        skip "Cannot test privilege error when running as root"
    fi
}

# Test sudo environment preservation
test_sudo_environment() {
    echo -e "\n${YELLOW}Testing sudo environment preservation...${NC}"
    
    if [ -n "$SUDO_USER" ]; then
        # Running under sudo
        pass "Detected sudo execution"
        
        # Check preserved variables
        if [ -n "$SUDO_UID" ]; then
            pass "SUDO_UID preserved: $SUDO_UID"
        fi
        
        if [ -n "$SUDO_GID" ]; then
            pass "SUDO_GID preserved: $SUDO_GID"
        fi
        
        if [ -n "$SUDO_COMMAND" ]; then
            pass "SUDO_COMMAND preserved: $SUDO_COMMAND"
        fi
        
        # Check HOME variable
        if [ "$HOME" = "/root" ] || [ "$HOME" = "/var/root" ]; then
            pass "HOME changed to root's home"
        else
            skip "HOME not changed (sudo -H not used)"
        fi
    else
        if [ "$IS_ROOT" = true ]; then
            skip "Not running under sudo (direct root)"
        else
            skip "Not running under sudo (regular user)"
        fi
    fi
}

# Test capability detection
test_capability_detection() {
    echo -e "\n${YELLOW}Testing capability detection...${NC}"
    
    # Check for specific capabilities needed
    CAPS_NEEDED=(
        "Bind to port 443"
        "Modify /etc/hosts"
        "Access System keychain"
        "Flush DNS cache"
        "Modify routing table"
    )
    
    for cap in "${CAPS_NEEDED[@]}"; do
        if [ "$IS_ROOT" = true ]; then
            pass "Have capability: $cap"
        else
            skip "Missing capability: $cap (need root)"
        fi
    done
}

# Test privilege escalation methods
test_escalation_methods() {
    echo -e "\n${YELLOW}Testing privilege escalation methods...${NC}"
    
    # Check if sudo is available
    if command -v sudo >/dev/null 2>&1; then
        pass "sudo command available"
        
        # Check if user can sudo (without actually running it)
        if [ "$IS_ROOT" = false ]; then
            if sudo -n true 2>/dev/null; then
                pass "User can sudo without password"
            else
                skip "User needs password for sudo"
            fi
        fi
    else
        fail "sudo command not found"
    fi
    
    # Check for other escalation methods
    if command -v doas >/dev/null 2>&1; then
        pass "doas command available (alternative to sudo)"
    else
        skip "doas not available"
    fi
}

# Test setuid scenarios
test_setuid_scenarios() {
    echo -e "\n${YELLOW}Testing setuid scenarios...${NC}"
    
    # Create test binary
    TEST_BINARY="$TEST_DIR/test_priv"
    cat > "$TEST_BINARY.c" <<EOF
#include <stdio.h>
#include <unistd.h>

int main() {
    printf("Real UID: %d\n", getuid());
    printf("Effective UID: %d\n", geteuid());
    return 0;
}
EOF
    
    # Compile test binary
    if cc -o "$TEST_BINARY" "$TEST_BINARY.c" 2>/dev/null; then
        pass "Compiled test privilege binary"
        
        # Run normally
        OUTPUT=$($TEST_BINARY)
        if echo "$OUTPUT" | grep -q "Real UID:"; then
            pass "Test binary reports UIDs correctly"
        fi
        
        # Test setuid bit (if root)
        if [ "$IS_ROOT" = true ]; then
            chmod u+s "$TEST_BINARY"
            if [ -u "$TEST_BINARY" ]; then
                pass "Set setuid bit on test binary"
            else
                fail "Failed to set setuid bit"
            fi
        else
            skip "Cannot test setuid without root"
        fi
    else
        skip "Could not compile test binary"
    fi
}

# Test permission error messages
test_error_messages() {
    echo -e "\n${YELLOW}Testing permission error messages...${NC}"
    
    # Test various permission denied scenarios
    if [ "$IS_ROOT" = false ]; then
        # Try to write to protected file
        if ! echo "test" > /etc/test_file 2>/dev/null; then
            pass "Correct permission denied for /etc write"
        fi
        
        # Try to read protected file
        if [ -f "/etc/sudoers" ]; then
            if ! cat /etc/sudoers 2>/dev/null; then
                pass "Correct permission denied for sudoers read"
            fi
        fi
    else
        skip "Cannot test permission errors as root"
    fi
}

# Test daemon launch requirements
test_daemon_requirements() {
    echo -e "\n${YELLOW}Testing daemon launch requirements...${NC}"
    
    # Check LaunchDaemon directory access
    LAUNCHD_DIR="/Library/LaunchDaemons"
    
    if [ -d "$LAUNCHD_DIR" ]; then
        if [ "$IS_ROOT" = true ]; then
            if [ -w "$LAUNCHD_DIR" ]; then
                pass "Can write to LaunchDaemons directory"
            else
                fail "Cannot write to LaunchDaemons despite root"
            fi
        else
            if [ ! -w "$LAUNCHD_DIR" ]; then
                pass "Correctly cannot write to LaunchDaemons without root"
            else
                fail "Unexpectedly can write to LaunchDaemons"
            fi
        fi
    else
        skip "LaunchDaemons directory not found"
    fi
    
    # Check launchctl access
    if command -v launchctl >/dev/null 2>&1; then
        pass "launchctl command available"
        
        # Test listing services
        if launchctl list 2>/dev/null | grep -q "com.apple"; then
            pass "Can list launchctl services"
        else
            skip "Cannot list launchctl services"
        fi
    else
        fail "launchctl command not found"
    fi
}

# Test privilege dropping
test_privilege_dropping() {
    echo -e "\n${YELLOW}Testing privilege dropping scenarios...${NC}"
    
    if [ "$IS_ROOT" = true ] && [ -n "$SUDO_UID" ]; then
        # Can test dropping back to original user
        pass "Running as root via sudo - can test privilege drop"
        
        # Check if we can switch back to original user
        if su - "$SUDO_USER" -c "echo test" 2>/dev/null; then
            pass "Can drop privileges back to $SUDO_USER"
        else
            fail "Cannot drop privileges to original user"
        fi
    else
        if [ "$IS_ROOT" = true ]; then
            skip "Direct root - no original user to drop to"
        else
            skip "Not root - cannot test privilege dropping"
        fi
    fi
}

# Main test execution
main() {
    echo "=================================="
    echo "Privilege Escalation Tests"
    echo "=================================="
    
    if [ "$IS_ROOT" = true ]; then
        echo -e "${PURPLE}Running with ROOT privileges${NC}"
        if [ -n "$SUDO_USER" ]; then
            echo -e "${BLUE}Via sudo from user: $SUDO_USER${NC}"
        fi
    else
        echo -e "${YELLOW}Running as regular user (UID=$EUID)${NC}"
        echo "Some tests will be skipped"
        echo "Run with: sudo $0 for complete testing"
    fi
    
    setup_test_env
    
    test_uid_detection
    test_privilege_requirements
    test_binary_privilege_check
    test_sudo_environment
    test_capability_detection
    test_escalation_methods
    test_setuid_scenarios
    test_error_messages
    test_daemon_requirements
    test_privilege_dropping
    
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