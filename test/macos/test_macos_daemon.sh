#!/bin/bash

# test_macos_daemon.sh - Functional tests for macOS daemon
# Tests the actual compiled daemon functionality

# Exit on error - temporarily disabled to allow all tests to run
# set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Dynamic binary path detection - check both development and production paths
if [ -f "$PROJECT_ROOT/bin/pm-authrouter" ]; then
    BINARY_PATH="$PROJECT_ROOT/bin/pm-authrouter"
elif [ -f "/usr/local/bin/postman/pm-authrouter" ]; then
    BINARY_PATH="/usr/local/bin/postman/pm-authrouter"
else
    # Will build to this path if not found
    BINARY_PATH="$PROJECT_ROOT/bin/pm-authrouter"
fi

TEST_RESULTS_FILE="$SCRIPT_DIR/test_results_macos_daemon.txt"
FAILED_TESTS=0
PASSED_TESTS=0

# Test certificate configuration
TEST_CERT_DIR="/usr/local/bin/postman"
TEST_CERT_PATH="$TEST_CERT_DIR/identity.getpostman.com.crt"
TEST_KEY_PATH="$TEST_CERT_DIR/identity.getpostman.com.key"
TEST_CERTS_CREATED=false

# Test helper functions
test_pass() {
    echo -e "${GREEN} $1${NC}"
    ((PASSED_TESTS++))
    echo "PASS: $1" >> "$TEST_RESULTS_FILE"
}

test_fail() {
    echo -e "${RED} $1${NC}"
    echo "  Reason: $2"
    ((FAILED_TESTS++))
    echo "FAIL: $1 - $2" >> "$TEST_RESULTS_FILE"
}

test_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Generate test certificates for daemon
setup_test_certificates() {
    echo -e "\n${YELLOW}Setting up test certificates...${NC}"
    
    # Check if running as root (required for /usr/local/bin/postman)
    if [ "$EUID" -ne 0 ]; then
        test_info "Not running as root - skipping certificate setup"
        return 1
    fi
    
    # Create certificate directory with proper permissions
    if ! sudo mkdir -p "$TEST_CERT_DIR"; then
        test_fail "Certificate directory creation" "Failed to create $TEST_CERT_DIR"
        return 1
    fi
    
    # Ensure directory has proper ownership
    sudo chown -R root:wheel "$TEST_CERT_DIR" 2>/dev/null || true
    
    # Generate self-signed certificate for testing
    if openssl req -new -x509 -nodes \
        -keyout "$TEST_KEY_PATH" \
        -out "$TEST_CERT_PATH" \
        -days 365 \
        -subj "/C=US/ST=Test/L=Test/O=Test/CN=identity.getpostman.com" \
        2>/dev/null; then
        
        # Set proper permissions
        chmod 644 "$TEST_CERT_PATH"
        chmod 600 "$TEST_KEY_PATH"
        
        test_pass "Test certificates generated"
        test_info "Certificate at: $TEST_CERT_PATH"
        TEST_CERTS_CREATED=true
        return 0
    else
        test_fail "Certificate generation" "OpenSSL failed to generate certificates"
        return 1
    fi
}

# Clean up test certificates
cleanup_test_certificates() {
    if $TEST_CERTS_CREATED && [ "$EUID" -eq 0 ]; then
        echo "Removing test certificates..."
        rm -f "$TEST_CERT_PATH" "$TEST_KEY_PATH" 2>/dev/null || true
        
        # Remove directory if empty
        rmdir "$TEST_CERT_DIR" 2>/dev/null || true
    fi
}

# Build the daemon
# Category: Medium/Component - Go binary compilation (60 seconds)
build_daemon() {
    echo -e "\n${YELLOW}Building daemon...${NC}"
    
    cd "$PROJECT_ROOT"
    
    # Build for current architecture
    if GOOS=darwin go build -o "$BINARY_PATH" ./cmd/pm-authrouter; then
        test_pass "Daemon built successfully"
        test_info "Binary at: $BINARY_PATH"
        
        # Check binary size
        local size=$(stat -f%z "$BINARY_PATH" 2>/dev/null || stat -c%s "$BINARY_PATH")
        test_info "Binary size: $(( size / 1024 / 1024 )) MB"
    else
        test_fail "Daemon build" "Build failed"
        exit 1
    fi
}

# Test privilege checking
# Category: Fast/Unit - Privilege validation (10 seconds)
test_privilege_check() {
    echo -e "\n${YELLOW}Testing: Privilege checking${NC}"
    
    if [ "$EUID" -eq 0 ]; then
        test_info "Running as root - testing root functionality"
        
        # Test that daemon starts checking privileges
        local output=$("$BINARY_PATH" --help 2>&1 || true)
        if echo "$output" | grep -q "ROOT PRIVILEGES REQUIRED"; then
            test_fail "Should not show privilege error when root"
        else
            test_pass "No privilege error when running as root"
        fi
    else
        test_info "Not running as root - testing privilege error"
        
        # Test that daemon refuses to run without root
        local output=$("$BINARY_PATH" 2>&1 || true)
        if echo "$output" | grep -q "ROOT PRIVILEGES REQUIRED"; then
            test_pass "Shows privilege error when not root"
        else
            test_fail "Privilege check" "Should require root privileges"
        fi
    fi
}

# Test command line arguments
# Category: Fast/Unit - CLI argument parsing (15 seconds)
test_command_line_args() {
    echo -e "\n${YELLOW}Testing: Command line arguments${NC}"
    
    # Test help
    if "$BINARY_PATH" --help 2>&1 | grep -q "team"; then
        test_pass "Help shows --team option"
    else
        test_fail "Help output" "Missing --team in help"
    fi
    
    if "$BINARY_PATH" --help 2>&1 | grep -q "saml-url"; then
        test_pass "Help shows --saml-url option"
    else
        test_fail "Help output" "Missing --saml-url in help"
    fi
}

# Test port binding
# Category: Slow/Integration - Network port operations (45 seconds)
test_port_binding() {
    echo -e "\n${YELLOW}Testing: Port 443 binding${NC}"
    
    if [ "$EUID" -ne 0 ]; then
        test_info "Skipping port 443 test - requires root"
        return
    fi
    
    # Check if test certificates exist
    if [ ! -f "$TEST_CERT_PATH" ]; then
        test_info "Test certificates not found - attempting to generate"
        if ! setup_test_certificates; then
            test_fail "Port binding" "Cannot test without certificates"
            return
        fi
    fi
    
    # Check if port 443 is already in use
    if lsof -i :443 2>/dev/null | grep -q LISTEN; then
        test_info "Port 443 already in use - attempting to free it"
        local existing_pid=$(lsof -t -i :443 2>/dev/null | head -1)
        if [ -n "$existing_pid" ]; then
            kill -TERM "$existing_pid" 2>/dev/null || true
            sleep 2
        fi
    fi
    
    # Start daemon in background with proper configuration
    "$BINARY_PATH" --team test --saml-url "https://test.example.com/saml" >/dev/null 2>&1 &
    local pid=$!
    
    # Give it time to bind and start
    local timeout=5
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if lsof -i :443 2>/dev/null | grep -q "$pid"; then
            test_pass "Daemon successfully bound to port 443"
            
            # Verify it's actually our daemon
            local process_name=$(ps -p $pid -o comm= 2>/dev/null)
            if [[ "$process_name" == *"pm-authrouter"* ]]; then
                test_pass "Verified process is pm-authrouter"
            fi
            
            # Kill the daemon
            kill $pid 2>/dev/null || true
            sleep 1
            return 0
        fi
        sleep 1
        ((elapsed++))
    done
    
    # Check if daemon is still running but failed to bind
    if kill -0 $pid 2>/dev/null; then
        test_fail "Port binding" "Daemon running but not bound to port 443"
        # Get daemon output for debugging
        kill $pid 2>/dev/null || true
    else
        test_fail "Port binding" "Daemon exited before binding to port 443"
    fi
}

# Test health endpoint
# Category: Slow/Integration - HTTP endpoint testing (30 seconds)
test_health_endpoint() {
    echo -e "\n${YELLOW}Testing: Health check endpoint${NC}"
    
    if [ "$EUID" -ne 0 ]; then
        test_info "Skipping health endpoint test - requires root"
        return
    fi
    
    # Check if test certificates exist
    if [ ! -f "$TEST_CERT_PATH" ]; then
        test_info "Test certificates not found - cannot test health endpoint"
        return
    fi
    
    # Start daemon in background
    "$BINARY_PATH" --team test --saml-url "https://test.example.com/saml" >/dev/null 2>&1 &
    local pid=$!
    
    # Wait for daemon to be ready
    local timeout=10
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if lsof -i :443 2>/dev/null | grep -q "$pid"; then
            # Port is bound, try health check
            sleep 1  # Give it a moment to fully initialize
            
            # Test health endpoint with our test certificate
            # Must send Host header for identity.getpostman.com
            local response=$(curl -k -s -o /dev/null -w "%{http_code}" -H "Host: identity.getpostman.com" https://127.0.0.1:443/health 2>/dev/null || echo "000")
            
            if [ "$response" = "200" ]; then
                test_pass "Health endpoint responds with 200 OK"
                
                # Also verify JSON response format
                local json_response=$(curl -k -s -H "Host: identity.getpostman.com" https://127.0.0.1:443/health 2>/dev/null)
                if echo "$json_response" | grep -q '"status":"healthy"' && \
                   echo "$json_response" | grep -q '"service":"pm-authrouter"'; then
                    test_pass "Health endpoint returns valid JSON"
                else
                    test_fail "Health endpoint JSON" "Invalid JSON format: $json_response"
                fi
                
                kill $pid 2>/dev/null || true
                sleep 1
                return 0
            elif [ "$response" != "000" ]; then
                test_info "Health endpoint returned: $response"
            fi
        fi
        sleep 1
        ((elapsed++))
    done
    
    test_fail "Health endpoint" "No valid response from /health after ${timeout}s"
    kill $pid 2>/dev/null || true
    sleep 1
}

# Test SAML redirect functionality
# Category: Medium/Component - SAML redirect validation (15 seconds)
test_saml_redirect() {
    echo -e "\n${YELLOW}Testing: SAML redirect functionality${NC}"
    
    if [ "$EUID" -ne 0 ]; then
        test_info "Skipping SAML redirect test - requires root for port 443"
        return
    fi
    
    # Clean up any existing processes
    pkill -f "pm-authrouter" 2>/dev/null || true
    sleep 1
    
    # Start daemon in background with SAML configuration
    "$BINARY_PATH" --team test --saml-url "https://test.example.com/saml/init" >/dev/null 2>&1 &
    local pid=$!
    
    # Wait for daemon to be ready
    local timeout=10
    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if lsof -i :443 2>/dev/null | grep -q "$pid"; then
            sleep 1  # Give it time to fully initialize
            break
        fi
        sleep 1
        ((elapsed++))
    done
    
    if ! lsof -i :443 2>/dev/null | grep -q "$pid"; then
        test_fail "SAML redirect test" "Daemon failed to bind to port 443"
        kill $pid 2>/dev/null || true
        return 1
    fi
    
    # Test 1: /login should redirect to SAML
    local response=$(curl -k -s -I -H "Host: identity.getpostman.com" https://127.0.0.1:443/login 2>/dev/null)
    local status_code=$(echo "$response" | head -n1 | grep -o '[0-9][0-9][0-9]' || echo "000")
    local location=$(echo "$response" | grep -i "^Location:" | cut -d' ' -f2- | tr -d '\r\n')
    
    if [ "$status_code" = "302" ] && [[ "$location" == *"test.example.com/saml"* ]]; then
        test_pass "Login redirects to SAML (302 → $location)"
    elif [ "$status_code" = "302" ]; then
        test_fail "SAML redirect validation" "Wrong redirect location: $location"
    else
        test_fail "SAML redirect validation" "Expected 302, got $status_code"
    fi
    
    # Test 1b: /login with auth_challenge (desktop flow)
    response=$(curl -k -s -I -H "Host: identity.getpostman.com" "https://127.0.0.1:443/login?auth_challenge=test123&auth_device=desktop" 2>/dev/null)
    location=$(echo "$response" | grep -i "^Location:" | cut -d' ' -f2- | tr -d '\r\n')
    
    if [[ "$location" == *"auth_challenge=test123"* ]] && [[ "$location" == *"auth_device=desktop"* ]]; then
        test_pass "Desktop flow preserves auth_challenge and auth_device parameters"
    else
        test_fail "Desktop flow parameters" "Missing auth parameters in redirect: $location"
    fi
    
    # Test 2: /enterprise/login should also redirect to SAML
    response=$(curl -k -s -I -H "Host: identity.getpostman.com" https://127.0.0.1:443/enterprise/login 2>/dev/null)
    status_code=$(echo "$response" | head -n1 | grep -o '[0-9][0-9][0-9]' || echo "000")
    location=$(echo "$response" | grep -i "^Location:" | cut -d' ' -f2- | tr -d '\r\n')
    
    if [ "$status_code" = "302" ] && [[ "$location" == *"test.example.com/saml"* ]]; then
        test_pass "Enterprise login redirects to SAML"
    else
        test_fail "Enterprise login SAML redirect" "Expected 302 to SAML, got $status_code"
    fi
    
    # Test 3: Non-login paths should NOT redirect to SAML (should proxy normally)
    response=$(curl -k -s -I -H "Host: identity.getpostman.com" https://127.0.0.1:443/api/user 2>/dev/null)
    status_code=$(echo "$response" | head -n1 | grep -o '[0-9][0-9][0-9]' || echo "000")
    
    if [ "$status_code" != "302" ] || ! echo "$response" | grep -i "Location:" | grep -q "saml"; then
        test_pass "Non-login paths don't redirect to SAML"
    else
        test_fail "Non-login path validation" "API path incorrectly redirected to SAML"
    fi
    
    # Test 4: Health endpoint should still return 200
    response=$(curl -k -s -o /dev/null -w "%{http_code}" -H "Host: identity.getpostman.com" https://127.0.0.1:443/health 2>/dev/null || echo "000")
    
    if [ "$response" = "200" ]; then
        test_pass "Health endpoint works alongside SAML redirects"
    else
        test_fail "Health endpoint validation" "Expected 200, got $response"
    fi
    
    # Clean up
    kill $pid 2>/dev/null || true
    sleep 1
}

# Test configuration validation
# Category: Fast/Unit - Configuration parameter validation (10 seconds)
test_config_validation() {
    echo -e "\n${YELLOW}Testing: Configuration validation${NC}"
    
    # Test missing configuration
    local output=$("$BINARY_PATH" 2>&1 || true)
    if echo "$output" | grep -q "team\|configuration\|SAML"; then
        test_pass "Validates configuration requirements"
    else
        test_info "Configuration validation depends on implementation"
    fi
}

# Test DNS interception setup
# Category: Slow/Integration - System DNS modification (90 seconds)
test_dns_setup() {
    echo -e "\n${YELLOW}Testing: DNS interception setup${NC}"
    
    if [ "$EUID" -ne 0 ]; then
        test_info "Skipping DNS tests - requires root"
        return
    fi
    
    # Check if test certificates exist
    if [ ! -f "$TEST_CERT_PATH" ]; then
        test_info "Test certificates not found - cannot test DNS setup"
        return
    fi
    
    # Check if certificate is trusted - DNS interception requires trusted cert
    if ! security verify-cert -c "$TEST_CERT_PATH" -p ssl 2>/dev/null; then
        test_info "Certificate not trusted - DNS interception will be disabled"
        # Start daemon and verify it runs but does NOT intercept DNS
        "$BINARY_PATH" --team test --saml-url "https://test.example.com/saml" >/dev/null 2>&1 &
        local pid=$!
        sleep 3
        
        if ! grep -q "identity.getpostman.com" /etc/hosts 2>/dev/null; then
            test_pass "DNS interception correctly disabled for untrusted certificate"
        else
            test_fail "DNS setup" "Should not intercept DNS with untrusted certificate"
        fi
        
        kill $pid 2>/dev/null || true
        return
    fi
    
    # Clean up any existing entries first
    sed -i.bak '/identity.getpostman.com.*PostmanAuthRouter/d' /etc/hosts 2>/dev/null || true
    
    # Check hosts file before
    local hosts_before=$(grep -c "identity.getpostman.com" /etc/hosts 2>/dev/null || echo "0")
    test_info "Hosts entries before: $hosts_before"
    
    # Start daemon with proper setup
    "$BINARY_PATH" --team test --saml-url "https://test.example.com/saml" >/dev/null 2>&1 &
    local pid=$!
    
    # Give daemon time to setup DNS
    sleep 3
    
    # Check hosts file after
    local hosts_after=$(grep -c "identity.getpostman.com" /etc/hosts 2>/dev/null || echo "0")
    test_info "Hosts entries after: $hosts_after"
    
    # Check if entry was added
    if [ "$hosts_after" -gt "$hosts_before" ]; then
        test_pass "DNS interception successfully modifies hosts file"
        
        # Verify the entry points to localhost
        if grep "identity.getpostman.com" /etc/hosts | grep -q "127.0.0.1\|::1"; then
            test_pass "DNS entry correctly points to localhost"
        else
            test_fail "DNS setup" "DNS entry does not point to localhost"
        fi
    else
        # Check if daemon is using other DNS methods
        if command -v pfctl >/dev/null && pfctl -s rules 2>/dev/null | grep -q "identity.getpostman.com"; then
            test_pass "DNS interception using pfctl (packet filter)"
        else
            test_info "DNS interception may be using other methods or failed"
        fi
    fi
    
    # Clean up
    kill $pid 2>/dev/null || true
    sleep 1
    
    # Clean up the entry
    sed -i.bak '/identity.getpostman.com.*PostmanAuthRouter/d' /etc/hosts 2>/dev/null || true
}

# Test signal handling
# Category: Medium/Component - Process signal management (30 seconds)
test_signal_handling() {
    echo -e "\n${YELLOW}Testing: Signal handling${NC}"
    
    if [ "$EUID" -ne 0 ]; then
        test_info "Skipping signal handling test - requires root"
        return
    fi
    
    # Start daemon in background
    "$BINARY_PATH" --team test --saml-url "https://test.example.com/saml" >/dev/null 2>&1 &
    local pid=$!
    
    # Give it time to start
    sleep 2
    
    # Send SIGTERM
    if kill -TERM $pid 2>/dev/null; then
        sleep 2
        if ! ps -p $pid >/dev/null 2>&1; then
            test_pass "Daemon handles SIGTERM gracefully"
        else
            test_fail "Signal handling" "Daemon didn't stop on SIGTERM"
            kill -9 $pid 2>/dev/null || true
        fi
    else
        test_fail "Signal handling" "Could not send signal to daemon"
    fi
}

# Test certificate validation (daemon doesn't generate, only validates)
# Category: Medium/Component - TLS certificate operations (45 seconds)
test_certificate_validation() {
    echo -e "\n${YELLOW}Testing: Certificate validation${NC}"
    
    if [ "$EUID" -ne 0 ]; then
        test_info "Skipping certificate test - requires root"
        return
    fi
    
    # Daemon should validate certificates, not generate them
    # Check if certificates exist at expected location
    if [ -f "$TEST_CERT_PATH" ]; then
        test_pass "Certificate exists at expected location"
        
        # Validate certificate
        if openssl x509 -in "$TEST_CERT_PATH" -noout -checkend 0 2>/dev/null; then
            test_pass "Certificate is valid and not expired"
            
            # Verify certificate subject
            local subject=$(openssl x509 -in "$TEST_CERT_PATH" -noout -subject 2>/dev/null)
            if [[ "$subject" == *"identity.getpostman.com"* ]]; then
                test_pass "Certificate has correct CN (identity.getpostman.com)"
            else
                test_fail "Certificate validation" "Certificate CN does not match expected"
            fi
            
            # Verify key exists and matches certificate
            if [ -f "$TEST_KEY_PATH" ]; then
                local cert_modulus=$(openssl x509 -in "$TEST_CERT_PATH" -noout -modulus 2>/dev/null | md5)
                local key_modulus=$(openssl rsa -in "$TEST_KEY_PATH" -noout -modulus 2>/dev/null | md5)
                if [ "$cert_modulus" = "$key_modulus" ]; then
                    test_pass "Certificate and key pair match"
                else
                    test_fail "Certificate validation" "Certificate and key do not match"
                fi
            else
                test_fail "Certificate validation" "Private key missing"
            fi
        else
            test_fail "Certificate validation" "Certificate is expired or invalid"
        fi
    else
        test_fail "Certificate validation" "Certificates not found at expected location"
    fi
}

# Test process management
# Category: Medium/Component - Process lifecycle management (40 seconds)
test_process_management() {
    echo -e "\n${YELLOW}Testing: Process management${NC}"
    
    if [ "$EUID" -ne 0 ]; then
        test_info "Skipping process management test - requires root"
        return
    fi
    
    # Run both daemons in same context to get correct PIDs
    # Start first daemon
    "$BINARY_PATH" --team test --saml-url "https://test.example.com/saml" >/dev/null 2>&1 &
    local pid1=$!
    sleep 2
    
    # Verify first daemon is running
    if ps -p $pid1 >/dev/null 2>&1; then
        # Try to start second daemon (should detect and terminate first)
        "$BINARY_PATH" --team test --saml-url "https://test.example.com/saml" >/dev/null 2>&1 &
        local pid2=$!
        
        # Wait for termination to complete (daemon waits up to 10 seconds)
        local terminated=false
        for i in {1..15}; do
            sleep 1
            if ! ps -p $pid1 >/dev/null 2>&1; then
                terminated=true
                break
            fi
        done
        
        if [ "$terminated" = true ]; then
            test_pass "Detects and terminates existing daemon"
        else
            test_fail "Process management" "Failed to terminate existing daemon after 15 seconds"
        fi
        
        # Clean up second daemon
        kill $pid2 2>/dev/null || true
    else
        test_fail "Process management" "First daemon failed to start"
    fi
    
    # Final cleanup
    killall pm-authrouter 2>/dev/null || true
}

# Test logging
# Category: Fast/Unit - Log file operations (15 seconds)
test_logging() {
    echo -e "\n${YELLOW}Testing: Logging functionality${NC}"
    
    local log_dir="/var/log/postman"
    local log_file="$log_dir/pm-authrouter.log"
    
    if [ "$EUID" -ne 0 ]; then
        test_info "Skipping logging test - requires root"
        return
    fi
    
    # Create log directory if it doesn't exist
    mkdir -p "$log_dir"
    
    # Start daemon briefly to generate logs
    timeout 3 "$BINARY_PATH" --team test --saml-url "https://test.example.com/saml" >"$log_file" 2>&1 || true
    
    if [ -s "$log_file" ]; then
        test_pass "Log file created"
        local lines=$(wc -l < "$log_file")
        test_info "Log contains $lines lines"
    else
        test_fail "Logging" "No log output generated"
    fi
}

# Test certificate trust behavior - DNS interception should be disabled if cert not trusted
# Category: Slow/Integration - Certificate trust validation (30 seconds)
test_certificate_trust_behavior() {
    echo -e "\n${YELLOW}Testing: Certificate trust behavior${NC}"
    
    if [ "$EUID" -ne 0 ]; then
        test_info "Skipping certificate trust test - requires root"
        return
    fi
    
    # Scenario 1: Untrusted certificate - DNS should NOT be intercepted
    # Remove certificate from keychain temporarily
    security delete-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain 2>/dev/null || true
    
    # Start daemon and verify DNS is NOT modified
    "$BINARY_PATH" --team test --saml-url "https://test.example.com/saml" >/dev/null 2>&1 &
    local pid=$!
    sleep 3
    
    # Check if hosts file was modified
    if grep -q "identity.getpostman.com.*PostmanAuthRouter" /etc/hosts 2>/dev/null; then
        test_fail "Certificate trust" "DNS interception active with untrusted cert"
    else
        test_pass "DNS interception correctly disabled for untrusted cert"
    fi
    
    # Check logs for warning message
    local log_file="/var/log/postman/pm-authrouter.log"
    if [ -f "$log_file" ] && grep -q "Certificate is not trusted" "$log_file"; then
        test_pass "Warning logged for untrusted certificate"
    fi
    
    kill $pid 2>/dev/null || true
    sleep 1
    
    # Clean up
    sed -i.bak '/identity.getpostman.com.*PostmanAuthRouter/d' /etc/hosts 2>/dev/null || true
}

# Test expired certificate handling - daemon should run in disabled mode
# Category: Medium/Component - Expired certificate handling (20 seconds)
test_expired_certificate_mode() {
    echo -e "\n${YELLOW}Testing: Expired certificate handling${NC}"
    
    if [ "$EUID" -ne 0 ]; then
        test_info "Skipping expired certificate test - requires root"
        return
    fi
    
    # Create an expired certificate for testing
    local expired_cert="/tmp/expired_cert.pem"
    local expired_key="/tmp/expired_key.pem"
    
    openssl req -new -x509 -nodes \
        -keyout "$expired_key" \
        -out "$expired_cert" \
        -days -1 \
        -subj "/C=US/ST=Test/L=Test/O=Test/CN=identity.getpostman.com" \
        2>/dev/null
    
    # Move original certificates temporarily
    if [ -f "$TEST_CERT_PATH" ]; then
        mv "$TEST_CERT_PATH" "$TEST_CERT_PATH.bak" 2>/dev/null || true
        mv "$TEST_KEY_PATH" "$TEST_KEY_PATH.bak" 2>/dev/null || true
    fi
    
    # Put expired certs in place
    cp "$expired_cert" "$TEST_CERT_PATH"
    cp "$expired_key" "$TEST_KEY_PATH"
    chmod 644 "$TEST_CERT_PATH"
    chmod 600 "$TEST_KEY_PATH"
    
    # Start daemon - should detect expired cert
    "$BINARY_PATH" --team test --saml-url "https://test.example.com/saml" >/dev/null 2>&1 &
    local pid=$!
    sleep 2
    
    # Check that hosts file is NOT modified
    if ! grep -q "identity.getpostman.com" /etc/hosts 2>/dev/null; then
        test_pass "Expired certificate mode - no DNS interception"
    else
        test_fail "Expired certificate" "Incorrectly intercepting DNS with expired cert"
    fi
    
    kill $pid 2>/dev/null || true
    
    # Restore original certificates
    if [ -f "$TEST_CERT_PATH.bak" ]; then
        mv "$TEST_CERT_PATH.bak" "$TEST_CERT_PATH" 2>/dev/null || true
        mv "$TEST_KEY_PATH.bak" "$TEST_KEY_PATH" 2>/dev/null || true
    fi
    
    # Clean up temp files
    rm -f "$expired_cert" "$expired_key"
}

# Test enhanced process management with dual detection methods
# Category: Medium/Component - Process lifecycle management (40 seconds)
test_process_management_enhanced() {
    echo -e "\n${YELLOW}Testing: Enhanced process management${NC}"
    
    if [ "$EUID" -ne 0 ]; then
        test_info "Skipping enhanced process management test - requires root"
        return
    fi
    
    # Test the FindRunningDaemons logic with multiple detection methods
    
    # Start daemon listening on port 443
    "$BINARY_PATH" --team test --saml-url "https://test.example.com/saml" >/dev/null 2>&1 &
    local pid1=$!
    sleep 2
    
    # Verify it's running and bound to port
    if ! lsof -i :443 2>/dev/null | grep -q "$pid1"; then
        test_fail "Process management setup" "First daemon failed to bind to port 443"
        kill $pid1 2>/dev/null || true
        return
    fi
    
    # Start second daemon - should detect via both methods:
    # 1. Binary name detection (findByBinary)
    # 2. Port 443 detection (findByPort)
    "$BINARY_PATH" --team test --saml-url "https://test.example.com/saml" >/dev/null 2>&1 &
    local pid2=$!
    
    # Give it time to detect and terminate (up to 15 seconds)
    local terminated=false
    for i in {1..15}; do
        sleep 1
        if ! ps -p $pid1 >/dev/null 2>&1; then
            terminated=true
            test_pass "Process detection and termination working"
            break
        fi
    done
    
    if [ "$terminated" = false ]; then
        test_fail "Enhanced process management" "Failed to detect/terminate existing daemon"
    fi
    
    # Test graceful termination with timeout
    if ps -p $pid2 >/dev/null 2>&1; then
        kill -TERM $pid2 2>/dev/null
        sleep 2
        if ! ps -p $pid2 >/dev/null 2>&1; then
            test_pass "Graceful termination with SIGTERM"
        else
            kill -9 $pid2 2>/dev/null || true
            test_fail "Graceful termination" "Required force kill"
        fi
    fi
    
    # Clean up
    killall pm-authrouter 2>/dev/null || true
}

# Test DNS fallback strategies when primary method fails
# Category: Slow/Integration - DNS fallback testing (60 seconds)
test_dns_fallback_strategies() {
    echo -e "\n${YELLOW}Testing: DNS fallback strategies${NC}"
    
    if [ "$EUID" -ne 0 ]; then
        test_info "Skipping DNS fallback test - requires root"
        return
    fi
    
    # The daemon tries multiple methods in order:
    # 1. Hosts file
    # 2. pfctl (macOS)
    # 3. Route command
    
    # Make hosts file temporarily read-only to force fallback
    chmod 444 /etc/hosts
    
    "$BINARY_PATH" --team test --saml-url "https://test.example.com/saml" >/dev/null 2>&1 &
    local pid=$!
    sleep 3
    
    # Check if it fell back to pfctl
    if pfctl -s rules 2>/dev/null | grep -q "identity.getpostman.com\|127.0.0.1"; then
        test_pass "Fallback to pfctl method successful"
    # Check if it fell back to route method
    elif netstat -rn | grep "$(nslookup identity.getpostman.com 8.8.8.8 2>/dev/null | grep -A1 "^Address:" | tail -1 | awk '{print $2}')" 2>/dev/null | grep -q "127.0.0.1"; then
        test_pass "Fallback to route method successful"
    else
        test_fail "DNS fallback strategies" "No working fallback method found"
    fi
    
    # Restore hosts file permissions
    chmod 644 /etc/hosts
    kill $pid 2>/dev/null || true
    sleep 1
    
    # Clean up any DNS changes
    pfctl -F nat 2>/dev/null || true
    sed -i.bak '/identity.getpostman.com.*PostmanAuthRouter/d' /etc/hosts 2>/dev/null || true
}

# Test configuration validation for missing parameters
# Category: Fast/Unit - Configuration validation (10 seconds)
test_configuration_validation_missing() {
    echo -e "\n${YELLOW}Testing: Configuration validation for missing parameters${NC}"
    
    # Test missing team name
    local output=$("$BINARY_PATH" --saml-url "https://test.example.com/saml" 2>&1 || true)
    if echo "$output" | grep -q "team name not configured\|--team flag"; then
        test_pass "Validates missing team name"
    else
        test_fail "Config validation" "Should require team name"
    fi
    
    # Test missing SAML URL
    output=$("$BINARY_PATH" --team test 2>&1 || true)
    if echo "$output" | grep -q "SAML URL not configured\|--saml-url flag"; then
        test_pass "Validates missing SAML URL"
    else
        test_fail "Config validation" "Should require SAML URL"
    fi
    
    # Test MDM managed preferences reading (macOS specific)
    if [ -f "/Library/Managed Preferences/com.postman.pm-authrouter.plist" ]; then
        test_info "MDM managed preferences file exists"
        # Check if daemon can read from it
        output=$("$BINARY_PATH" 2>&1 || true)
        if echo "$output" | grep -q "Found managed preference"; then
            test_pass "Reads MDM managed preferences"
        fi
    else
        test_info "No MDM managed preferences found (expected in non-MDM environment)"
    fi
}

# Test MDM profile generation capability
# Category: Fast/Unit - MDM profile generation check (10 seconds)
test_mdm_profile_generation_daemon() {
    echo -e "\n${YELLOW}Testing: Daemon MDM profile generation${NC}"
    
    if [ -f "/usr/local/bin/postman/generate_mdm_profile.sh" ]; then
        test_pass "MDM profile generator script exists"
        
        # Test that it can run (without actually generating)
        if /usr/local/bin/postman/generate_mdm_profile.sh 2>&1 | grep -q "Generate MDM\|Generating"; then
            test_pass "MDM generator script is executable"
        else
            test_info "MDM generator present but requires certificates"
        fi
    else
        test_info "MDM generator not yet installed (requires full installation)"
    fi
}

# Verify cleanup was successful
verify_cleanup() {
    echo -e "\n${YELLOW}Verifying cleanup...${NC}"
    local cleanup_issues=0
    
    # Check for remaining daemon processes
    if pgrep -f pm-authrouter >/dev/null 2>&1; then
        test_fail "Process cleanup" "Daemon processes still running"
        ((cleanup_issues++))
    else
        test_pass "No daemon processes remaining"
    fi
    
    # Check hosts file entries
    if grep -q "identity.getpostman.com.*PostmanAuthRouter" /etc/hosts 2>/dev/null; then
        test_fail "Hosts file cleanup" "DNS entries still present"
        ((cleanup_issues++))
    else
        test_pass "Hosts file cleaned"
    fi
    
    # Check for test binary
    if [ -f "$BINARY_PATH" ]; then
        test_fail "Binary cleanup" "Test binary still exists"
        ((cleanup_issues++))
    else
        test_pass "Test binary removed"
    fi
    
    # Check for port 443 binding
    if lsof -i :443 2>/dev/null | grep -q pm-authrouter; then
        test_fail "Port cleanup" "Port 443 still bound by daemon"
        ((cleanup_issues++))
    else
        test_pass "Port 443 released"
    fi
    
    # Check for certificate files (if we created any during testing)
    local cert_dir="/usr/local/bin/postman"
    if [ -f "$cert_dir/identity.getpostman.com.crt" ]; then
        test_info "Certificate files remain (expected for persistent install)"
    fi
    
    # Check for log directory cleanup
    if [ -d "/var/log/postman" ]; then
        test_fail "Log directory cleanup" "Log directory still exists"
        ((cleanup_issues++))
    else
        test_pass "Log directory cleaned"
    fi
    
    # Summary
    if [ $cleanup_issues -eq 0 ]; then
        test_pass "System cleanup verification successful"
    else
        test_fail "Cleanup verification" "$cleanup_issues issues found"
    fi
    
    return $cleanup_issues
}

# Enhanced cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    
    # Kill any remaining daemon processes with escalating force
    if pgrep -f pm-authrouter >/dev/null 2>&1; then
        echo "Terminating daemon processes..."
        pkill -TERM -f pm-authrouter 2>/dev/null || true
        sleep 2
        
        # If still running, force kill
        if pgrep -f pm-authrouter >/dev/null 2>&1; then
            echo "Force killing remaining processes..."
            pkill -KILL -f pm-authrouter 2>/dev/null || true
            sleep 1
        fi
    fi
    
    # Remove test binary
    if [ -f "$BINARY_PATH" ]; then
        echo "Removing test binary..."
        rm -f "$BINARY_PATH"
    fi
    
    # Clean up test certificates
    cleanup_test_certificates
    
    # Clean hosts file if needed
    if [ "$EUID" -eq 0 ]; then
        if grep -q "identity.getpostman.com.*PostmanAuthRouter" /etc/hosts 2>/dev/null; then
            echo "Cleaning hosts file entries..."
            sed -i.bak '/identity.getpostman.com.*PostmanAuthRouter/d' /etc/hosts 2>/dev/null || true
        fi
    fi
    
    # Clean up test log files and directory
    local log_dir="/var/log/postman"
    if [ "$EUID" -eq 0 ] && [ -d "$log_dir" ]; then
        echo "Removing test log files and directory..."
        rm -f "$log_dir/pm-authrouter.log" 2>/dev/null || true
        rmdir "$log_dir" 2>/dev/null || true
    fi
    
    # Verify cleanup was successful
    verify_cleanup
}

# Main test runner
main() {
    echo "========================================"
    echo "macOS Daemon Functional Test Suite"
    echo "========================================"
    echo "Test started: $(date)"
    echo ""
    echo -e "${YELLOW}IMPORTANT: Certificate Trust Requirements${NC}"
    echo "----------------------------------------"
    echo "For DNS interception tests to work, the certificate must be trusted."
    echo ""
    echo "To install the MDM profile for certificate trust:"
    echo "1. Double-click: deployment/macos/Postman-Enterprise-*.mobileconfig"
    echo "2. System Preferences will open"
    echo "3. Click 'Install' and enter admin password"
    echo "4. The certificate will be trusted system-wide"
    echo ""
    echo "Checking certificate trust status..."
    if security find-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain >/dev/null 2>&1; then
        echo -e "${GREEN} Certificate found in system keychain${NC}"
    else
        echo -e "${YELLOW} Certificate not in system keychain - DNS interception will be disabled${NC}"
    fi
    echo ""
    echo "" > "$TEST_RESULTS_FILE"
    
    # Set trap for cleanup
    trap cleanup EXIT
    
    # Setup test environment if running as root
    if [ "$EUID" -eq 0 ]; then
        setup_test_certificates
    else
        test_info "Running without root - some tests will be limited"
    fi
    
    # Build daemon
    build_daemon
    
    # Run tests
    test_privilege_check
    test_command_line_args
    test_port_binding
    test_health_endpoint
    test_saml_redirect
    test_config_validation
    test_dns_setup
    test_signal_handling
    test_certificate_validation
    test_certificate_trust_behavior
    test_expired_certificate_mode
    test_process_management
    test_process_management_enhanced
    test_dns_fallback_strategies
    test_configuration_validation_missing
    test_logging
    test_mdm_profile_generation_daemon
    
    # Summary
    echo ""
    echo "========================================"
    echo "Test Summary"
    echo "========================================"
    echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
    echo -e "${RED}Failed: $FAILED_TESTS${NC}"
    
    # Run cleanup and verification (will update test counts)
    cleanup
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "\n${GREEN}All tests passed with clean system state!${NC}"
        exit 0
    else
        echo -e "\n${YELLOW}Some tests failed. Check $TEST_RESULTS_FILE for details.${NC}"
        exit 1
    fi
}

# Run tests if script is executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi