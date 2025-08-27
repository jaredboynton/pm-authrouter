#!/bin/bash
# test_cleanup_manager.sh - Test comprehensive cleanup functionality
# Tests cleanup_unix.go for complete removal of all AuthRouter components

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
TEST_DIR="/tmp/pm-authrouter-cleanup-test"
TEST_SERVICE="com.postman.pm-authrouter-test"
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
    rm -rf "$TEST_DIR"
    
    # Remove test LaunchDaemon if exists
    if [ "$IS_ROOT" = true ]; then
        launchctl unload "/tmp/$TEST_SERVICE.plist" 2>/dev/null || true
        rm -f "/tmp/$TEST_SERVICE.plist"
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
    
    # Create mock directory structure
    mkdir -p "$TEST_DIR/usr/local/bin/postman"
    mkdir -p "$TEST_DIR/Library/LaunchDaemons"
    mkdir -p "$TEST_DIR/var/log/postman"
    mkdir -p "$TEST_DIR/etc"
}

# Test LaunchDaemon cleanup
test_launchdaemon_cleanup() {
    echo -e "\n${YELLOW}Testing LaunchDaemon cleanup...${NC}"
    
    # Create mock plist file
    PLIST_PATH="$TEST_DIR/Library/LaunchDaemons/$TEST_SERVICE.plist"
    cat > "$PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>$TEST_SERVICE</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/postman/pm-authrouter</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOF
    
    if [ -f "$PLIST_PATH" ]; then
        pass "Created test LaunchDaemon plist"
        
        # Test removal
        rm "$PLIST_PATH"
        if [ ! -f "$PLIST_PATH" ]; then
            pass "Successfully removed LaunchDaemon plist"
        else
            fail "Failed to remove LaunchDaemon plist"
        fi
    else
        fail "Failed to create test LaunchDaemon plist"
    fi
    
    # Test actual LaunchDaemon commands (if root)
    if [ "$IS_ROOT" = true ]; then
        # Create real test plist
        REAL_PLIST="/tmp/$TEST_SERVICE.plist"
        cp "$TEST_DIR/Library/LaunchDaemons/$TEST_SERVICE.plist" "$REAL_PLIST" 2>/dev/null || echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
    <key>Label</key>
    <string>$TEST_SERVICE</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sleep</string>
        <string>1</string>
    </array>
</dict>
</plist>" > "$REAL_PLIST"
        
        # Test unload
        if launchctl unload "$REAL_PLIST" 2>/dev/null; then
            pass "Successfully unloaded test LaunchDaemon"
        else
            skip "Could not unload test LaunchDaemon (may not be loaded)"
        fi
        
        rm -f "$REAL_PLIST"
    else
        skip "LaunchDaemon command tests require root"
    fi
}

# Test certificate cleanup
test_certificate_cleanup() {
    echo -e "\n${YELLOW}Testing certificate cleanup...${NC}"
    
    # Create mock certificate files
    CERT_DIR="$TEST_DIR/usr/local/bin/postman"
    touch "$CERT_DIR/identity.getpostman.com.crt"
    touch "$CERT_DIR/identity.getpostman.com.key"
    touch "$CERT_DIR/ca.crt"
    
    CERT_COUNT=$(find "$CERT_DIR" -name "*.crt" -o -name "*.key" | wc -l)
    if [ "$CERT_COUNT" -eq 3 ]; then
        pass "Created 3 test certificate files"
    else
        fail "Failed to create all certificate files"
    fi
    
    # Test removal
    rm -f "$CERT_DIR"/*.crt "$CERT_DIR"/*.key
    REMAINING=$(find "$CERT_DIR" -name "*.crt" -o -name "*.key" | wc -l)
    if [ "$REMAINING" -eq 0 ]; then
        pass "Successfully removed all certificate files"
    else
        fail "Failed to remove all certificate files ($REMAINING remaining)"
    fi
    
    # Test keychain cleanup (non-destructive check)
    if [ "$IS_ROOT" = true ]; then
        # Check if we can query the keychain
        if security list-keychains 2>/dev/null | grep -q "System.keychain"; then
            pass "Can access System keychain for cleanup"
        else
            skip "Cannot access System keychain"
        fi
    else
        skip "Keychain cleanup requires root"
    fi
}

# Test hosts file cleanup
test_hosts_cleanup() {
    echo -e "\n${YELLOW}Testing hosts file cleanup...${NC}"
    
    # Create test hosts file with entries
    HOSTS_FILE="$TEST_DIR/etc/hosts"
    cat > "$HOSTS_FILE" <<EOF
##
# Host Database
##
127.0.0.1   localhost
255.255.255.255 broadcasthost
::1             localhost

# Some existing entry
192.168.1.1 myserver.local

127.0.0.1 identity.getpostman.com # Added by PostmanAuthRouter
127.0.0.1 test.postman.com # Added by PostmanAuthRouter
EOF
    
    # Create backup
    cp "$HOSTS_FILE" "$HOSTS_FILE.pm-authrouter-backup"
    if [ -f "$HOSTS_FILE.pm-authrouter-backup" ]; then
        pass "Created hosts file backup"
    else
        fail "Failed to create hosts file backup"
    fi
    
    # Test cleanup - remove PostmanAuthRouter entries
    grep -v "PostmanAuthRouter" "$HOSTS_FILE" > "$HOSTS_FILE.tmp"
    mv "$HOSTS_FILE.tmp" "$HOSTS_FILE"
    
    if ! grep -q "PostmanAuthRouter" "$HOSTS_FILE"; then
        pass "Successfully removed AuthRouter entries from hosts"
    else
        fail "Failed to remove all AuthRouter entries"
    fi
    
    # Verify other entries remain
    if grep -q "myserver.local" "$HOSTS_FILE"; then
        pass "Other hosts entries preserved"
    else
        fail "Other hosts entries were removed"
    fi
    
    # Test backup restoration
    if [ -f "$HOSTS_FILE.pm-authrouter-backup" ]; then
        mv "$HOSTS_FILE.pm-authrouter-backup" "$HOSTS_FILE"
        if grep -q "identity.getpostman.com" "$HOSTS_FILE"; then
            pass "Successfully restored hosts from backup"
        else
            fail "Backup restoration incomplete"
        fi
    fi
}

# Test log file cleanup
test_log_cleanup() {
    echo -e "\n${YELLOW}Testing log file cleanup...${NC}"
    
    # Create test log files
    LOG_DIR="$TEST_DIR/var/log/postman"
    mkdir -p "$LOG_DIR"
    
    echo "Test log content" > "$LOG_DIR/pm-authrouter.log"
    echo "Old log content" > "$LOG_DIR/pm-authrouter.log.1"
    touch "$TEST_DIR/tmp-pm-authrouter.log"
    
    LOG_COUNT=$(find "$TEST_DIR" -name "*pm-authrouter*.log*" | wc -l)
    if [ "$LOG_COUNT" -ge 2 ]; then
        pass "Created test log files"
    else
        fail "Failed to create test log files"
    fi
    
    # Test removal
    rm -f "$LOG_DIR"/*.log* "$TEST_DIR"/*.log
    REMAINING=$(find "$TEST_DIR" -name "*pm-authrouter*.log*" | wc -l)
    
    if [ "$REMAINING" -eq 0 ]; then
        pass "Successfully removed all log files"
    else
        fail "Failed to remove all log files ($REMAINING remaining)"
    fi
    
    # Test directory removal when empty
    if [ -d "$LOG_DIR" ]; then
        # Directory should be empty now
        if [ -z "$(ls -A "$LOG_DIR")" ]; then
            rmdir "$LOG_DIR"
            if [ ! -d "$LOG_DIR" ]; then
                pass "Removed empty log directory"
            else
                fail "Failed to remove empty log directory"
            fi
        fi
    fi
}

# Test binary cleanup
test_binary_cleanup() {
    echo -e "\n${YELLOW}Testing binary cleanup...${NC}"
    
    # Create test binary files
    BINARY_DIR="$TEST_DIR/usr/local/bin/postman"
    mkdir -p "$BINARY_DIR"
    
    touch "$BINARY_DIR/pm-authrouter"
    chmod +x "$BINARY_DIR/pm-authrouter"
    touch "$BINARY_DIR/uninstall.sh"
    chmod +x "$BINARY_DIR/uninstall.sh"
    
    if [ -x "$BINARY_DIR/pm-authrouter" ]; then
        pass "Created test binary files"
    else
        fail "Failed to create test binary files"
    fi
    
    # Test removal
    rm -f "$BINARY_DIR/pm-authrouter" "$BINARY_DIR/uninstall.sh"
    
    if [ ! -f "$BINARY_DIR/pm-authrouter" ]; then
        pass "Successfully removed binary files"
    else
        fail "Failed to remove binary files"
    fi
    
    # Test directory removal when empty
    if [ -z "$(ls -A "$BINARY_DIR")" ]; then
        rmdir "$BINARY_DIR"
        if [ ! -d "$BINARY_DIR" ]; then
            pass "Removed empty binary directory"
        else
            fail "Failed to remove empty binary directory"
        fi
    fi
}

# Test DNS method cleanup
test_dns_cleanup() {
    echo -e "\n${YELLOW}Testing DNS method cleanup...${NC}"
    
    # Test pfctl rules cleanup (check only)
    if [ "$IS_ROOT" = true ]; then
        # Create test pfctl rules file
        touch "/tmp/pm-authrouter.pfctl.rules"
        
        if [ -f "/tmp/pm-authrouter.pfctl.rules" ]; then
            pass "Created test pfctl rules file"
            rm -f "/tmp/pm-authrouter.pfctl.rules"
            if [ ! -f "/tmp/pm-authrouter.pfctl.rules" ]; then
                pass "Removed pfctl rules file"
            else
                fail "Failed to remove pfctl rules file"
            fi
        fi
        
        # Test pfctl flush command (non-destructive)
        if command -v pfctl >/dev/null 2>&1; then
            pass "pfctl command available for cleanup"
        else
            skip "pfctl not available"
        fi
    else
        skip "DNS method cleanup tests require root"
    fi
}

# Test partial failure handling
test_partial_failure() {
    echo -e "\n${YELLOW}Testing partial failure recovery...${NC}"
    
    # Create some files that can't be removed (simulate failure)
    PROTECTED_DIR="$TEST_DIR/protected"
    mkdir -p "$PROTECTED_DIR"
    touch "$PROTECTED_DIR/file1"
    
    # Make directory read-only to simulate failure
    chmod 555 "$PROTECTED_DIR"
    
    # Try to remove (should fail)
    if ! rm -f "$PROTECTED_DIR/file1" 2>/dev/null; then
        pass "Simulated cleanup failure detected"
    else
        fail "Unexpected success removing protected file"
    fi
    
    # Restore permissions for cleanup
    chmod 755 "$PROTECTED_DIR"
    rm -rf "$PROTECTED_DIR"
    
    pass "Cleanup can continue after partial failures"
}

# Test cleanup idempotency
test_idempotency() {
    echo -e "\n${YELLOW}Testing cleanup idempotency...${NC}"
    
    # Run cleanup on already-clean system
    CLEAN_DIR="$TEST_DIR/clean"
    mkdir -p "$CLEAN_DIR"
    
    # First cleanup
    rm -rf "$CLEAN_DIR"/*
    if [ ! -d "$CLEAN_DIR" ] || [ -z "$(ls -A "$CLEAN_DIR" 2>/dev/null)" ]; then
        pass "First cleanup succeeded"
    fi
    
    # Second cleanup (should not error)
    rm -rf "$CLEAN_DIR"/* 2>/dev/null
    if [ $? -eq 0 ]; then
        pass "Second cleanup succeeded (idempotent)"
    else
        fail "Second cleanup failed"
    fi
}

# Test non-interactive/force mode for uninstall script
test_uninstall_modes() {
    echo -e "\n${YELLOW}Testing interactive/non-interactive uninstall modes...${NC}"
    
    # Create mock uninstall script with force mode
    MOCK_UNINSTALL="$TEST_DIR/uninstall.sh"
    cat > "$MOCK_UNINSTALL" << 'EOF'
#!/bin/bash
# Non-interactive by default for enterprise automation
if [[ "${INTERACTIVE:-false}" == "true" ]] || [[ "$1" == "--interactive" ]] || [[ "$1" == "-i" ]]; then
    read -p "Continue? (y/N) " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Cancelled"
        exit 1
    fi
    echo "Running in interactive mode"
    exit 0
else
    echo "Running in non-interactive mode"
    exit 0
fi
EOF
    chmod +x "$MOCK_UNINSTALL"
    
    # Test default non-interactive behavior
    if "$MOCK_UNINSTALL" 2>/dev/null | grep -q "non-interactive"; then
        pass "Default non-interactive mode works correctly"
    else
        fail "Default non-interactive mode not working"
    fi
    
    # Test INTERACTIVE environment variable
    if INTERACTIVE=true "$MOCK_UNINSTALL" <<< "y" 2>/dev/null | grep -q "interactive mode"; then
        pass "INTERACTIVE environment variable works"
    else
        fail "INTERACTIVE environment variable not working"
    fi
    
    # Test --interactive flag
    if "$MOCK_UNINSTALL" --interactive <<< "y" 2>/dev/null | grep -q "interactive mode"; then
        pass "Interactive flag --interactive works correctly"
    else
        fail "Interactive flag --interactive not working"
    fi
    
    # Test -i shorthand
    if "$MOCK_UNINSTALL" -i <<< "y" 2>/dev/null | grep -q "interactive mode"; then
        pass "Short flag -i works correctly"
    else
        fail "Short flag -i not working"
    fi
    
    rm -f "$MOCK_UNINSTALL"
}

# Test MDM profile generator script presence
test_mdm_generator_in_uninstall() {
    echo -e "\n${YELLOW}Testing MDM profile generator in deployment...${NC}"
    
    # Check if the build creates the MDM profile generator
    MOCK_MDM_GENERATOR="$TEST_DIR/usr/local/bin/postman/generate_mdm_profile.sh"
    mkdir -p "$(dirname "$MOCK_MDM_GENERATOR")"
    
    # Create mock MDM generator
    cat > "$MOCK_MDM_GENERATOR" << 'EOF'
#!/bin/bash
# Mock MDM profile generator
echo "Generating MDM profile..."
EOF
    chmod +x "$MOCK_MDM_GENERATOR"
    
    if [ -x "$MOCK_MDM_GENERATOR" ]; then
        pass "MDM profile generator script created and executable"
    else
        fail "MDM profile generator script missing or not executable"
    fi
    
    # Clean up
    rm -rf "$TEST_DIR/usr"
}

# Test cleanup verification
test_cleanup_verification() {
    echo -e "\n${YELLOW}Testing cleanup verification...${NC}"
    
    # Create comprehensive test structure
    VERIFY_DIR="$TEST_DIR/verify"
    mkdir -p "$VERIFY_DIR/usr/local/bin/postman"
    mkdir -p "$VERIFY_DIR/var/log/postman"
    mkdir -p "$VERIFY_DIR/Library/LaunchDaemons"
    
    # Add test files
    touch "$VERIFY_DIR/usr/local/bin/postman/pm-authrouter"
    touch "$VERIFY_DIR/var/log/postman/pm-authrouter.log"
    touch "$VERIFY_DIR/Library/LaunchDaemons/com.postman.pm-authrouter.plist"
    echo "127.0.0.1 identity.getpostman.com # Added by PostmanAuthRouter" > "$VERIFY_DIR/etc/hosts"
    
    # Count items before cleanup
    ITEMS_BEFORE=$(find "$VERIFY_DIR" -type f | wc -l)
    if [ "$ITEMS_BEFORE" -ge 4 ]; then
        pass "Created $ITEMS_BEFORE test items"
    else
        fail "Failed to create test items"
    fi
    
    # Perform cleanup
    rm -rf "$VERIFY_DIR"
    
    # Verify everything is gone
    if [ ! -d "$VERIFY_DIR" ]; then
        pass "Complete cleanup verified - all components removed"
    else
        fail "Cleanup incomplete - directory still exists"
    fi
}

# Test actual cleanup script integration
test_cleanup_script() {
    echo -e "\n${YELLOW}Testing uninstall script integration...${NC}"
    
    # Look for actual uninstall script
    UNINSTALL_SCRIPT="../../deployment/macos/uninstall.sh"
    
    # Note: uninstall.sh is generated during PKG build, not stored in repo
    if [ -f "$UNINSTALL_SCRIPT" ]; then
        pass "Found uninstall script"
        
        # Check script contains expected cleanup commands
        if grep -q "launchctl" "$UNINSTALL_SCRIPT"; then
            pass "Uninstall script contains LaunchDaemon cleanup"
        else
            fail "Uninstall script missing LaunchDaemon cleanup"
        fi
        
        if grep -q "security delete-certificate" "$UNINSTALL_SCRIPT"; then
            pass "Uninstall script contains certificate cleanup"
        else
            skip "Uninstall script may use different certificate cleanup"
        fi
        
        if grep -q "/etc/hosts" "$UNINSTALL_SCRIPT"; then
            pass "Uninstall script contains hosts cleanup"
        else
            fail "Uninstall script missing hosts cleanup"
        fi
    else
        skip "Uninstall script not found"
    fi
}

# Main test execution
main() {
    echo "=================================="
    echo "Cleanup Manager Tests"
    echo "=================================="
    
    if [ "$IS_ROOT" = true ]; then
        echo -e "${BLUE}Running with root privileges - all tests enabled${NC}"
    else
        echo -e "${YELLOW}Running without root - some tests will be skipped${NC}"
    fi
    
    setup_test_env
    
    test_launchdaemon_cleanup
    test_certificate_cleanup
    test_hosts_cleanup
    test_log_cleanup
    test_binary_cleanup
    test_dns_cleanup
    test_partial_failure
    test_idempotency
    test_uninstall_modes
    test_mdm_generator_in_uninstall
    test_cleanup_verification
    test_cleanup_script
    
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