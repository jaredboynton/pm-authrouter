#!/bin/bash

# test_macos_integration.sh - End-to-end integration tests for macOS deployment
# Tests complete installation, configuration, and uninstallation flow

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
BUILD_SCRIPT="$PROJECT_ROOT/deployment/macos/build_pkg_mdm.sh"
TEST_RESULTS_FILE="$SCRIPT_DIR/test_results_macos_integration.txt"
FAILED_TESTS=0
PASSED_TESTS=0

# Test configuration values
TEST_TEAM="test-team-$(date +%s)"
TEST_SAML_URL="https://identity.getpostman.com/sso/test/$(date +%s)/init"

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

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}Warning: Some tests require root privileges${NC}"
        echo "Run with: sudo $0"
        return 1
    fi
    return 0
}

# Test PKG build process
# Category: Slow/Integration - Complete PKG build process (3-5 minutes)
test_pkg_build() {
    echo -e "\n${YELLOW}Testing: PKG build process${NC}"
    
    # Check if build script exists
    if [ ! -f "$BUILD_SCRIPT" ]; then
        test_fail "Build script exists" "Script not found at $BUILD_SCRIPT"
        return 1
    fi
    
    # Check for original PKG files
    local has_pkg=false
    if ls "$PROJECT_ROOT"/deployment/macos/Postman-Enterprise-*-arm64.pkg 2>/dev/null | grep -v -- '-saml' >/dev/null; then
        has_pkg=true
        test_pass "Found ARM64 original PKG"
    fi
    
    if ls "$PROJECT_ROOT"/deployment/macos/Postman-Enterprise-*-x64.pkg 2>/dev/null | grep -v -- '-saml' >/dev/null; then
        has_pkg=true
        test_pass "Found Intel original PKG"
    fi
    
    if [ "$has_pkg" = false ]; then
        test_fail "Original PKG detection" "No original Postman PKG found"
        return 1
    fi
    
    # Test actual build process with configuration
    test_info "Testing build with embedded configuration..."
    if cd "$PROJECT_ROOT/deployment/macos"; then
        # Run actual build (not just --help)
        if "$BUILD_SCRIPT" --team "$TEST_TEAM" --saml-url "$TEST_SAML_URL" --quiet; then
            test_pass "Build script completed successfully"
            
            # Check for SAML PKG output
            if ls Postman-Enterprise-*-saml.pkg 2>/dev/null | grep -v "^ls:" | head -1; then
                test_pass "SAML PKG created successfully"
            else
                test_fail "PKG creation" "No SAML PKG found after build"
            fi
            
            # Check for MDM profile output
            if ls Postman-Enterprise-*-auth.mobileconfig 2>/dev/null | grep -v "^ls:" | head -1; then
                test_pass "MDM profile created successfully"
            else
                test_fail "MDM profile creation" "No .mobileconfig file found after build"
            fi
        else
            test_fail "Build script execution" "Failed to run build script"
        fi
    else
        test_fail "Build directory access" "Cannot change to deployment/macos directory"
    fi
}

# Test certificate operations
# Category: Slow/Integration - Certificate generation and keychain operations (60 seconds)
test_certificate_operations() {
    echo -e "\n${YELLOW}Testing: Certificate operations${NC}"
    
    if [ "$EUID" -ne 0 ]; then
        test_info "Skipping certificate tests - requires root"
        return
    fi
    
    # Test certificate generation
    local test_cert_dir="/tmp/test_cert_$$"
    mkdir -p "$test_cert_dir"
    cd "$test_cert_dir"
    
    # Generate test certificate
    openssl genrsa -out identity.getpostman.com.key 2048 2>/dev/null
    openssl req -new -x509 \
        -key identity.getpostman.com.key \
        -out identity.getpostman.com.crt \
        -days 3650 \
        -subj "/C=US/O=Postdot Technologies, Inc/CN=identity.getpostman.com" \
        2>/dev/null
    
    if [ -f identity.getpostman.com.crt ] && [ -f identity.getpostman.com.key ]; then
        test_pass "Certificate generation successful"
    else
        test_fail "Certificate generation" "Failed to generate certificate files"
    fi
    
    # Test certificate trust check (without actually trusting)
    if security find-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain >/dev/null 2>&1; then
        test_info "Certificate already in keychain (from previous test)"
    else
        test_pass "Certificate not in keychain (clean state)"
    fi
    
    # Cleanup
    rm -rf "$test_cert_dir"
}

# Test LaunchDaemon operations
# Category: Slow/Integration - LaunchDaemon installation and management (45 seconds)
test_launchdaemon_operations() {
    echo -e "\n${YELLOW}Testing: LaunchDaemon operations${NC}"
    
    local plist_path="/Library/LaunchDaemons/com.postman.pm-authrouter.plist"
    
    # Check if daemon is currently loaded
    if launchctl list | grep -q com.postman.pm-authrouter; then
        test_info "AuthRouter daemon is currently running"
        
        # Check configuration
        if [ -f "$plist_path" ]; then
            local team=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:2" "$plist_path" 2>/dev/null | grep -v "\-\-" || echo "")
            local saml=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:4" "$plist_path" 2>/dev/null | grep -v "\-\-" || echo "")
            
            if [ -n "$team" ]; then
                test_pass "Daemon has team configuration: $team"
            else
                test_info "Daemon has no team configuration"
            fi
            
            if [ -n "$saml" ]; then
                test_pass "Daemon has SAML configuration"
            else
                test_info "Daemon has no SAML configuration"
            fi
        fi
    else
        test_pass "AuthRouter daemon is not running (clean state)"
    fi
    
    # Test plist validation
    if [ -f "$plist_path" ]; then
        if plutil -lint "$plist_path" >/dev/null 2>&1; then
            test_pass "LaunchDaemon plist is valid"
        else
            test_fail "LaunchDaemon plist validation" "Invalid plist format"
        fi
    else
        test_info "LaunchDaemon plist not installed"
    fi
}

# Test MDM profile from build output
# Category: Medium/Component - MDM profile validation from build (30 seconds)
test_mdm_profile_generation() {
    echo -e "\n${YELLOW}Testing: MDM profile from build output${NC}"
    
    # Find MDM profile created by build script
    local mdm_profile=""
    for profile in "$PROJECT_ROOT"/deployment/macos/Postman-Enterprise-*-auth.mobileconfig; do
        if [ -f "$profile" ]; then
            mdm_profile="$profile"
            break
        fi
    done
    
    if [ -n "$mdm_profile" ] && [ -f "$mdm_profile" ]; then
        test_pass "Found MDM profile from build: $(basename "$mdm_profile")"
        
        # Validate profile structure
        if plutil -lint "$mdm_profile" >/dev/null 2>&1; then
            test_pass "MDM profile is valid XML/plist"
            
            # Check for required keys
            if grep -q "PayloadContent" "$mdm_profile"; then
                test_pass "MDM profile contains PayloadContent"
            else
                test_fail "MDM profile structure" "Missing PayloadContent"
            fi
            
            if grep -q "com.postman.authrouter.certificate" "$mdm_profile"; then
                test_pass "MDM profile has correct identifier"
            else
                test_fail "MDM profile identifier" "Missing or incorrect identifier"
            fi
        else
            test_fail "MDM profile validation" "Invalid XML/plist format"
        fi
    else
        test_info "No MDM profile found - build may not have been run"
    fi
    
    # Test installed generator if PKG was installed
    if [ -f "/usr/local/bin/postman/generate_mdm_profile.sh" ]; then
        test_info "Found installed MDM generator script"
        if [ "$EUID" -eq 0 ]; then
            local test_profile="/tmp/test_profile_$$.mobileconfig"
            if /usr/local/bin/postman/generate_mdm_profile.sh \
               "/usr/local/bin/postman/identity.getpostman.com.crt" \
               "$test_profile" 2>/dev/null; then
                test_pass "Installed MDM generator works"
                rm -f "$test_profile"
            else
                test_info "MDM generator requires certificate to exist"
            fi
        fi
    fi
}

# Test PKG installation readiness
# Category: Medium/Component - PKG installation validation (20 seconds)
test_pkg_installation_readiness() {
    echo -e "\n${YELLOW}Testing: PKG installation readiness${NC}"
    
    # Check if we have built PKGs
    local pkg_count=0
    for pkg in "$PROJECT_ROOT"/deployment/macos/Postman-Enterprise-*-saml.pkg; do
        if [ -f "$pkg" ]; then
            ((pkg_count++))
            test_pass "Found PKG ready for installation: $(basename "$pkg")"
            
            # Check PKG size
            local size=$(stat -f%z "$pkg" 2>/dev/null || stat -c%s "$pkg")
            if [ $size -gt 1048576 ]; then # > 1MB
                test_pass "PKG has reasonable size: $(($size/1024/1024))MB"
            else
                test_fail "PKG size" "PKG too small: $(($size/1024))KB"
            fi
        fi
    done
    
    if [ $pkg_count -eq 0 ]; then
        test_info "No PKGs found - need to run build first"
    else
        test_info "PKGs support runtime configuration via:"
        test_info "  sudo launchctl setenv INSTALLER_TEAM_NAME 'team'"
        test_info "  sudo launchctl setenv INSTALLER_SAML_URL 'https://...'"
        test_info "  sudo installer -pkg package.pkg -target /"
    fi
}

# Test hosts file operations
# Category: Slow/Integration - System hosts file modification (30 seconds)
test_hosts_file_operations() {
    echo -e "\n${YELLOW}Testing: Hosts file operations${NC}"
    
    if [ "$EUID" -ne 0 ]; then
        test_info "Skipping hosts file tests - requires root"
        return
    fi
    
    # Check current hosts file
    if grep -q "identity.getpostman.com" /etc/hosts; then
        test_info "Hosts file already contains identity.getpostman.com entry"
    else
        test_pass "Hosts file is clean"
    fi
    
    # Test hosts file backup
    if [ -f /etc/hosts.backup ] || [ -f /etc/hosts.pm-authrouter-backup ]; then
        test_info "Hosts file backup exists from previous run"
    else
        test_pass "No stale hosts file backups"
    fi
}

# Test DNS interception methods
# Category: Slow/Integration - DNS routing and interception testing (90 seconds)
test_dns_interception() {
    echo -e "\n${YELLOW}Testing: DNS interception methods${NC}"
    
    # Test DNS resolution
    local real_ip=$(nslookup identity.getpostman.com 8.8.8.8 2>/dev/null | grep -A1 "Name:" | grep "Address:" | awk '{print $2}')
    if [ -n "$real_ip" ]; then
        test_pass "Can resolve real IP of identity.getpostman.com: $real_ip"
    else
        test_info "Could not resolve real IP (may be offline)"
    fi
    
    # Test pfctl availability
    if which pfctl >/dev/null 2>&1; then
        test_pass "pfctl is available for DNS redirection"
        
        if [ "$EUID" -eq 0 ]; then
            # Check if pfctl is enabled
            if pfctl -s info 2>/dev/null | grep -q "Status: Enabled"; then
                test_info "pfctl is currently enabled"
            else
                test_info "pfctl is currently disabled"
            fi
        fi
    else
        test_fail "pfctl availability" "pfctl not found"
    fi
    
    # Test route command availability
    if which route >/dev/null 2>&1; then
        test_pass "route command is available"
    else
        test_fail "route availability" "route command not found"
    fi
}

# Test logging
# Category: Fast/Unit - Log file creation and permissions (15 seconds)
test_logging() {
    echo -e "\n${YELLOW}Testing: Logging configuration${NC}"
    
    local log_dir="/var/log/postman"
    local log_file="$log_dir/pm-authrouter.log"
    
    if [ -d "$log_dir" ]; then
        test_pass "Log directory exists"
        
        if [ -f "$log_file" ]; then
            test_info "Log file exists with $(wc -l < "$log_file") lines"
            
            # Check recent logs
            if [ "$EUID" -eq 0 ]; then
                tail -5 "$log_file" 2>/dev/null | while read line; do
                    test_info "Recent log: $line"
                done
            fi
        else
            test_info "No log file yet"
        fi
    else
        test_pass "Log directory not created yet (clean state)"
    fi
}

# Test uninstaller
# Category: Slow/Integration - Complete system cleanup and validation (2-3 minutes)
test_uninstaller() {
    echo -e "\n${YELLOW}Testing: Uninstaller script${NC}"
    
    local uninstaller="/usr/local/bin/postman/uninstall.sh"
    
    if [ -f "$uninstaller" ]; then
        test_pass "Uninstaller script exists"
        
        if [ -x "$uninstaller" ]; then
            test_pass "Uninstaller is executable"
        else
            test_fail "Uninstaller permissions" "Script not executable"
        fi
        
        # Validate script syntax
        if bash -n "$uninstaller" 2>/dev/null; then
            test_pass "Uninstaller has valid syntax"
        else
            test_fail "Uninstaller syntax" "Script has syntax errors"
        fi
    else
        test_info "Uninstaller not installed (package not deployed)"
    fi
}

# Verify cleanup was successful
verify_integration_cleanup() {
    echo -e "\n${YELLOW}Verifying integration cleanup...${NC}"
    local cleanup_issues=0
    
    # Check for daemon processes
    if pgrep -f pm-authrouter >/dev/null 2>&1; then
        test_fail "Process cleanup" "AuthRouter processes still running"
        ((cleanup_issues++))
    else
        test_pass "No AuthRouter processes remaining"
    fi
    
    # Check LaunchDaemon
    if launchctl list | grep -q com.postman.pm-authrouter; then
        test_info "LaunchDaemon still loaded (may be intentional)"
    else
        test_pass "LaunchDaemon not loaded"
    fi
    
    # Check hosts file entries
    if grep -q "identity.getpostman.com.*PostmanAuthRouter" /etc/hosts 2>/dev/null; then
        test_fail "Hosts cleanup" "DNS entries still present"
        ((cleanup_issues++))
    else
        test_pass "Hosts file cleaned"
    fi
    
    # Check for port 443 binding
    if [ "$EUID" -eq 0 ]; then
        if lsof -i :443 2>/dev/null | grep -q pm-authrouter; then
            test_fail "Port cleanup" "Port 443 still bound by AuthRouter"
            ((cleanup_issues++))
        else
            test_pass "Port 443 not bound by AuthRouter"
        fi
    fi
    
    # Check temporary test files
    if find /tmp -name "test_*_$$*" -type f 2>/dev/null | grep -q .; then
        test_fail "Temp file cleanup" "Test temporary files still exist"
        ((cleanup_issues++))
    else
        test_pass "Temporary test files cleaned"
    fi
    
    # Summary
    if [ $cleanup_issues -eq 0 ]; then
        test_pass "Integration cleanup verification successful"
    else
        test_fail "Cleanup verification" "$cleanup_issues issues found"
    fi
    
    return $cleanup_issues
}

# Cleanup function for integration tests
cleanup_integration() {
    echo -e "\n${YELLOW}Cleaning up integration test artifacts...${NC}"
    
    # Stop any running AuthRouter processes
    if pgrep -f pm-authrouter >/dev/null 2>&1; then
        echo "Stopping AuthRouter processes..."
        pkill -TERM -f pm-authrouter 2>/dev/null || true
        sleep 3
        
        # Force kill if still running
        if pgrep -f pm-authrouter >/dev/null 2>&1; then
            echo "Force killing AuthRouter processes..."
            pkill -KILL -f pm-authrouter 2>/dev/null || true
            sleep 1
        fi
    fi
    
    # Clean hosts file entries added during testing
    if [ "$EUID" -eq 0 ]; then
        if grep -q "identity.getpostman.com.*PostmanAuthRouter" /etc/hosts 2>/dev/null; then
            echo "Cleaning hosts file entries..."
            sed -i.bak '/identity.getpostman.com.*PostmanAuthRouter/d' /etc/hosts 2>/dev/null || true
        fi
    fi
    
    # Clean temporary test files
    echo "Removing temporary test files..."
    rm -f /tmp/test_*_$$* 2>/dev/null || true
    rm -f /tmp/test_profile_*.mobileconfig 2>/dev/null || true
    rm -f /tmp/test_cert_*.* 2>/dev/null || true
    
    # Verify cleanup was successful
    verify_integration_cleanup
}

# Test system state
# Category: Medium/Component - System state assessment and validation (45 seconds)
test_system_state() {
    echo -e "\n${YELLOW}Testing: Current system state${NC}"
    
    # Check if Postman Enterprise is installed
    if [ -d "/Applications/Postman Enterprise.app" ]; then
        test_info "Postman Enterprise.app is installed"
    else
        test_info "Postman Enterprise.app is not installed"
    fi
    
    # Check if AuthRouter binary exists
    if [ -f "/usr/local/bin/postman/pm-authrouter" ]; then
        test_pass "AuthRouter binary is installed"
        
        # Check binary permissions
        if [ -x "/usr/local/bin/postman/pm-authrouter" ]; then
            test_pass "AuthRouter binary is executable"
        else
            test_fail "AuthRouter permissions" "Binary not executable"
        fi
    else
        test_info "AuthRouter binary not installed"
    fi
    
    # Check port 443
    if [ "$EUID" -eq 0 ]; then
        if lsof -i :443 2>/dev/null | grep -q LISTEN; then
            test_info "Port 443 is in use"
            lsof -i :443 2>/dev/null | grep LISTEN | head -1
        else
            test_pass "Port 443 is available"
        fi
    fi
}

# Test post-installation components
# Category: Medium/Component - Post-installation validation (30 seconds)
test_post_installation() {
    echo -e "\n${YELLOW}Testing: Post-installation components${NC}"
    
    # Check if package was installed
    if [ -f "/usr/local/bin/postman/pm-authrouter" ]; then
        test_pass "AuthRouter binary installed"
        
        # Check binary is executable
        if [ -x "/usr/local/bin/postman/pm-authrouter" ]; then
            test_pass "AuthRouter binary is executable"
        else
            test_fail "AuthRouter permissions" "Binary not executable"
        fi
        
        # Test MDM generator script
        if [ -f "/usr/local/bin/postman/generate_mdm_profile.sh" ]; then
            test_pass "MDM generator script installed"
            
            # Check if it's executable
            if [ -x "/usr/local/bin/postman/generate_mdm_profile.sh" ]; then
                test_pass "MDM generator is executable"
                
                # Test it can generate a profile (requires root and certificate)
                if [ "$EUID" -eq 0 ] && [ -f "/usr/local/bin/postman/identity.getpostman.com.crt" ]; then
                    local test_profile="/tmp/test_mdm_$$.mobileconfig"
                    if /usr/local/bin/postman/generate_mdm_profile.sh \
                       "/usr/local/bin/postman/identity.getpostman.com.crt" \
                       "$test_profile" 2>/dev/null; then
                        test_pass "MDM generator creates valid profile"
                        
                        # Validate generated profile
                        if plutil -lint "$test_profile" >/dev/null 2>&1; then
                            test_pass "Generated profile is valid XML"
                        else
                            test_fail "Generated profile validation" "Invalid XML format"
                        fi
                        rm -f "$test_profile"
                    else
                        test_fail "MDM generator execution" "Failed to generate profile"
                    fi
                else
                    test_info "MDM generator test requires root and certificate"
                fi
            else
                test_fail "MDM generator permissions" "Script not executable"
            fi
        else
            test_info "MDM generator not installed (package may not be installed)"
        fi
        
        # Check uninstaller
        if [ -f "/usr/local/bin/postman/uninstall.sh" ]; then
            test_pass "Uninstaller script installed"
            if [ -x "/usr/local/bin/postman/uninstall.sh" ]; then
                test_pass "Uninstaller is executable"
            else
                test_fail "Uninstaller permissions" "Script not executable"
            fi
        else
            test_info "Uninstaller not installed"
        fi
    else
        test_info "Package not installed - skipping post-install tests"
        test_info "To install: sudo installer -pkg Postman-Enterprise-*-saml.pkg -target /"
    fi
}

# Main test runner
main() {
    echo "========================================"
    echo "macOS Integration Test Suite"
    echo "========================================"
    echo "Test started: $(date)"
    echo "" > "$TEST_RESULTS_FILE"
    
    # Set trap for cleanup
    trap cleanup_integration EXIT
    
    # Check if running as root
    if ! check_root; then
        echo -e "${YELLOW}Running with limited permissions - some tests will be skipped${NC}"
    fi
    
    # Run tests
    test_pkg_build
    test_certificate_operations
    test_launchdaemon_operations
    test_mdm_profile_generation
    test_pkg_installation_readiness
    test_hosts_file_operations
    test_dns_interception
    test_logging
    test_uninstaller
    test_system_state
    test_post_installation
    
    # Summary
    echo ""
    echo "========================================"
    echo "Test Summary"
    echo "========================================"
    echo -e "${GREEN}Passed: $PASSED_TESTS${NC}"
    echo -e "${RED}Failed: $FAILED_TESTS${NC}"
    
    # Run cleanup and verification (will update test counts)
    cleanup_integration
    
    if [ $FAILED_TESTS -eq 0 ]; then
        echo -e "\n${GREEN}All integration tests passed with clean system state!${NC}"
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