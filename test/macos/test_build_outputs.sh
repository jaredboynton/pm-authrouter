#!/bin/bash

# test_build_outputs.sh - Test build script outputs match expectations
# Focused testing of build_pkg_mdm.sh outputs

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
BUILD_DIR="$PROJECT_ROOT/deployment/macos"
BUILD_SCRIPT="$BUILD_DIR/build_pkg_mdm.sh"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

# Test helper functions
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

info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

# Check if build script exists
check_build_script() {
    echo -e "\n${YELLOW}Checking build script...${NC}"
    
    if [ ! -f "$BUILD_SCRIPT" ]; then
        fail "Build script not found at: $BUILD_SCRIPT"
        return 1
    fi
    
    pass "Build script found: $(basename "$BUILD_SCRIPT")"
    
    # Check if it's executable
    if [ -x "$BUILD_SCRIPT" ]; then
        pass "Build script is executable"
    else
        fail "Build script is not executable"
        info "Run: chmod +x $BUILD_SCRIPT"
    fi
    
    return 0
}

# Check for original PKGs
check_original_pkgs() {
    echo -e "\n${YELLOW}Checking for original Postman PKGs...${NC}"
    
    local found_arm64=false
    local found_intel=false
    
    # Check for ARM64 PKG
    for pkg in "$BUILD_DIR"/Postman-Enterprise-*-arm64.pkg; do
        if [ -f "$pkg" ] && [[ ! "$(basename "$pkg")" =~ -saml ]]; then
            pass "Found ARM64 original PKG: $(basename "$pkg")"
            found_arm64=true
            break
        fi
    done
    
    if [ "$found_arm64" = false ]; then
        info "No ARM64 original PKG found"
    fi
    
    # Check for Intel PKG
    for pkg in "$BUILD_DIR"/Postman-Enterprise-*-x64.pkg; do
        if [ -f "$pkg" ] && [[ ! "$(basename "$pkg")" =~ -saml ]]; then
            pass "Found Intel original PKG: $(basename "$pkg")"
            found_intel=true
            break
        fi
    done
    
    if [ "$found_intel" = false ]; then
        info "No Intel original PKG found"
    fi
    
    if [ "$found_arm64" = false ] && [ "$found_intel" = false ]; then
        fail "No original Postman PKGs found"
        info "Download PKGs or enable auto-download in build script"
        return 1
    fi
    
    return 0
}

# Test basic build
test_basic_build() {
    echo -e "\n${YELLOW}Testing basic build (no configuration)...${NC}"
    
    cd "$BUILD_DIR" || {
        fail "Cannot change to build directory"
        return 1
    }
    
    # Run build without parameters
    if ./build_pkg_mdm.sh --quiet; then
        pass "Build completed without configuration"
    else
        fail "Build failed without configuration"
        return 1
    fi
    
    # Check for output files
    local pkg_found=false
    for pkg in Postman-Enterprise-*-saml.pkg; do
        if [ -f "$pkg" ]; then
            pkg_found=true
            local size=$(stat -f%z "$pkg" 2>/dev/null || stat -c%s "$pkg")
            if [ $size -gt 1048576 ]; then  # > 1MB
                pass "PKG created: $pkg ($(($size/1024/1024))MB)"
            else
                fail "PKG too small: $pkg ($(($size/1024))KB)"
            fi
        fi
    done
    
    if [ "$pkg_found" = false ]; then
        fail "No SAML PKG created"
    fi
    
    # Check for MDM profile
    local profile_found=false
    for profile in Postman-Enterprise-*-auth.mobileconfig; do
        if [ -f "$profile" ]; then
            profile_found=true
            if plutil -lint "$profile" >/dev/null 2>&1; then
                pass "Valid MDM profile: $profile"
                
                # Check profile contents
                if grep -q "PayloadContent" "$profile"; then
                    pass "MDM profile has PayloadContent"
                else
                    fail "MDM profile missing PayloadContent"
                fi
                
                if grep -q "com.postman.authrouter.certificate" "$profile"; then
                    pass "MDM profile has correct identifier"
                else
                    fail "MDM profile has incorrect identifier"
                fi
            else
                fail "Invalid MDM profile: $profile"
            fi
        fi
    done
    
    if [ "$profile_found" = false ]; then
        fail "No MDM profile created"
    fi
}

# Test build with configuration
test_configured_build() {
    echo -e "\n${YELLOW}Testing build with configuration...${NC}"
    
    local test_team="test-team-$$"
    local test_saml="https://identity.getpostman.com/sso/test/$$/init"
    
    cd "$BUILD_DIR" || {
        fail "Cannot change to build directory"
        return 1
    }
    
    # Clean previous builds
    rm -f Postman-Enterprise-*-saml.pkg 2>/dev/null
    rm -f Postman-Enterprise-*-auth.mobileconfig 2>/dev/null
    
    # Run build with configuration
    if ./build_pkg_mdm.sh --team "$test_team" --saml-url "$test_saml" --quiet; then
        pass "Build completed with configuration"
    else
        fail "Build failed with configuration"
        return 1
    fi
    
    # Verify PKG was created
    local pkg_count=0
    for pkg in Postman-Enterprise-*-saml.pkg; do
        if [ -f "$pkg" ]; then
            ((pkg_count++))
            pass "Configured PKG created: $pkg"
            
            # TODO: Could expand PKG and verify configuration is embedded
            # but that's complex and requires temp directories
        fi
    done
    
    if [ $pkg_count -eq 0 ]; then
        fail "No configured PKG created"
    fi
}

# Test build script options
test_build_options() {
    echo -e "\n${YELLOW}Testing build script options...${NC}"
    
    cd "$BUILD_DIR" || return 1
    
    # Test help
    if ./build_pkg_mdm.sh --help 2>&1 | grep -q "Usage:"; then
        pass "Help option works"
    else
        fail "Help option doesn't show usage"
    fi
    
    # Test version
    if ./build_pkg_mdm.sh --version 2>&1 | grep -q "version"; then
        pass "Version option works"
    else
        fail "Version option doesn't show version"
    fi
    
    # Test debug mode
    if ./build_pkg_mdm.sh --debug --help 2>&1 | grep -q "Debug mode enabled"; then
        pass "Debug mode option accepted"
    else
        skip "Debug mode not testable with help"
    fi
    
    # Test offline mode
    if ./build_pkg_mdm.sh --offline --help 2>&1 | grep -q "Offline mode enabled"; then
        pass "Offline mode option accepted"
    else
        skip "Offline mode not testable with help"
    fi
}

# Clean up test artifacts
cleanup_test_artifacts() {
    echo -e "\n${YELLOW}Cleaning up test artifacts...${NC}"
    
    cd "$BUILD_DIR" || return
    
    # Remove test-generated files only
    local cleaned=0
    
    # Clean test PKGs (keep original PKGs)
    for pkg in Postman-Enterprise-*-saml.pkg; do
        if [ -f "$pkg" ] && [[ "$(basename "$pkg")" =~ test-team ]]; then
            rm -f "$pkg"
            ((cleaned++))
        fi
    done
    
    if [ $cleaned -gt 0 ]; then
        pass "Cleaned $cleaned test artifacts"
    else
        info "No test artifacts to clean"
    fi
}

# Main test runner
main() {
    echo "========================================"
    echo "Build Output Tests"
    echo "========================================"
    echo "Testing: $BUILD_SCRIPT"
    echo ""
    
    # Check prerequisites
    if ! check_build_script; then
        echo -e "\n${RED}Cannot proceed without build script${NC}"
        exit 1
    fi
    
    if ! check_original_pkgs; then
        echo -e "\n${YELLOW}Warning: No original PKGs found${NC}"
        echo "Build script will attempt to download them"
    fi
    
    # Run tests
    test_build_options
    test_basic_build
    test_configured_build
    
    # Cleanup
    cleanup_test_artifacts
    
    # Summary
    echo ""
    echo "========================================"
    echo "Test Summary"
    echo "========================================"
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

# Run if executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi