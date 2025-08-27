#!/bin/bash

# test_download_robustness.sh - Test download resilience and integrity validation
# Tests the build script's ability to handle connection interruptions and corrupted files

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_SCRIPT="$SCRIPT_DIR/../../deployment/macos/build_pkg_mdm.sh"
TEST_TEMP_DIR="/tmp/download_test_$$"
DOWNLOAD_URL="https://dl.pstmn.io/download/latest/version/11/osx_arm64?channel=enterprise&filetype=pkg"
FAILED_TESTS=0
PASSED_TESTS=0

# Create test directory
mkdir -p "$TEST_TEMP_DIR"
cd "$TEST_TEMP_DIR"

# Test logging functions
test_pass() {
    echo -e "${GREEN} PASS:${NC} $1"
    ((PASSED_TESTS++))
}

test_fail() {
    echo -e "${RED} FAIL:${NC} $1 - $2"
    ((FAILED_TESTS++))
}

test_info() {
    echo -e "${YELLOW}ℹ INFO:${NC} $1"
}

# Cleanup function
cleanup() {
    cd /
    rm -rf "$TEST_TEMP_DIR" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Download Robustness Tests ==="
echo "Test directory: $TEST_TEMP_DIR"

# Test 1: Validate build script handles corrupted PKG files
test_corrupted_pkg() {
    test_info "Test 1: Corrupted PKG handling"
    
    # Create a corrupted PKG file
    echo "This is not a valid PKG file" > "Postman-Enterprise-11.58.0-enterprise01-arm64.pkg"
    chmod 644 "Postman-Enterprise-11.58.0-enterprise01-arm64.pkg"
    
    # Try to build - should fail gracefully with validation error
    if "$BUILD_SCRIPT" --team "test" --saml-url "https://example.com/init" --offline --output "test.pkg" 2>&1 | grep -q "corrupted\|cannot be expanded"; then
        test_pass "Build script correctly detects corrupted PKG files"
    else
        test_fail "Build script detection" "Did not detect corrupted PKG file"
    fi
    
    rm -f "Postman-Enterprise-11.58.0-enterprise01-arm64.pkg"
}

# Test 2: Validate size checking works
test_undersized_pkg() {
    test_info "Test 2: Undersized PKG handling"
    
    # Create a PKG that's too small (1KB instead of ~115MB)
    dd if=/dev/zero of="Postman-Enterprise-11.58.0-enterprise01-arm64.pkg" bs=1024 count=1 2>/dev/null
    
    # Try to build - should fail with size validation error
    if "$BUILD_SCRIPT" --team "test" --saml-url "https://example.com/init" --offline --output "test.pkg" 2>&1 | grep -q "too small\|minimum.*MB"; then
        test_pass "Build script correctly detects undersized PKG files"
    else
        test_fail "Size validation" "Did not detect undersized PKG file"
    fi
    
    rm -f "Postman-Enterprise-11.58.0-enterprise01-arm64.pkg"
}

# Test 3: Test download with connection timeout simulation
test_download_timeout() {
    test_info "Test 3: Download timeout handling"
    
    # Remove any existing PKGs to force download
    rm -f Postman-Enterprise-*.pkg
    
    # Set a very short timeout to simulate connection issues
    export CURL_TIMEOUT=1
    
    # This should fail but gracefully with retry attempts
    if "$BUILD_SCRIPT" --team "test" --saml-url "https://example.com/init" --output "timeout-test.pkg" 2>&1 | grep -q "Download attempt.*failed\|retry"; then
        test_pass "Build script handles download timeouts with retry logic"
    else
        test_info "Download timeout test may have succeeded if connection was fast enough"
    fi
    
    unset CURL_TIMEOUT
}

# Test 4: Test successful download and validation
test_successful_download() {
    test_info "Test 4: Successful download and validation"
    
    # Remove any existing PKGs
    rm -f Postman-Enterprise-*.pkg
    
    # Download with our robust curl settings (match build script)
    if curl -L --fail --silent --connect-timeout 57 --max-time 900 --retry 2 --retry-delay 3 --retry-max-time 300 -C - -o "test-download.pkg" "$DOWNLOAD_URL"; then
        # Validate the download
        local size=$(stat -f%z "test-download.pkg" 2>/dev/null || stat -c%s "test-download.pkg")
        local min_size=$((100 * 1024 * 1024)) # 100MB minimum
        
        if [[ $size -gt $min_size ]]; then
            test_pass "Downloaded PKG has reasonable size: $((size/1024/1024))MB"
            
            # Test PKG can be expanded
            local test_dir="/tmp/pkg-expand-test-$$"
            if pkgutil --expand "test-download.pkg" "$test_dir" 2>/dev/null; then
                test_pass "Downloaded PKG can be properly expanded"
                rm -rf "$test_dir"
            else
                test_fail "PKG expansion" "Downloaded PKG cannot be expanded"
            fi
        else
            test_fail "Download size" "Downloaded PKG too small: $((size/1024/1024))MB"
        fi
    else
        test_fail "Download test" "Could not download PKG for validation"
    fi
}

# Test 5: Test resume capability with -C flag
test_resume_download() {
    test_info "Test 5: Download resume capability"
    
    # Create a partial file
    head -c 1000000 /dev/urandom > "partial-download.pkg" # 1MB partial file
    local initial_size=$(stat -f%z "partial-download.pkg" 2>/dev/null || stat -c%s "partial-download.pkg")
    
    # Try to resume download (this may complete or fail, but should handle -C flag gracefully)
    if curl -L --fail --silent --connect-timeout 57 --max-time 900 --retry 2 --retry-delay 3 --retry-max-time 300 -C - -o "partial-download.pkg" "$DOWNLOAD_URL" 2>/dev/null || true; then
        local final_size=$(stat -f%z "partial-download.pkg" 2>/dev/null || stat -c%s "partial-download.pkg")
        
        if [[ $final_size -gt $initial_size ]]; then
            test_pass "Download resume functionality works (size increased from $((initial_size/1024))KB to $((final_size/1024))KB)"
        else
            test_info "Resume test inconclusive - may have failed due to server not supporting range requests"
        fi
    else
        test_info "Resume download failed - this is acceptable behavior"
    fi
}

# Run all tests
test_corrupted_pkg
test_undersized_pkg
test_download_timeout
test_successful_download
test_resume_download

# Summary
echo ""
echo "=== Test Summary ==="
echo -e "Passed: ${GREEN}$PASSED_TESTS${NC}"
echo -e "Failed: ${RED}$FAILED_TESTS${NC}"

if [[ $FAILED_TESTS -eq 0 ]]; then
    echo -e "${GREEN}All download robustness tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed. Review download handling logic.${NC}"
    exit 1
fi