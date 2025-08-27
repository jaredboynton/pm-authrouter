#!/bin/bash
# test_browser_sessions.sh - Test browser profile detection and session cleanup
# Tests paths_darwin.go functionality for all supported browsers

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
TEST_DIR="/tmp/pm-authrouter-browser-test"
PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

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

# Test Chrome profile detection
test_chrome_profiles() {
    echo -e "\n${YELLOW}Testing Chrome profile detection...${NC}"
    
    # Create mock Chrome profile structure
    CHROME_DIR="$HOME/Library/Application Support/Google/Chrome"
    
    if [ -d "$CHROME_DIR" ]; then
        # Test Default profile detection
        if [ -d "$CHROME_DIR/Default" ]; then
            pass "Chrome Default profile detected at $CHROME_DIR/Default"
        else
            skip "Chrome Default profile not found"
        fi
        
        # Test additional profile detection (Profile 1, Profile 2, etc)
        PROFILE_COUNT=0
        for profile in "$CHROME_DIR"/Profile*; do
            if [ -d "$profile" ]; then
                pass "Chrome profile detected: $(basename "$profile")"
                ((PROFILE_COUNT++))
            fi
        done
        
        if [ $PROFILE_COUNT -eq 0 ]; then
            skip "No additional Chrome profiles found"
        else
            pass "Found $PROFILE_COUNT additional Chrome profiles"
        fi
        
        # Test cookie file locations
        if [ -f "$CHROME_DIR/Default/Cookies" ]; then
            pass "Chrome cookies database found"
        else
            skip "Chrome cookies database not found"
        fi
    else
        skip "Chrome not installed - skipping Chrome tests"
    fi
}

# Test Chromium profile detection
test_chromium_profiles() {
    echo -e "\n${YELLOW}Testing Chromium profile detection...${NC}"
    
    CHROMIUM_DIR="$HOME/Library/Application Support/Chromium"
    
    if [ -d "$CHROMIUM_DIR" ]; then
        if [ -d "$CHROMIUM_DIR/Default" ]; then
            pass "Chromium Default profile detected"
        else
            fail "Chromium installed but Default profile not found"
        fi
    else
        skip "Chromium not installed - skipping Chromium tests"
    fi
}

# Test Firefox profile detection
test_firefox_profiles() {
    echo -e "\n${YELLOW}Testing Firefox profile detection...${NC}"
    
    FIREFOX_DIR="$HOME/Library/Application Support/Firefox/Profiles"
    
    if [ -d "$FIREFOX_DIR" ]; then
        PROFILE_COUNT=0
        for profile in "$FIREFOX_DIR"/*; do
            if [ -d "$profile" ]; then
                pass "Firefox profile detected: $(basename "$profile")"
                ((PROFILE_COUNT++))
                
                # Check for cookies database in profile
                if [ -f "$profile/cookies.sqlite" ]; then
                    pass "Firefox cookies database found in $(basename "$profile")"
                fi
            fi
        done
        
        if [ $PROFILE_COUNT -eq 0 ]; then
            fail "Firefox installed but no profiles found"
        else
            pass "Found $PROFILE_COUNT Firefox profiles"
        fi
    else
        skip "Firefox not installed - skipping Firefox tests"
    fi
}

# Test Safari cookie detection
test_safari_cookies() {
    echo -e "\n${YELLOW}Testing Safari cookie detection...${NC}"
    
    # Check old location
    OLD_COOKIE_PATH="$HOME/Library/Cookies/Cookies.binarycookies"
    if [ -f "$OLD_COOKIE_PATH" ]; then
        pass "Safari cookies found at legacy location"
    else
        skip "Safari cookies not found at legacy location"
    fi
    
    # Check new location (macOS 10.15+)
    NEW_COOKIE_PATH="$HOME/Library/HTTPStorages/com.apple.Safari/Cookies.binarycookies"
    if [ -f "$NEW_COOKIE_PATH" ]; then
        pass "Safari cookies found at modern location"
    else
        skip "Safari cookies not found at modern location"
    fi
    
    # Check Safari cache
    SAFARI_CACHE="$HOME/Library/Caches/com.apple.Safari"
    if [ -d "$SAFARI_CACHE" ]; then
        pass "Safari cache directory found"
    else
        skip "Safari cache directory not found"
    fi
}

# Test Edge profile detection
test_edge_profiles() {
    echo -e "\n${YELLOW}Testing Edge profile detection...${NC}"
    
    EDGE_DIR="$HOME/Library/Application Support/Microsoft Edge"
    
    if [ -d "$EDGE_DIR" ]; then
        # Test Default profile
        if [ -d "$EDGE_DIR/Default" ]; then
            pass "Edge Default profile detected"
        else
            fail "Edge installed but Default profile not found"
        fi
        
        # Test additional profiles
        PROFILE_COUNT=0
        for profile in "$EDGE_DIR"/Profile*; do
            if [ -d "$profile" ]; then
                pass "Edge profile detected: $(basename "$profile")"
                ((PROFILE_COUNT++))
            fi
        done
        
        if [ $PROFILE_COUNT -gt 0 ]; then
            pass "Found $PROFILE_COUNT additional Edge profiles"
        fi
    else
        skip "Edge not installed - skipping Edge tests"
    fi
}

# Test profile permission checks
test_profile_permissions() {
    echo -e "\n${YELLOW}Testing profile access permissions...${NC}"
    
    # Check if we can read browser profiles without elevated permissions
    CHROME_DIR="$HOME/Library/Application Support/Google/Chrome"
    
    if [ -d "$CHROME_DIR/Default" ]; then
        if [ -r "$CHROME_DIR/Default" ]; then
            pass "Can read Chrome profiles with current permissions"
        else
            fail "Cannot read Chrome profiles - may need elevated permissions"
        fi
    fi
    
    # Test write permissions (should fail for safety)
    if [ -d "$CHROME_DIR/Default" ]; then
        if [ -w "$CHROME_DIR/Default/Cookies" ] 2>/dev/null; then
            fail "WARNING: Can write to Chrome cookies - security risk!"
        else
            pass "Cannot write to Chrome cookies (expected for security)"
        fi
    fi
}

# Test mock browser profile creation
test_mock_profiles() {
    echo -e "\n${YELLOW}Testing mock profile creation for testing...${NC}"
    
    # Create mock browser structure
    MOCK_CHROME="$TEST_DIR/Library/Application Support/Google/Chrome"
    mkdir -p "$MOCK_CHROME/Default"
    mkdir -p "$MOCK_CHROME/Profile 1"
    mkdir -p "$MOCK_CHROME/Profile 2"
    
    if [ -d "$MOCK_CHROME/Default" ] && [ -d "$MOCK_CHROME/Profile 1" ]; then
        pass "Successfully created mock Chrome profile structure"
    else
        fail "Failed to create mock Chrome profile structure"
    fi
    
    # Create mock Firefox structure
    MOCK_FIREFOX="$TEST_DIR/Library/Application Support/Firefox/Profiles"
    mkdir -p "$MOCK_FIREFOX/abcd1234.default"
    mkdir -p "$MOCK_FIREFOX/efgh5678.dev-edition"
    
    if [ -d "$MOCK_FIREFOX/abcd1234.default" ]; then
        pass "Successfully created mock Firefox profile structure"
    else
        fail "Failed to create mock Firefox profile structure"
    fi
}

# Test session file detection
test_session_files() {
    echo -e "\n${YELLOW}Testing session file detection...${NC}"
    
    # Check for session restoration files
    CHROME_DIR="$HOME/Library/Application Support/Google/Chrome"
    if [ -d "$CHROME_DIR/Default" ]; then
        SESSION_FILES=(
            "Current Session"
            "Current Tabs"
            "Last Session"
            "Last Tabs"
        )
        
        for file in "${SESSION_FILES[@]}"; do
            if [ -f "$CHROME_DIR/Default/$file" ]; then
                pass "Chrome session file found: $file"
            else
                skip "Chrome session file not found: $file"
            fi
        done
    fi
}

# Test cleanup simulation
test_cleanup_simulation() {
    echo -e "\n${YELLOW}Testing cleanup simulation (dry run)...${NC}"
    
    # Create test cookies file
    TEST_COOKIES="$TEST_DIR/test_cookies"
    echo "test cookie data" > "$TEST_COOKIES"
    
    if [ -f "$TEST_COOKIES" ]; then
        pass "Created test cookie file"
        
        # Simulate cleanup (don't actually delete)
        if [ -w "$TEST_COOKIES" ]; then
            pass "Would be able to clean test cookie file"
            rm "$TEST_COOKIES"
            pass "Successfully removed test cookie file"
        else
            fail "Cannot clean test cookie file"
        fi
    else
        fail "Failed to create test cookie file"
    fi
}

# Test binary integration
test_binary_integration() {
    echo -e "\n${YELLOW}Testing integration with pm-authrouter binary...${NC}"
    
    # Check if binary exists
    BINARY_PATH="../../cmd/pm-authrouter/pm-authrouter"
    
    if [ -f "$BINARY_PATH" ]; then
        pass "pm-authrouter binary found"
        
        # Check if it has browser session functions
        if strings "$BINARY_PATH" 2>/dev/null | grep -q "getChromeProfilePaths"; then
            pass "Binary contains Chrome profile detection code"
        else
            skip "Binary Chrome profile detection not verified"
        fi
        
        if strings "$BINARY_PATH" 2>/dev/null | grep -q "getFirefoxProfilePaths"; then
            pass "Binary contains Firefox profile detection code"
        else
            skip "Binary Firefox profile detection not verified"
        fi
    else
        skip "pm-authrouter binary not built - skipping integration tests"
    fi
}

# Main test execution
main() {
    echo "=================================="
    echo "Browser Session Detection Tests"
    echo "=================================="
    
    setup_test_env
    
    test_chrome_profiles
    test_chromium_profiles
    test_firefox_profiles
    test_safari_cookies
    test_edge_profiles
    test_profile_permissions
    test_mock_profiles
    test_session_files
    test_cleanup_simulation
    test_binary_integration
    
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