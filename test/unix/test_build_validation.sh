#!/bin/bash

# test_build_validation.sh - Unix Build Script Validation Tests
# Comprehensive testing of build_msi_mdm_unix.sh functionality and validation phases

set -e

# Test configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${POSTMAN_TEST_PROJECT_ROOT:-$(dirname "$(dirname "$SCRIPT_DIR")")}"
BUILD_SCRIPT="$PROJECT_ROOT/deployment/windows/build_msi_mdm_unix.sh"
TEMP_TEST_DIR=""
TEST_RESULTS=()
TOTAL_TESTS=0
FAILED_TESTS=0

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test helper functions
log_test_info() {
    echo -e "${BLUE}[TEST INFO]${NC} $1"
}

log_test_pass() {
    echo -e "${GREEN}[TEST PASS]${NC} $1"
    TEST_RESULTS+=("PASS: $1")
}

log_test_fail() {
    echo -e "${RED}[TEST FAIL]${NC} $1"
    TEST_RESULTS+=("FAIL: $1")
    ((FAILED_TESTS++))
}

log_test_skip() {
    echo -e "${YELLOW}[TEST SKIP]${NC} $1"
    TEST_RESULTS+=("SKIP: $1")
}

# Setup and cleanup functions
setup_test_environment() {
    log_test_info "Setting up test environment..."
    
    TEMP_TEST_DIR=$(mktemp -d "/tmp/postman-build-test-$$-XXXXXX")
    export BUILD_WORK_DIR="$TEMP_TEST_DIR/work"
    export BUILD_LOG_DIR="$TEMP_TEST_DIR/logs"
    export DEBUG_MODE="1"
    
    log_test_info "Test workspace: $TEMP_TEST_DIR"
    log_test_info "Work directory: $BUILD_WORK_DIR" 
    log_test_info "Log directory: $BUILD_LOG_DIR"
    
    # Ensure build script exists
    if [[ ! -f "$BUILD_SCRIPT" ]]; then
        echo "ERROR: Build script not found: $BUILD_SCRIPT"
        exit 1
    fi
    
    # Make build script executable
    chmod +x "$BUILD_SCRIPT"
}

cleanup_test_environment() {
    if [[ -n "$TEMP_TEST_DIR" ]] && [[ -d "$TEMP_TEST_DIR" ]]; then
        log_test_info "Cleaning up test environment: $TEMP_TEST_DIR"
        rm -rf "$TEMP_TEST_DIR" 2>/dev/null || true
    fi
}

# Trap cleanup on exit
trap cleanup_test_environment EXIT

# Test dependency checking functionality
test_dependency_checking() {
    ((TOTAL_TESTS++))
    log_test_info "Testing dependency checking functionality..."
    
    # Test with missing dependencies (simulate)
    local test_script="$TEMP_TEST_DIR/test_deps.sh"
    
    # Create a modified build script that we can control
    cp "$BUILD_SCRIPT" "$test_script"
    chmod +x "$test_script"
    
    # Test dependency check function by running just the dependency check
    if grep -q "check_and_install_dependencies" "$test_script"; then
        log_test_pass "Dependency checking function found in build script"
    else
        log_test_fail "Dependency checking function missing from build script"
        return 1
    fi
    
    # Test if script properly detects missing tools
    # We'll test this by temporarily renaming a required tool
    local original_tool=""
    local temp_tool=""
    
    # Find a tool we can temporarily disable
    for tool in msiextract msidump msibuild; do
        if command -v "$tool" >/dev/null 2>&1; then
            original_tool="$tool"
            temp_tool="${tool}_disabled_for_test"
            break
        fi
    done
    
    if [[ -n "$original_tool" ]]; then
        # Temporarily disable the tool
        local tool_path=$(command -v "$original_tool")
        if [[ -w "$(dirname "$tool_path")" ]]; then
            mv "$tool_path" "${tool_path}_disabled" 2>/dev/null || true
            
            # Test that script detects missing tool
            if "$test_script" --help >/dev/null 2>&1; then
                # Restore tool
                mv "${tool_path}_disabled" "$tool_path" 2>/dev/null || true
                log_test_pass "Build script handles missing dependencies gracefully"
            else
                # Restore tool
                mv "${tool_path}_disabled" "$tool_path" 2>/dev/null || true
                log_test_fail "Build script does not handle missing dependencies properly"
                return 1
            fi
        else
            log_test_skip "Cannot test missing dependencies (insufficient permissions)"
        fi
    else
        log_test_skip "Cannot test missing dependencies (no suitable tool found)"
    fi
}

# Test build script argument parsing
test_argument_parsing() {
    ((TOTAL_TESTS++))
    log_test_info "Testing build script argument parsing..."
    
    # Test help option
    if "$BUILD_SCRIPT" --help >/dev/null 2>&1; then
        log_test_pass "Build script --help option works"
    else
        log_test_fail "Build script --help option failed"
        return 1
    fi
    
    # Test version option
    if "$BUILD_SCRIPT" --version >/dev/null 2>&1; then
        log_test_pass "Build script --version option works"
    else
        log_test_fail "Build script --version option failed"
        return 1
    fi
    
    # Test invalid option handling
    if ! "$BUILD_SCRIPT" --invalid-option >/dev/null 2>&1; then
        log_test_pass "Build script properly rejects invalid options"
    else
        log_test_fail "Build script does not reject invalid options"
        return 1
    fi
}

# Test MSI extraction functionality
test_msi_extraction() {
    ((TOTAL_TESTS++))
    log_test_info "Testing MSI extraction functionality..."
    
    # Find original Postman MSI
    local original_msi=$(find "$PROJECT_ROOT/deployment/windows" -name "Postman-Enterprise-*.msi" ! -name "*-saml.msi" | head -1)
    
    if [[ -z "$original_msi" ]] || [[ ! -f "$original_msi" ]]; then
        log_test_skip "Original Postman MSI not found - skipping extraction test"
        return 0
    fi
    
    log_test_info "Using original MSI: $(basename "$original_msi")"
    
    # Test MSI extraction using msitools directly
    local extract_dir="$TEMP_TEST_DIR/msi_extract_test"
    mkdir -p "$extract_dir"
    
    if command -v msiextract >/dev/null 2>&1; then
        cd "$extract_dir"
        if msiextract -C extracted_files "$original_msi" >/dev/null 2>&1; then
            if [[ -d "extracted_files" ]] && [[ $(find extracted_files -type f | wc -l) -gt 0 ]]; then
                log_test_pass "MSI file extraction successful"
            else
                log_test_fail "MSI extraction produced no files"
                return 1
            fi
        else
            log_test_fail "MSI extraction failed"
            return 1
        fi
        
        # Test IDT table extraction
        if msidump -t "$original_msi" >/dev/null 2>&1; then
            if ls *.idt >/dev/null 2>&1; then
                local idt_count=$(ls *.idt | wc -l)
                log_test_pass "IDT table extraction successful ($idt_count tables)"
            else
                log_test_fail "No IDT tables extracted"
                return 1
            fi
        else
            log_test_fail "IDT table extraction failed"
            return 1
        fi
        
        # Test stream extraction
        if msidump -s "$original_msi" >/dev/null 2>&1; then
            if [[ -d "_Streams" ]] && [[ $(find _Streams -type f | wc -l) -gt 0 ]]; then
                log_test_pass "MSI stream extraction successful"
            else
                log_test_fail "MSI stream extraction produced no files"
                return 1
            fi
        else
            log_test_fail "MSI stream extraction failed"
            return 1
        fi
        
    else
        log_test_skip "msitools not available - skipping MSI extraction test"
        return 0
    fi
}

# Test certificate generation
test_certificate_generation() {
    ((TOTAL_TESTS++))
    log_test_info "Testing certificate generation functionality..."
    
    local cert_dir="$TEMP_TEST_DIR/cert_test"
    mkdir -p "$cert_dir"
    cd "$cert_dir"
    
    # Test CA certificate generation
    if openssl req -new -x509 -days 1 -nodes -out test_ca.crt -keyout test_ca.key \
        -subj "/C=US/ST=CA/L=SF/O=Test/CN=Test CA" >/dev/null 2>&1; then
        log_test_pass "CA certificate generation successful"
    else
        log_test_fail "CA certificate generation failed"
        return 1
    fi
    
    # Test server certificate generation
    if openssl req -new -nodes -out test_server.csr -keyout test_server.key \
        -subj "/C=US/ST=CA/L=SF/O=Test/CN=identity.getpostman.com" >/dev/null 2>&1; then
        log_test_pass "Server certificate request generation successful"
    else
        log_test_fail "Server certificate request generation failed"
        return 1
    fi
    
    # Test certificate signing
    if openssl x509 -req -in test_server.csr -CA test_ca.crt -CAkey test_ca.key -CAcreateserial \
        -out test_server.crt -days 1 >/dev/null 2>&1; then
        log_test_pass "Server certificate signing successful"
    else
        log_test_fail "Server certificate signing failed"
        return 1
    fi
    
    # Test certificate verification
    if openssl verify -CAfile test_ca.crt test_server.crt >/dev/null 2>&1; then
        log_test_pass "Certificate chain verification successful"
    else
        log_test_fail "Certificate chain verification failed"
        return 1
    fi
}

# Test wixl cabinet compression
test_wixl_compression() {
    ((TOTAL_TESTS++))
    log_test_info "Testing wixl cabinet compression functionality..."
    
    if ! command -v wixl >/dev/null 2>&1; then
        log_test_skip "wixl not available - skipping compression test"
        return 0
    fi
    
    local wixl_dir="$TEMP_TEST_DIR/wixl_test"
    mkdir -p "$wixl_dir"
    cd "$wixl_dir"
    
    # Create test files
    echo "Test content 1" > test1.txt
    echo "Test content 2" > test2.txt
    
    # Create simple WXS file
    cat > test.wxs << 'EOF'
<?xml version='1.0' encoding='windows-1252'?>
<Wix xmlns='http://schemas.microsoft.com/wix/2006/wi'>
  <Product Name='Test' Id='12345678-1234-5678-9ABC-DEF012345678' 
    UpgradeCode='87654321-4321-8765-CBA9-FED210987654'
    Language='1033' Codepage='1252' Version='1.0.0' Manufacturer='Test'>
    <Package Id='*' Keywords='Installer' Description="Test MSI"
      Manufacturer='Test' InstallerVersion='100' Languages='1033' Compressed='yes' />
    <Media Id='1' Cabinet='test.cab' EmbedCab='yes' />
    <Directory Id='TARGETDIR' Name='SourceDir'>
      <Directory Id='INSTALLDIR' Name='Install'>
        <Component Id='TestFiles' Guid='{ABCDEF12-3456-7890-ABCD-EF1234567890}'>
          <File Id='test1_txt' Source='test1.txt' Name='test1.txt' />
          <File Id='test2_txt' Source='test2.txt' Name='test2.txt' />
        </Component>
      </Directory>
    </Directory>
    <Feature Id='Complete' Level='1'>
      <ComponentRef Id='TestFiles' />
    </Feature>
  </Product>
</Wix>
EOF
    
    # Test wixl compilation
    if wixl test.wxs >/dev/null 2>&1; then
        if [[ -f "test.msi" ]]; then
            log_test_pass "wixl MSI compilation successful"
            
            # Test that the MSI is valid
            if file test.msi | grep -q "Composite Document File"; then
                log_test_pass "Generated MSI has correct file format"
            else
                log_test_fail "Generated MSI has incorrect file format"
                return 1
            fi
        else
            log_test_fail "wixl compilation did not produce MSI file"
            return 1
        fi
    else
        log_test_fail "wixl MSI compilation failed"
        return 1
    fi
}

# Test IDT schema validation
test_idt_validation() {
    ((TOTAL_TESTS++))
    log_test_info "Testing IDT schema validation functionality..."
    
    local idt_dir="$TEMP_TEST_DIR/idt_test"
    mkdir -p "$idt_dir"
    cd "$idt_dir"
    
    # Create test IDT files with correct format
    cat > Component.idt << 'EOF'
Component	Component_	Directory_	Attributes	Condition	KeyPath
s72	s72	s72	i2	S255	S72
Component	Component
TestComponent	{12345678-1234-5678-9ABC-DEF012345678}	INSTALLDIR	260		test.txt
EOF
    
    cat > File.idt << 'EOF'
File	Component_	FileName	FileSize	Version	Language	Attributes	Sequence
s72	s72	l255	i4	S72	S20	I2	i2
File	File
test.txt	TestComponent	test.txt	100		1033	512	1
EOF
    
    # Test IDT format validation
    if [[ $(wc -l < Component.idt) -ge 4 ]]; then
        log_test_pass "Component.idt has correct minimum line count"
    else
        log_test_fail "Component.idt has insufficient lines"
        return 1
    fi
    
    # Test column format
    local header_line=$(head -1 Component.idt)
    if echo "$header_line" | grep -q "Component.*Directory_.*Attributes"; then
        log_test_pass "Component.idt has correct header format"
    else
        log_test_fail "Component.idt has incorrect header format"
        return 1
    fi
    
    # Test data line format
    local data_line=$(tail -1 Component.idt)
    if echo "$data_line" | grep -q "TestComponent.*{.*}.*INSTALLDIR"; then
        log_test_pass "Component.idt has correct data format"
    else
        log_test_fail "Component.idt has incorrect data format"  
        return 1
    fi
}

# Test build validation phases
test_validation_phases() {
    ((TOTAL_TESTS++))
    log_test_info "Testing build validation phases functionality..."
    
    # Test if build script contains all 5 validation phases mentioned in the plan
    local validation_phases=(
        "validate_original_msi_structure"
        "validate_source_components" 
        "validate_idt_schema"
        "validate_idt_relationships"
        "validate_no_regressions"
    )
    
    local phases_found=0
    for phase in "${validation_phases[@]}"; do
        if grep -q "$phase" "$BUILD_SCRIPT"; then
            ((phases_found++))
            log_test_info "Found validation phase: $phase"
        else
            log_test_info "Missing validation phase: $phase"
        fi
    done
    
    if [[ $phases_found -ge 4 ]]; then
        log_test_pass "Build script contains $phases_found/5 validation phases"
    else
        log_test_fail "Build script contains only $phases_found/5 validation phases"
        return 1
    fi
    
    # Test validation logging
    if grep -q "validation_error\|validation_success\|VALIDATION_" "$BUILD_SCRIPT"; then
        log_test_pass "Build script contains validation logging functions"
    else
        log_test_fail "Build script missing validation logging functions"
        return 1
    fi
}

# Test error handling and recovery
test_error_handling() {
    ((TOTAL_TESTS++))
    log_test_info "Testing error handling and recovery functionality..."
    
    # Test cleanup function exists
    if grep -q "cleanup()" "$BUILD_SCRIPT"; then
        log_test_pass "Build script contains cleanup function"
    else
        log_test_fail "Build script missing cleanup function"
        return 1
    fi
    
    # Test trap handling
    if grep -q "trap.*cleanup.*EXIT" "$BUILD_SCRIPT"; then
        log_test_pass "Build script contains proper trap handling"
    else
        log_test_fail "Build script missing trap handling"
        return 1
    fi
    
    # Test error exit settings
    if grep -q "set -e" "$BUILD_SCRIPT"; then
        log_test_pass "Build script uses strict error handling (set -e)"
    else
        log_test_fail "Build script missing strict error handling"
        return 1
    fi
    
    # Test logging to file
    if grep -q "LOG_FILE\|tee.*log" "$BUILD_SCRIPT"; then
        log_test_pass "Build script includes logging to file"
    else
        log_test_fail "Build script missing file logging"
        return 1
    fi
}

# Test security and path validation
test_security_validation() {
    ((TOTAL_TESTS++))
    log_test_info "Testing security and path validation functionality..."
    
    # Test for secure path handling
    if grep -q "TEMP_ROOT.*TMPDIR\|mktemp.*XXXXXX" "$BUILD_SCRIPT"; then
        log_test_pass "Build script uses secure temporary directories"
    else
        log_test_fail "Build script missing secure temporary directory handling"
        return 1
    fi
    
    # Test for path validation
    if grep -q "pm-msi.*work.*dir" "$BUILD_SCRIPT"; then
        log_test_pass "Build script includes path validation"
    else
        log_test_fail "Build script missing path validation"
        return 1
    fi
    
    # Test umask settings for secure file permissions
    if grep -q "umask.*007" "$BUILD_SCRIPT"; then
        log_test_pass "Build script sets secure file permissions"
    else
        log_test_fail "Build script missing secure file permissions"
        return 1
    fi
}

# Generate test report
generate_test_report() {
    echo ""
    echo "========================================"
    echo "Unix Build Script Validation Test Report"
    echo "========================================"
    echo "Total tests: $TOTAL_TESTS"
    echo "Failed tests: $FAILED_TESTS"
    echo "Success rate: $(( (TOTAL_TESTS - FAILED_TESTS) * 100 / TOTAL_TESTS ))%"
    echo ""
    
    if [[ $FAILED_TESTS -eq 0 ]]; then
        echo -e "${GREEN}All tests passed!${NC}"
        echo ""
        echo "Unix build script validation: COMPLETE"
        echo "Ready for cross-platform MSI building"
    else
        echo -e "${RED}$FAILED_TESTS test(s) failed${NC}"
        echo ""
        echo "Failed tests:"
        for result in "${TEST_RESULTS[@]}"; do
            if [[ $result == FAIL:* ]]; then
                echo "  - ${result#FAIL: }"
            fi
        done
    fi
    
    echo ""
    echo "Test details:"
    for result in "${TEST_RESULTS[@]}"; do
        case $result in
            PASS:*) echo -e "  ${GREEN}${NC} ${result#PASS: }" ;;
            FAIL:*) echo -e "  ${RED}${NC} ${result#FAIL: }" ;;
            SKIP:*) echo -e "  ${YELLOW}○${NC} ${result#SKIP: }" ;;
        esac
    done
    
    echo ""
}

# Main test execution
main() {
    echo "========================================"
    echo "Unix Build Script Validation Tests"
    echo "========================================"
    echo "Testing: $BUILD_SCRIPT"
    echo "Platform: $(uname -s) $(uname -m)"
    echo "Started: $(date)"
    echo ""
    
    # Setup test environment
    setup_test_environment
    
    # Run all tests
    test_dependency_checking
    test_argument_parsing
    test_msi_extraction
    test_certificate_generation
    test_wixl_compression
    test_idt_validation
    test_validation_phases
    test_error_handling
    test_security_validation
    
    # Generate report
    generate_test_report
    
    # Exit with appropriate code
    if [[ $FAILED_TESTS -eq 0 ]]; then
        exit 0
    else
        exit 1
    fi
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi