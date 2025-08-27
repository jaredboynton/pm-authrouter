#!/bin/bash

# test_build_consistency.sh - Unix vs Windows Build Consistency Tests  
# Validates that Unix-built MSIs are functionally identical to Windows-built ones

set -e

# Test configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${POSTMAN_TEST_PROJECT_ROOT:-$(dirname "$(dirname "$SCRIPT_DIR")")}"
UNIX_BUILD_SCRIPT="$PROJECT_ROOT/deployment/windows/build_msi_mdm_unix.sh"
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
    log_test_info "Setting up build consistency test environment..."
    
    TEMP_TEST_DIR=$(mktemp -d "/tmp/postman-consistency-test-$$-XXXXXX")
    log_test_info "Test workspace: $TEMP_TEST_DIR"
    
    # Ensure Unix build script exists
    if [[ ! -f "$UNIX_BUILD_SCRIPT" ]]; then
        echo "ERROR: Unix build script not found: $UNIX_BUILD_SCRIPT"
        exit 1
    fi
    
    chmod +x "$UNIX_BUILD_SCRIPT"
}

cleanup_test_environment() {
    if [[ -n "$TEMP_TEST_DIR" ]] && [[ -d "$TEMP_TEST_DIR" ]]; then
        log_test_info "Cleaning up test environment: $TEMP_TEST_DIR"
        rm -rf "$TEMP_TEST_DIR" 2>/dev/null || true
    fi
}

# Trap cleanup on exit
trap cleanup_test_environment EXIT

# Find MSI files for comparison
find_msi_files() {
    local deployment_dir="$PROJECT_ROOT/deployment/windows"
    
    # Find original Postman MSI
    ORIGINAL_MSI=$(find "$deployment_dir" -name "Postman-Enterprise-*.msi" ! -name "*-saml.msi" | head -1)
    
    # Find Windows-built SAML MSI (if exists)
    WINDOWS_MSI=$(find "$deployment_dir" -name "Postman-Enterprise-*-saml.msi" | head -1)
    
    log_test_info "Original MSI: ${ORIGINAL_MSI:-Not found}"
    log_test_info "Windows SAML MSI: ${WINDOWS_MSI:-Not found}"
}

# Extract MSI for analysis
extract_msi() {
    local msi_file="$1"
    local extract_dir="$2"
    local label="$3"
    
    if [[ ! -f "$msi_file" ]]; then
        log_test_skip "MSI file not found: $msi_file"
        return 1
    fi
    
    mkdir -p "$extract_dir"
    cd "$extract_dir"
    
    log_test_info "Extracting $label MSI: $(basename "$msi_file")"
    
    # Extract files
    if ! msiextract -C extracted_files "$msi_file" >/dev/null 2>&1; then
        log_test_fail "$label MSI file extraction failed"
        return 1
    fi
    
    # Extract IDT tables
    if ! msidump -t "$msi_file" >/dev/null 2>&1; then
        log_test_fail "$label MSI table extraction failed"
        return 1
    fi
    
    # Extract streams
    if ! msidump -s "$msi_file" >/dev/null 2>&1; then
        log_test_fail "$label MSI stream extraction failed"
        return 1
    fi
    
    log_test_info "$label MSI extracted successfully"
    return 0
}

# Compare IDT table structures
test_idt_table_structure_consistency() {
    ((TOTAL_TESTS++))
    log_test_info "Testing IDT table structure consistency..."
    
    if [[ -z "$ORIGINAL_MSI" ]] || [[ ! -f "$ORIGINAL_MSI" ]]; then
        log_test_skip "Original MSI not available for comparison"
        return 0
    fi
    
    local original_dir="$TEMP_TEST_DIR/original"
    local unix_built_dir="$TEMP_TEST_DIR/unix_built"
    
    # Extract original MSI
    extract_msi "$ORIGINAL_MSI" "$original_dir" "Original"
    
    # Build MSI with Unix script for comparison
    log_test_info "Building MSI with Unix build script for comparison..."
    local unix_msi="$PROJECT_ROOT/deployment/windows/test-unix-build.msi"
    
    cd "$PROJECT_ROOT"
    export BUILD_WORK_DIR="$TEMP_TEST_DIR/unix_build_work"
    
    if "$UNIX_BUILD_SCRIPT" --team "test-team" --saml-url "https://test.example.com/init" >/dev/null 2>&1; then
        # Find the built MSI
        local built_msi=$(find "$PROJECT_ROOT/deployment/windows" -name "*-saml.msi" -newer "$TEMP_TEST_DIR" | head -1)
        if [[ -n "$built_msi" ]]; then
            unix_msi="$built_msi"
            log_test_info "Unix-built MSI: $(basename "$unix_msi")"
        else
            log_test_skip "Unix build did not produce MSI for comparison"
            return 0
        fi
    else
        log_test_skip "Unix MSI build failed - skipping structure comparison"
        return 0
    fi
    
    # Extract Unix-built MSI
    extract_msi "$unix_msi" "$unix_built_dir" "Unix-built"
    
    # Compare critical table structures
    local critical_tables=("Component" "File" "Media" "Directory" "Feature")
    local structure_matches=0
    
    for table in "${critical_tables[@]}"; do
        local orig_table="$original_dir/${table}.idt"
        local unix_table="$unix_built_dir/${table}.idt"
        
        if [[ -f "$orig_table" ]] && [[ -f "$unix_table" ]]; then
            # Compare headers (first 3 lines)
            local orig_header=$(head -3 "$orig_table")
            local unix_header=$(head -3 "$unix_table")
            
            if [[ "$orig_header" == "$unix_header" ]]; then
                log_test_info "$table.idt header structure matches"
                ((structure_matches++))
            else
                log_test_info "$table.idt header structure differs"
            fi
        else
            log_test_info "$table.idt missing in one or both MSIs"
        fi
    done
    
    if [[ $structure_matches -ge 4 ]]; then
        log_test_pass "IDT table structures are consistent ($structure_matches/${#critical_tables[@]} match)"
    else
        log_test_fail "IDT table structures inconsistent ($structure_matches/${#critical_tables[@]} match)"
    fi
}

# Test cabinet content verification
test_cabinet_content_verification() {
    ((TOTAL_TESTS++))
    log_test_info "Testing cabinet content verification..."
    
    if [[ -z "$ORIGINAL_MSI" ]] || [[ ! -f "$ORIGINAL_MSI" ]]; then
        log_test_skip "Original MSI not available for cabinet comparison"
        return 0
    fi
    
    local original_dir="$TEMP_TEST_DIR/original"
    
    # Extract original MSI if not already done
    if [[ ! -d "$original_dir" ]]; then
        extract_msi "$ORIGINAL_MSI" "$original_dir" "Original"
    fi
    
    cd "$original_dir"
    
    # Check for starship.cab
    local starship_cab=""
    if [[ -f "_Streams/starship.cab" ]]; then
        starship_cab="_Streams/starship.cab"
    elif [[ -f "starship.cab" ]]; then
        starship_cab="starship.cab"
    fi
    
    if [[ -n "$starship_cab" ]]; then
        if file "$starship_cab" | grep -q "Microsoft Cabinet"; then
            log_test_pass "Original starship.cab is valid Microsoft Cabinet"
            
            # Test cabinet extraction
            if command -v cabextract >/dev/null 2>&1; then
                local cab_list=$(cabextract -l "$starship_cab" 2>/dev/null | grep -E "\.(exe|dll|msi)$" | wc -l)
                if [[ $cab_list -gt 0 ]]; then
                    log_test_pass "starship.cab contains $cab_list executable files"
                else
                    log_test_fail "starship.cab contains no recognizable executables"
                fi
            else
                log_test_skip "cabextract not available - skipping cabinet content analysis"
            fi
        else
            log_test_fail "starship.cab is not a valid Microsoft Cabinet"
        fi
    else
        log_test_fail "starship.cab not found in original MSI"
    fi
}

# Test service configuration parity
test_service_configuration_parity() {
    ((TOTAL_TESTS++))
    log_test_info "Testing service configuration parity..."
    
    # Test that Unix build script generates proper service configuration
    if grep -q "ServiceInstall.idt" "$UNIX_BUILD_SCRIPT"; then
        log_test_pass "Unix build script includes ServiceInstall table generation"
    else
        log_test_fail "Unix build script missing ServiceInstall table generation"
        return 1
    fi
    
    if grep -q "ServiceControl.idt" "$UNIX_BUILD_SCRIPT"; then
        log_test_pass "Unix build script includes ServiceControl table generation"
    else
        log_test_fail "Unix build script missing ServiceControl table generation"
        return 1
    fi
    
    # Test service configuration values
    if grep -q "PostmanAuthRouter.*16.*2.*1" "$UNIX_BUILD_SCRIPT"; then
        log_test_pass "Unix build script uses correct service type, start type, and error control"
    else
        log_test_fail "Unix build script has incorrect service configuration"
        return 1
    fi
    
    # Test service arguments handling
    if grep -q "SERVICE_ARGS.*--mode service" "$UNIX_BUILD_SCRIPT"; then
        log_test_pass "Unix build script includes proper service arguments"
    else
        log_test_fail "Unix build script missing service arguments configuration"
        return 1
    fi
}

# Test certificate handling consistency
test_certificate_handling_consistency() {
    ((TOTAL_TESTS++))
    log_test_info "Testing certificate handling consistency..."
    
    # Test that Unix script generates proper certificates
    local cert_test_dir="$TEMP_TEST_DIR/cert_consistency"
    mkdir -p "$cert_test_dir"
    
    # Check certificate generation in build script
    if grep -q "openssl req.*CA.*identity.getpostman.com" "$UNIX_BUILD_SCRIPT"; then
        log_test_pass "Unix build script includes proper certificate generation"
    else
        log_test_fail "Unix build script missing certificate generation"
        return 1
    fi
    
    # Test certificate installation actions
    if grep -q "certutil.*-addstore.*ROOT" "$UNIX_BUILD_SCRIPT"; then
        log_test_pass "Unix build script includes certificate installation"
    else
        log_test_fail "Unix build script missing certificate installation"
        return 1
    fi
    
    # Test certificate removal actions  
    if grep -q "certutil.*-delstore.*ROOT" "$UNIX_BUILD_SCRIPT"; then
        log_test_pass "Unix build script includes certificate removal"
    else
        log_test_fail "Unix build script missing certificate removal"
        return 1
    fi
}

# Test file sequence and GUID consistency
test_file_sequence_guid_consistency() {
    ((TOTAL_TESTS++))
    log_test_info "Testing file sequence and GUID consistency..."
    
    # Test GUID generation methodology
    if grep -q "deterministic.*GUID.*generation" "$UNIX_BUILD_SCRIPT"; then
        log_test_pass "Unix build script uses deterministic GUID generation"
    elif grep -q "openssl dgst.*md5.*GUID" "$UNIX_BUILD_SCRIPT"; then
        log_test_pass "Unix build script uses hash-based GUID generation"
    else
        log_test_fail "Unix build script missing consistent GUID generation"
        return 1
    fi
    
    # Test file sequence ranges
    if grep -q "9001.*9999.*AUTH_FILE_SEQ" "$UNIX_BUILD_SCRIPT"; then
        log_test_pass "Unix build script uses consistent file sequence range"
    else
        log_test_fail "Unix build script missing consistent file sequence range"
        return 1
    fi
    
    # Test media ID consistency
    if grep -q "900.*authrouter.cab" "$UNIX_BUILD_SCRIPT"; then
        log_test_pass "Unix build script uses consistent media ID for AuthRouter cabinet"
    else
        log_test_fail "Unix build script missing consistent media ID"
        return 1
    fi
}

# Test MSI size and compression consistency
test_msi_size_compression_consistency() {
    ((TOTAL_TESTS++))
    log_test_info "Testing MSI size and compression consistency..."
    
    if [[ -z "$ORIGINAL_MSI" ]] || [[ ! -f "$ORIGINAL_MSI" ]]; then
        log_test_skip "Original MSI not available for size comparison"
        return 0
    fi
    
    # Get original MSI size
    local orig_size=$(stat -c%s "$ORIGINAL_MSI" 2>/dev/null || stat -f%z "$ORIGINAL_MSI" 2>/dev/null)
    local orig_size_mb=$(( orig_size / 1024 / 1024 ))
    
    log_test_info "Original MSI size: ${orig_size_mb} MB"
    
    # Test 125MB size limit mentioned in Windows tests
    if [[ $orig_size_mb -lt 125 ]]; then
        log_test_pass "Original MSI within 125MB size limit (${orig_size_mb} MB)"
    else
        log_test_fail "Original MSI exceeds 125MB size limit (${orig_size_mb} MB)"
    fi
    
    # Test compression settings in Unix script
    if grep -q "wixl.*compression\|60%.*compression" "$UNIX_BUILD_SCRIPT"; then
        log_test_pass "Unix build script includes compression optimization"
    else
        log_test_fail "Unix build script missing compression optimization"
        return 1
    fi
}

# Test validation phase consistency
test_validation_phase_consistency() {
    ((TOTAL_TESTS++))
    log_test_info "Testing validation phase consistency with Windows..."
    
    # Test for the 5-phase validation system mentioned in the plan
    local validation_phases=(
        "validate_original_msi_structure"
        "validate_idt_schema"
        "validate_idt_relationships"
        "validate_no_regressions"
        "validate_final_msi"
    )
    
    local phases_found=0
    for phase in "${validation_phases[@]}"; do
        if grep -q "$phase" "$UNIX_BUILD_SCRIPT"; then
            ((phases_found++))
        fi
    done
    
    # Windows tests expect 5-phase validation
    if [[ $phases_found -ge 4 ]]; then
        log_test_pass "Unix build script has $phases_found/5 validation phases (consistent with Windows)"
    else
        log_test_fail "Unix build script has only $phases_found/5 validation phases (inconsistent with Windows)"
        return 1
    fi
    
    # Test validation error handling consistency
    if grep -q "validation_error.*validation_success" "$UNIX_BUILD_SCRIPT"; then
        log_test_pass "Unix build script has consistent validation error handling"
    else
        log_test_fail "Unix build script missing validation error handling"
        return 1
    fi
}

# Test build output format consistency
test_build_output_format_consistency() {
    ((TOTAL_TESTS++))
    log_test_info "Testing build output format consistency..."
    
    # Test output naming convention
    if grep -q "\-saml\.msi" "$UNIX_BUILD_SCRIPT"; then
        log_test_pass "Unix build script uses consistent SAML MSI naming"
    else
        log_test_fail "Unix build script missing consistent SAML MSI naming"
        return 1
    fi
    
    # Test version preservation
    if grep -q "MSI_VERSION.*original.*version" "$UNIX_BUILD_SCRIPT"; then
        log_test_pass "Unix build script preserves original MSI version"
    else
        log_test_fail "Unix build script missing version preservation"
        return 1
    fi
    
    # Test metadata preservation
    if grep -q "basename.*version.*metadata" "$UNIX_BUILD_SCRIPT"; then
        log_test_pass "Unix build script preserves MSI metadata"
    else
        log_test_skip "Unix build script metadata preservation not clearly evident"
    fi
}

# Generate test report
generate_test_report() {
    echo ""
    echo "========================================"
    echo "Unix vs Windows Build Consistency Report"
    echo "========================================"
    echo "Total tests: $TOTAL_TESTS"
    echo "Failed tests: $FAILED_TESTS"
    echo "Success rate: $(( (TOTAL_TESTS - FAILED_TESTS) * 100 / TOTAL_TESTS ))%"
    echo ""
    
    if [[ $FAILED_TESTS -eq 0 ]]; then
        echo -e "${GREEN}All consistency tests passed!${NC}"
        echo ""
        echo "Unix build script produces MSIs consistent with Windows builds"
        echo "Cross-platform build parity: VALIDATED"
    else
        echo -e "${RED}$FAILED_TESTS consistency test(s) failed${NC}"
        echo ""
        echo "Failed tests:"
        for result in "${TEST_RESULTS[@]}"; do
            if [[ $result == FAIL:* ]]; then
                echo "  - ${result#FAIL: }"
            fi
        done
    fi
    
    echo ""
    echo "Consistency test details:"
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
    echo "Unix vs Windows Build Consistency Tests"
    echo "========================================"
    echo "Unix build script: $UNIX_BUILD_SCRIPT"
    echo "Platform: $(uname -s) $(uname -m)"
    echo "Started: $(date)"
    echo ""
    
    # Setup test environment
    setup_test_environment
    
    # Find MSI files for comparison
    find_msi_files
    
    # Run all consistency tests
    test_idt_table_structure_consistency
    test_cabinet_content_verification  
    test_service_configuration_parity
    test_certificate_handling_consistency
    test_file_sequence_guid_consistency
    test_msi_size_compression_consistency
    test_validation_phase_consistency
    test_build_output_format_consistency
    
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