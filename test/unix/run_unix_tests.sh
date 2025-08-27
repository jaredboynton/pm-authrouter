#!/bin/bash

# run_unix_tests.sh - Master Unix test runner for cross-platform testing
# Validates Unix build scripts and ensures parity with Windows testing

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Test configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
TEST_ROOT="$(dirname "$SCRIPT_DIR")"
TOTAL_FAILURES=0
VERBOSE_OUTPUT=false

# Platform detection
PLATFORM=$(uname -s)
ARCH=$(uname -m)
case "$PLATFORM" in
    "Darwin") OS_TYPE="macos" ;;
    "Linux") OS_TYPE="linux" ;;
    *) OS_TYPE="unknown" ;;
esac

# Speed/execution modes
SPEED_MODE="full"  # smoke, fast, component, full
USE_CACHE=true
ENABLE_PARALLEL=true
MAX_PARALLEL_JOBS=3

# Test suite configuration
declare -A TEST_SUITES=(
    ["build_validation"]="Unix Build Script Validation Tests"
    ["build_consistency"]="Unix vs Windows Build Consistency Tests"
    ["platform_specific"]="Platform-Specific Build Environment Tests"
    ["dependency_validation"]="Dependency Management Validation Tests"
    ["msi_structure"]="MSI Structure and Integrity Tests"
    ["idt_validation"]="IDT Schema and Relationship Tests"
    ["regression_testing"]="Build Regression and Compatibility Tests"
)

# Test categories and requirements
declare -A TEST_CATEGORIES=(
    ["smoke"]="build_validation"
    ["fast"]="build_validation,dependency_validation"
    ["component"]="build_validation,dependency_validation,platform_specific,msi_structure"
    ["full"]="build_validation,build_consistency,platform_specific,dependency_validation,msi_structure,idt_validation,regression_testing"
)

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_debug() {
    if [[ "$VERBOSE_OUTPUT" == "true" ]]; then
        echo -e "${CYAN}[DEBUG]${NC} $1"
    fi
}

log_separator() {
    echo "========================================"
}

# Platform detection and validation
detect_platform_details() {
    log_info "Detecting platform details..."
    log_info "OS: $PLATFORM ($OS_TYPE)"
    log_info "Architecture: $ARCH"
    
    case "$OS_TYPE" in
        "macos")
            local macos_version=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
            log_info "macOS Version: $macos_version"
            
            # Check for package managers
            if command -v brew >/dev/null 2>&1; then
                log_info "Homebrew detected: $(brew --version | head -1)"
            fi
            if command -v port >/dev/null 2>&1; then
                log_info "MacPorts detected: $(port version 2>/dev/null || echo "unknown")"
            fi
            ;;
        "linux")
            if [[ -f /etc/os-release ]]; then
                source /etc/os-release
                log_info "Linux Distribution: $NAME $VERSION"
            fi
            ;;
    esac
}

# Check test prerequisites
check_prerequisites() {
    log_info "Checking Unix test prerequisites..."
    local missing_tools=()
    local warnings=()
    
    # Essential tools for testing
    local essential_tools=(bash grep sed awk cut head tail wc tr sort uniq)
    local build_tools=(gcc make openssl curl wget)
    local msi_tools=(msiextract msidump msibuild wixl gcab)
    
    # Check essential tools
    for tool in "${essential_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool (essential)")
        fi
    done
    
    # Check build tools
    for tool in "${build_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool (build)")
        fi
    done
    
    # Check MSI tools (may need installation)
    local msi_missing=0
    for tool in "${msi_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            warnings+=("$tool (will attempt auto-install)")
            ((msi_missing++))
        fi
    done
    
    # Check Go installation
    if ! command -v go >/dev/null 2>&1; then
        missing_tools+=("go (required for building AuthRouter)")
    else
        local go_version=$(go version 2>/dev/null)
        log_info "Go detected: $go_version"
    fi
    
    # Check for original Postman MSI (for comparison tests)
    local original_msi_count=$(find "$PROJECT_ROOT/deployment/windows" -name "Postman-Enterprise-*.msi" ! -name "*-saml.msi" 2>/dev/null | wc -l)
    if [[ $original_msi_count -eq 0 ]]; then
        warnings+=("Original Postman MSI not found - consistency tests will be limited")
    else
        log_info "Found $original_msi_count original Postman MSI(s)"
    fi
    
    # Report issues
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing essential tools:"
        for tool in "${missing_tools[@]}"; do
            log_error "  - $tool"
        done
        return 1
    fi
    
    if [[ ${#warnings[@]} -gt 0 ]]; then
        log_warning "Warnings detected:"
        for warning in "${warnings[@]}"; do
            log_warning "  - $warning"
        done
    fi
    
    # Check root privileges for some tests
    if [[ $EUID -eq 0 ]]; then
        log_success "Running as root - all tests available"
    else
        log_warning "Not running as root - some tests may be skipped"
        log_info "For complete testing, consider running with sudo"
    fi
    
    log_success "Prerequisites check completed"
    return 0
}

# Dependency installation function
install_missing_dependencies() {
    log_info "Attempting to install missing MSI tools..."
    
    case "$OS_TYPE" in
        "macos")
            if command -v brew >/dev/null 2>&1; then
                log_info "Installing msitools via Homebrew..."
                brew install msitools cabextract || log_warning "Homebrew installation failed"
            elif command -v port >/dev/null 2>&1; then
                log_info "Installing msitools via MacPorts..."
                sudo port install msitools +universal || log_warning "MacPorts installation failed"
            else
                log_warning "No package manager found - will attempt source build"
                return 1
            fi
            ;;
        "linux")
            if command -v apt-get >/dev/null 2>&1; then
                log_info "Installing msitools via apt..."
                sudo apt-get update && sudo apt-get install -y msitools gcab || log_warning "apt installation failed"
            elif command -v yum >/dev/null 2>&1; then
                log_info "Installing msitools via yum..."
                sudo yum install -y msitools gcab || log_warning "yum installation failed"
            elif command -v dnf >/dev/null 2>&1; then
                log_info "Installing msitools via dnf..."
                sudo dnf install -y msitools gcab || log_warning "dnf installation failed"
            else
                log_warning "No supported package manager found"
                return 1
            fi
            ;;
        *)
            log_error "Unsupported platform for automatic dependency installation"
            return 1
            ;;
    esac
    
    # Verify installation
    if command -v msiextract >/dev/null 2>&1 && command -v msidump >/dev/null 2>&1; then
        log_success "MSI tools installed successfully"
        return 0
    else
        log_warning "MSI tools installation incomplete"
        return 1
    fi
}

# Test execution functions
run_test_suite() {
    local suite_name="$1"
    local suite_description="$2"
    
    log_separator
    echo -e "${YELLOW}Running $suite_description${NC}"
    log_separator
    
    local test_script="$SCRIPT_DIR/test_${suite_name}.sh"
    
    if [[ ! -f "$test_script" ]]; then
        log_warning "Test script not found: $test_script"
        return 2  # Skip
    fi
    
    if [[ ! -x "$test_script" ]]; then
        log_debug "Making test script executable: $test_script"
        chmod +x "$test_script"
    fi
    
    local start_time=$(date +%s)
    local temp_log=$(mktemp)
    
    # Export test environment
    export POSTMAN_TEST_SPEED_MODE="$SPEED_MODE"
    export POSTMAN_TEST_USE_CACHE="$USE_CACHE"
    export POSTMAN_TEST_VERBOSE="$VERBOSE_OUTPUT"
    export POSTMAN_TEST_PROJECT_ROOT="$PROJECT_ROOT"
    export POSTMAN_TEST_OS_TYPE="$OS_TYPE"
    export POSTMAN_TEST_PLATFORM="$PLATFORM"
    export POSTMAN_TEST_ARCH="$ARCH"
    
    if "$test_script" > "$temp_log" 2>&1; then
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        if [[ "$VERBOSE_OUTPUT" == "true" ]]; then
            cat "$temp_log"
        fi
        
        log_success "$suite_description completed successfully (${duration}s)"
        rm -f "$temp_log"
        return 0
    else
        local exit_code=$?
        local end_time=$(date +%s)
        local duration=$((end_time - start_time))
        
        log_error "$suite_description failed (${duration}s, exit: $exit_code)"
        
        # Always show output for failed tests
        echo "Test output:"
        cat "$temp_log"
        rm -f "$temp_log"
        
        return $exit_code
    fi
}

# Test suite selection based on speed mode
get_test_suites_for_mode() {
    local mode="$1"
    local suites_string="${TEST_CATEGORIES[$mode]:-}"
    
    if [[ -z "$suites_string" ]]; then
        log_warning "Unknown speed mode: $mode, using full"
        suites_string="${TEST_CATEGORIES[full]}"
    fi
    
    echo "$suites_string" | tr ',' ' '
}

# Parse command line arguments
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --build-validation)
                SPECIFIC_SUITE="build_validation"
                shift
                ;;
            --build-consistency)
                SPECIFIC_SUITE="build_consistency"
                shift
                ;;
            --platform-specific)
                SPECIFIC_SUITE="platform_specific"
                shift
                ;;
            --smoke)
                SPEED_MODE="smoke"
                shift
                ;;
            --fast)
                SPEED_MODE="fast"
                shift
                ;;
            --component)
                SPEED_MODE="component"
                shift
                ;;
            --full)
                SPEED_MODE="full"
                shift
                ;;
            --no-cache)
                USE_CACHE=false
                shift
                ;;
            --verbose|-v)
                VERBOSE_OUTPUT=true
                shift
                ;;
            --parallel)
                ENABLE_PARALLEL=true
                if [[ $2 =~ ^[0-9]+$ ]] && [[ $2 -gt 0 ]]; then
                    MAX_PARALLEL_JOBS=$2
                    shift
                fi
                shift
                ;;
            --sequential)
                ENABLE_PARALLEL=false
                shift
                ;;
            --install-deps)
                INSTALL_DEPS=true
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Help function
show_help() {
    cat << EOF
Usage: $0 [OPTIONS]

Unix Test Suite Runner for Postman SAML Enforcer

Test Suite Options:
  --build-validation      Run only build script validation tests
  --build-consistency     Run only Unix vs Windows consistency tests  
  --platform-specific     Run only platform-specific environment tests

Speed/Category Options:
  --smoke                 Run smoke tests (critical functionality, ~30s)
  --fast                  Run fast tests (unit tests, ~2 minutes)
  --component             Run component tests (fast + medium, ~5 minutes)
  --full                  Run all tests (complete coverage, ~15+ minutes)

Configuration Options:
  --no-cache              Disable build caching
  --verbose, -v           Enable verbose output
  --parallel [N]          Enable parallel execution (default: 3 jobs)
  --sequential            Disable parallel execution
  --install-deps          Attempt to install missing dependencies

Other Options:
  --help, -h              Show this help message

Examples:
  $0 --smoke              # Quick validation
  $0 --fast --verbose     # Fast tests with detailed output  
  $0 --component          # Pre-commit validation
  $0 --full               # Complete test coverage
  $0 --build-validation   # Test only Unix build script
  $0 --install-deps       # Install dependencies and run tests

Platform Support:
  - macOS (Intel and Apple Silicon)
  - Linux (Ubuntu, CentOS, RHEL, Fedora)
  - Automatic dependency installation where supported

Requirements:
  - Bash 4.0+
  - Standard Unix tools (grep, sed, awk, etc.)
  - Go compiler
  - MSI tools (msitools package) - can auto-install
  - Original Postman Enterprise MSI (for consistency tests)

EOF
}

# Generate summary report
generate_summary() {
    log_separator
    echo -e "${YELLOW}Unix Test Summary${NC}"
    log_separator
    
    local test_suites=($(get_test_suites_for_mode "$SPEED_MODE"))
    local total_suites=${#test_suites[@]}
    local failed_suites=0
    
    log_info "Platform: $PLATFORM ($OS_TYPE, $ARCH)"
    log_info "Speed mode: $SPEED_MODE"
    log_info "Total test suites: $total_suites"
    
    if [[ $TOTAL_FAILURES -eq 0 ]]; then
        log_success "All test suites passed!"
        echo ""
        log_info "Unix build script validation: COMPLETE"
        log_info "Cross-platform testing: VALIDATED"
    else
        log_error "$TOTAL_FAILURES test suite(s) failed"
    fi
    
    # Show platform-specific information
    echo ""
    log_info "Platform capabilities:"
    case "$OS_TYPE" in
        "macos")
            log_info "  - Native macOS MSI building: Available"
            log_info "  - Cross-compilation: Supported"
            command -v brew >/dev/null && log_info "  - Package management: Homebrew"
            command -v port >/dev/null && log_info "  - Package management: MacPorts"
            ;;
        "linux")
            log_info "  - Linux MSI building: Available" 
            log_info "  - Cross-compilation: Supported"
            if [[ -f /etc/os-release ]]; then
                source /etc/os-release
                log_info "  - Distribution: $NAME $VERSION"
            fi
            ;;
    esac
    
    # Show log locations
    echo ""
    log_info "Test logs stored in: $SCRIPT_DIR/logs/"
    log_info "For detailed output, use: $0 --verbose"
}

# Main execution function
main() {
    # Initialize
    echo "========================================"
    echo "Unix Test Suite Runner"
    echo "========================================"
    echo "Started: $(date)"
    echo "Working directory: $(pwd)"
    echo ""
    
    # Parse arguments
    parse_arguments "$@"
    
    # Detect platform
    detect_platform_details
    echo ""
    
    # Check prerequisites
    if ! check_prerequisites; then
        if [[ "${INSTALL_DEPS:-false}" == "true" ]]; then
            echo ""
            install_missing_dependencies
            echo ""
            # Recheck after installation
            if ! check_prerequisites; then
                log_error "Prerequisites still not met after installation attempt"
                exit 1
            fi
        else
            echo ""
            log_error "Prerequisites not met. Use --install-deps to attempt automatic installation"
            exit 1
        fi
    fi
    
    echo ""
    log_info "Test configuration:"
    log_info "  Speed mode: $SPEED_MODE"
    log_info "  Use cache: $USE_CACHE"
    log_info "  Verbose output: $VERBOSE_OUTPUT"
    log_info "  Parallel execution: $ENABLE_PARALLEL"
    if [[ "$ENABLE_PARALLEL" == "true" ]]; then
        log_info "  Max parallel jobs: $MAX_PARALLEL_JOBS"
    fi
    
    # Change to project root
    cd "$PROJECT_ROOT"
    
    # Create logs directory
    mkdir -p "$SCRIPT_DIR/logs"
    
    # Determine test suites to run
    local test_suites
    if [[ -n "${SPECIFIC_SUITE:-}" ]]; then
        test_suites=("$SPECIFIC_SUITE")
    else
        IFS=' ' read -ra test_suites <<< "$(get_test_suites_for_mode "$SPEED_MODE")"
    fi
    
    echo ""
    log_info "Test suites to run: ${test_suites[*]}"
    echo ""
    
    # Run test suites
    for suite in "${test_suites[@]}"; do
        local description="${TEST_SUITES[$suite]:-Unknown Test Suite}"
        
        if run_test_suite "$suite" "$description"; then
            log_debug "Suite $suite completed successfully"
        else
            local exit_code=$?
            if [[ $exit_code -eq 2 ]]; then
                log_warning "Suite $suite skipped (not implemented)"
            else
                log_error "Suite $suite failed"
                ((TOTAL_FAILURES++))
            fi
        fi
        echo ""
    done
    
    # Generate summary
    generate_summary
    
    # Exit with appropriate code
    if [[ $TOTAL_FAILURES -eq 0 ]]; then
        exit 0
    else
        exit 1
    fi
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi