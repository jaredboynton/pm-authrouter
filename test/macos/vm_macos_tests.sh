#!/bin/bash

# vm_macos_tests.sh - VM-based macOS testing automation
# Runs comprehensive pre-release validation in clean VM environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VM_NAME="macOS-TestVM"
CLEAN_SNAPSHOT="clean-state"
SHARED_FOLDER="/tmp/postman-test-$$"
VM_TEST_PATH="/tmp/postman_test_suite"
VM_USER="testuser"

# Test results
TOTAL_FAILURES=0
TEST_RESULTS_FILE="$SCRIPT_DIR/test_results_vm_macos.txt"

# Helper functions
log_info() {
    echo -e "${BLUE}[VM-INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[VM-SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[VM-WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[VM-ERROR]${NC} $1"
}

log_separator() {
    echo "========================================"
}

# Check if Parallels is available
check_parallels() {
    log_info "Checking Parallels Desktop availability..."
    
    if ! command -v prlctl &> /dev/null; then
        log_error "Parallels Desktop (prlctl) not found"
        log_info "Install Parallels Desktop or use alternative VM solution"
        exit 1
    fi
    
    log_success "Parallels Desktop found"
}

# Check VM exists
check_vm_exists() {
    log_info "Checking VM '$VM_NAME' exists..."
    
    if ! prlctl list --all | grep -q "$VM_NAME"; then
        log_error "VM '$VM_NAME' not found"
        log_info "Create a macOS VM named '$VM_NAME' first"
        log_info "VM should have:"
        log_info "  - Clean macOS installation"
        log_info "  - Apple Developer certificates installed"
        log_info "  - Network access for SAML testing"
        log_info "  - User account: '$VM_USER'"
        exit 1
    fi
    
    log_success "VM '$VM_NAME' found"
}

# Create clean state snapshot if it doesn't exist
create_clean_snapshot() {
    log_info "Checking clean state snapshot..."
    
    if prlctl snapshot-list "$VM_NAME" 2>/dev/null | grep -q "$CLEAN_SNAPSHOT"; then
        log_success "Clean state snapshot '$CLEAN_SNAPSHOT' exists"
    else
        log_info "Creating clean state snapshot..."
        log_warning "Ensure VM is in clean state before continuing"
        read -p "Press Enter to create snapshot of current VM state..."
        
        if prlctl snapshot "$VM_NAME" --name "$CLEAN_SNAPSHOT" --description "Clean state for testing"; then
            log_success "Clean state snapshot created"
        else
            log_error "Failed to create snapshot"
            exit 1
        fi
    fi
}

# Start VM and wait for it to be ready
start_vm() {
    log_info "Starting VM '$VM_NAME'..."
    
    local vm_status=$(prlctl list "$VM_NAME" | tail -1 | awk '{print $4}')
    
    if [[ "$vm_status" == "running" ]]; then
        log_success "VM already running"
    else
        prlctl start "$VM_NAME"
        log_info "Waiting for VM to boot..."
        
        # Wait for VM to be accessible
        local attempts=0
        while ! prlctl exec "$VM_NAME" whoami &>/dev/null && [ $attempts -lt 60 ]; do
            sleep 5
            ((attempts++))
            echo -n "."
        done
        echo
        
        if [ $attempts -eq 60 ]; then
            log_error "VM failed to become accessible"
            exit 1
        fi
        
        log_success "VM is ready"
    fi
}

# Stop VM
stop_vm() {
    log_info "Stopping VM '$VM_NAME'..."
    
    local vm_status=$(prlctl list "$VM_NAME" | tail -1 | awk '{print $4}')
    
    if [[ "$vm_status" == "running" ]]; then
        prlctl stop "$VM_NAME"
        log_success "VM stopped"
    else
        log_info "VM already stopped"
    fi
}

# Restore VM to clean state
restore_clean_state() {
    log_info "Restoring VM to clean state..."
    
    stop_vm
    
    if prlctl snapshot-switch "$VM_NAME" --id "$CLEAN_SNAPSHOT"; then
        log_success "VM restored to clean state"
    else
        log_error "Failed to restore clean state"
        exit 1
    fi
}

# Prepare shared folder with test files
prepare_test_files() {
    log_info "Preparing test files in shared folder..."
    
    # Create shared folder
    mkdir -p "$SHARED_FOLDER"
    
    # Copy entire test directory
    cp -r "$SCRIPT_DIR"/* "$SHARED_FOLDER/"
    
    # Copy deployment scripts
    cp -r "$PROJECT_ROOT/deployment" "$SHARED_FOLDER/"
    
    # Copy source code for building
    cp -r "$PROJECT_ROOT/cmd" "$SHARED_FOLDER/"
    cp -r "$PROJECT_ROOT/internal" "$SHARED_FOLDER/"
    cp "$PROJECT_ROOT/go.mod" "$SHARED_FOLDER/"
    cp "$PROJECT_ROOT/go.sum" "$SHARED_FOLDER/" 2>/dev/null || true
    
    # Copy any existing build artifacts
    log_info "Copying build artifacts if present..."
    if ls "$PROJECT_ROOT"/deployment/macos/*.pkg 2>/dev/null; then
        cp "$PROJECT_ROOT"/deployment/macos/*.pkg "$SHARED_FOLDER/deployment/macos/" 2>/dev/null || true
        log_success "Copied PKG files"
    fi
    
    if ls "$PROJECT_ROOT"/deployment/macos/*.mobileconfig 2>/dev/null; then
        cp "$PROJECT_ROOT"/deployment/macos/*.mobileconfig "$SHARED_FOLDER/deployment/macos/" 2>/dev/null || true
        log_success "Copied MDM profiles"
    fi
    
    # Copy built binaries if present
    if [ -f "$PROJECT_ROOT/cmd/pm-authrouter/pm-authrouter" ]; then
        mkdir -p "$SHARED_FOLDER/cmd/pm-authrouter"
        cp "$PROJECT_ROOT/cmd/pm-authrouter/pm-authrouter" "$SHARED_FOLDER/cmd/pm-authrouter/"
        log_success "Copied pm-authrouter binary"
    fi
    
    log_success "Test files prepared in $SHARED_FOLDER"
}

# Copy test files to VM
copy_files_to_vm() {
    log_info "Copying test files to VM..."
    
    # Create test directory in VM
    prlctl exec "$VM_NAME" mkdir -p "$VM_TEST_PATH"
    
    # Copy files using tar to preserve permissions
    tar -C "$SHARED_FOLDER" -cf - . | prlctl exec "$VM_NAME" tar -C "$VM_TEST_PATH" -xf -
    
    # Make scripts executable
    prlctl exec "$VM_NAME" find "$VM_TEST_PATH" -name "*.sh" -exec chmod +x {} \;
    
    log_success "Files copied to VM"
}

# Run specific test suite in VM
run_vm_test_suite() {
    local suite_name="$1"
    local test_script="$2"
    
    log_separator
    log_info "Running $suite_name in VM"
    log_separator
    
    # Run test in VM and capture output
    local vm_output_file="$SHARED_FOLDER/vm_output_${suite_name,,}.txt"
    
    if prlctl exec "$VM_NAME" bash -c "cd $VM_TEST_PATH && ./$test_script" > "$vm_output_file" 2>&1; then
        log_success "$suite_name completed successfully"
        
        # Show summary of output
        echo "=== $suite_name Output ==="
        tail -20 "$vm_output_file"
        echo
        
        return 0
    else
        log_error "$suite_name failed"
        
        # Show error output
        echo "=== $suite_name Error Output ==="
        tail -50 "$vm_output_file"
        echo
        
        ((TOTAL_FAILURES++))
        return 1
    fi
}

# Collect test results from VM
collect_results() {
    log_info "Collecting test results from VM..."
    
    # Copy result files back
    prlctl exec "$VM_NAME" bash -c "find $VM_TEST_PATH -name 'test_results_*.txt' -exec cp {} /tmp/ \;" 2>/dev/null || true
    
    # Collect the results
    for result_file in /tmp/test_results_*.txt; do
        if [ -f "$result_file" ]; then
            local basename=$(basename "$result_file")
            prlctl exec "$VM_NAME" cat "/tmp/$basename" >> "$TEST_RESULTS_FILE" 2>/dev/null || true
        fi
    done
    
    log_success "Results collected"
}

# Cleanup shared resources
cleanup() {
    log_info "Cleaning up shared resources..."
    
    # Remove shared folder
    rm -rf "$SHARED_FOLDER"
    
    # Clean up VM temp files
    prlctl exec "$VM_NAME" rm -rf "$VM_TEST_PATH" /tmp/test_results_*.txt 2>/dev/null || true
    
    log_success "Cleanup completed"
}

# Parse command line arguments
parse_arguments() {
    local run_specific=""
    local restore_only=false
    local show_help=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --build)
                run_specific="build"
                shift
                ;;
            --daemon)
                run_specific="daemon"
                shift
                ;;
            --integration)
                run_specific="integration"
                shift
                ;;
            --restore-clean)
                restore_only=true
                shift
                ;;
            --vm-name)
                VM_NAME="$2"
                shift 2
                ;;
            --help|-h)
                show_help=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_help=true
                shift
                ;;
        esac
    done
    
    if $show_help; then
        echo "Usage: $0 [OPTIONS]"
        echo ""
        echo "Run macOS test suites in clean VM environment"
        echo ""
        echo "Options:"
        echo "  --build        Run only build script tests"
        echo "  --daemon       Run only daemon functional tests"
        echo "  --integration  Run only integration tests"
        echo "  --restore-clean Restore VM to clean state only"
        echo "  --vm-name NAME Use specific VM name (default: $VM_NAME)"
        echo "  --help, -h     Show this help message"
        echo ""
        echo "VM Requirements:"
        echo "  - Parallels Desktop with macOS VM named '$VM_NAME'"
        echo "  - VM should have clean macOS with developer certificates"
        echo "  - User account '$VM_USER' with sudo privileges"
        echo "  - Network access for SAML endpoint testing"
        echo ""
        exit 0
    fi
    
    if $restore_only; then
        echo "restore-only"
    else
        echo "$run_specific"
    fi
}

# Generate summary report
generate_summary() {
    log_separator
    echo -e "${YELLOW}VM Test Summary${NC}"
    log_separator
    
    if [ "$TOTAL_FAILURES" -eq 0 ]; then
        log_success "All VM test suites passed!"
        log_info "System is ready for release deployment"
    else
        log_error "Test suites failed: $TOTAL_FAILURES"
        log_warning "Review failures before release"
    fi
    
    # Show result files
    if [ -f "$TEST_RESULTS_FILE" ]; then
        echo ""
        log_info "Detailed results in: $TEST_RESULTS_FILE"
    fi
}

# Main test runner
main() {
    echo "========================================"
    echo "VM-Based macOS Test Suite Runner"
    echo "========================================"
    echo "Started: $(date)"
    echo "VM: $VM_NAME"
    echo ""
    
    # Initialize results file
    echo "" > "$TEST_RESULTS_FILE"
    echo "VM macOS Test Results - $(date)" >> "$TEST_RESULTS_FILE"
    echo "=========================================" >> "$TEST_RESULTS_FILE"
    
    # Parse command line
    local run_mode
    run_mode=$(parse_arguments "$@")
    
    # Set cleanup trap
    trap cleanup EXIT
    
    # Check prerequisites
    check_parallels
    check_vm_exists
    create_clean_snapshot
    
    # Handle restore-only mode
    if [ "$run_mode" = "restore-only" ]; then
        restore_clean_state
        log_success "VM restored to clean state"
        exit 0
    fi
    
    # Prepare test environment
    restore_clean_state
    start_vm
    prepare_test_files
    copy_files_to_vm
    
    # Run test suites
    if [ -n "$run_mode" ]; then
        log_info "Running specific test suite: $run_mode"
        case "$run_mode" in
            build)
                run_vm_test_suite "Build Tests" "test_macos_build.sh"
                run_vm_test_suite "Build Output Tests" "test_build_outputs.sh"
                ;;
            daemon)
                run_vm_test_suite "Daemon Tests" "test_macos_daemon.sh"
                ;;
            integration)
                run_vm_test_suite "Integration Tests" "test_macos_integration.sh"
                ;;
        esac
    else
        log_info "Running all test suites"
        
        # Run all test suites in sequence
        run_vm_test_suite "Build Tests" "test_macos_build.sh"
        run_vm_test_suite "Build Output Tests" "test_build_outputs.sh"
        run_vm_test_suite "Daemon Tests" "test_macos_daemon.sh"
        run_vm_test_suite "Integration Tests" "test_macos_integration.sh"
    fi
    
    # Collect results
    collect_results
    
    # Generate summary
    generate_summary
    
    # Restore clean state for next run
    restore_clean_state
    
    # Exit with appropriate code
    if [ "$TOTAL_FAILURES" -eq 0 ]; then
        exit 0
    else
        exit 1
    fi
}

# Run if executed directly
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi