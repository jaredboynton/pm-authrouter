#!/bin/bash

# run_macos_tests.sh - Master test runner for all macOS tests
# Coordinates and runs all macOS test suites

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
CACHE_MANAGER="$SCRIPT_DIR/test_cache.sh"
TOTAL_FAILURES=0

# Speed/execution modes
SPEED_MODE="full"  # smoke, fast, component, full
USE_CACHE=true

# Parallel execution configuration
ENABLE_PARALLEL=true
MAX_PARALLEL_JOBS=3
JOB_TIMEOUT=600  # 10 minutes max per test suite
JOB_DIR="$SCRIPT_DIR/jobs"
JOB_PIDS=()
JOB_NAMES=()
JOB_START_TIMES=()

# Resource isolation configuration
BASE_TEST_PORT=8443  # Start port for auxiliary test services
USE_RESOURCE_ISOLATION=true
PORT_RANGE_SIZE=10  # Each job gets 10 ports for auxiliary services
LOG_SEGREGATION=true
PORT_443_LOCK_FILE="$SCRIPT_DIR/.port443.lock"  # Mutex for port 443

# Test suite configuration
# Using regular arrays since -A not available in all bash versions
TEST_SUITES_build="Build Script Tests"
TEST_SUITES_daemon="Daemon Functional Tests"
TEST_SUITES_integration="Integration Tests"
TEST_SUITES_browser="Browser Session Tests"
TEST_SUITES_dns="DNS Interception Tests"
TEST_SUITES_cleanup="Cleanup Manager Tests"
TEST_SUITES_privilege="Privilege Escalation Tests"
TEST_SUITES_cache="Cache System Tests"
TEST_SUITES_download="Download Robustness Tests"

# Test suite resource requirements
TEST_SUITES_build_resources="cpu:low,disk:low,network:none,ports:none,requires_root:no"
TEST_SUITES_daemon_resources="cpu:medium,disk:low,network:low,ports:443,requires_root:yes"
TEST_SUITES_integration_resources="cpu:high,disk:medium,network:high,ports:443,requires_root:yes"
TEST_SUITES_browser_resources="cpu:low,disk:low,network:none,ports:none,requires_root:no"
TEST_SUITES_dns_resources="cpu:low,disk:low,network:low,ports:none,requires_root:partial"
TEST_SUITES_cleanup_resources="cpu:low,disk:low,network:none,ports:none,requires_root:partial"
TEST_SUITES_privilege_resources="cpu:low,disk:low,network:none,ports:none,requires_root:partial"
TEST_SUITES_cache_resources="cpu:low,disk:low,network:none,ports:none,requires_root:no"
TEST_SUITES_download_resources="cpu:low,disk:high,network:high,ports:none,requires_root:no"

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

log_separator() {
    echo "========================================"
}

# Initialize cache system
init_cache_system() {
    if $USE_CACHE; then
        log_info "Initializing artifact cache system..."
        "$CACHE_MANAGER" init
        
        # Show cache stats if available
        if "$CACHE_MANAGER" stats >/dev/null 2>&1; then
            log_info "Cache system ready"
        fi
    else
        log_info "Cache system disabled"
    fi
}

# Initialize parallel execution system
init_parallel_system() {
    if $ENABLE_PARALLEL; then
        log_info "Initializing parallel execution system..."
        
        # Create job directory
        mkdir -p "$JOB_DIR"
        
        # Clean up any old job files
        rm -f "$JOB_DIR"/*.pid "$JOB_DIR"/*.log "$JOB_DIR"/*.result 2>/dev/null || true
        
        log_info "Parallel execution: enabled (max jobs: $MAX_PARALLEL_JOBS)"
    else
        log_info "Parallel execution: disabled (sequential mode)"
    fi
}

# Acquire port 443 lock for tests that need it
acquire_port_443_lock() {
    local suite_name="$1"
    local timeout="${2:-60}"
    local elapsed=0
    
    # Check if this suite needs port 443
    local resources_var="TEST_SUITES_${suite_name}_resources"
    local resources="${!resources_var}"
    
    if [[ "$resources" != *"ports:443"* ]]; then
        return 0  # Doesn't need port 443
    fi
    
    # Try to acquire lock
    while [ $elapsed -lt $timeout ]; do
        if mkdir "$PORT_443_LOCK_FILE" 2>/dev/null; then
            echo "$suite_name:$$" > "$PORT_443_LOCK_FILE/owner"
            log_info "Acquired port 443 lock for $suite_name"
            return 0
        fi
        
        # Check if lock owner is still alive
        if [ -f "$PORT_443_LOCK_FILE/owner" ]; then
            local owner=$(cat "$PORT_443_LOCK_FILE/owner" 2>/dev/null)
            local owner_pid="${owner#*:}"
            if ! kill -0 "$owner_pid" 2>/dev/null; then
                log_warning "Stale port 443 lock detected, cleaning up"
                rm -rf "$PORT_443_LOCK_FILE"
                continue
            fi
        fi
        
        sleep 2
        ((elapsed += 2))
    done
    
    log_error "Failed to acquire port 443 lock for $suite_name (timeout)"
    return 1
}

# Release port 443 lock
release_port_443_lock() {
    local suite_name="$1"
    
    if [ -d "$PORT_443_LOCK_FILE" ]; then
        local owner=$(cat "$PORT_443_LOCK_FILE/owner" 2>/dev/null)
        if [[ "$owner" == "$suite_name:$$" ]]; then
            rm -rf "$PORT_443_LOCK_FILE"
            log_info "Released port 443 lock for $suite_name"
        fi
    fi
}

# Allocate isolated resources for a test suite
allocate_test_resources() {
    local suite_name="$1"
    local job_index="$2"
    
    # Create isolated temp directory
    local temp_dir="$JOB_DIR/${suite_name}_env_$$"
    mkdir -p "$temp_dir"
    
    # Allocate auxiliary port range (NOT port 443)
    local start_port=$((BASE_TEST_PORT + (job_index * PORT_RANGE_SIZE)))
    local end_port=$((start_port + PORT_RANGE_SIZE - 1))
    
    # Create isolated log directory
    local log_dir="$temp_dir/logs"
    mkdir -p "$log_dir"
    
    # Check if this suite needs port 443
    local needs_port_443="no"
    local resources_var="TEST_SUITES_${suite_name}_resources"
    local resources="${!resources_var}"
    if [[ "$resources" == *"ports:443"* ]]; then
        needs_port_443="yes"
    fi
    
    # Create resource allocation file
    cat > "$temp_dir/resources.env" <<EOF
# Test suite: $suite_name
# Job index: $job_index
# Allocated resources
POSTMAN_TEST_TEMP_DIR="$temp_dir"
POSTMAN_TEST_LOG_DIR="$log_dir"
POSTMAN_TEST_SUITE_NAME="$suite_name"
POSTMAN_TEST_PORT_START="$start_port"
POSTMAN_TEST_PORT_END="$end_port"
POSTMAN_TEST_PRIMARY_PORT="$start_port"
POSTMAN_TEST_SECONDARY_PORT="$((start_port + 1))"
POSTMAN_TEST_HEALTH_PORT="$((start_port + 2))"
POSTMAN_TEST_DEBUG_PORT="$((start_port + 3))"
POSTMAN_TEST_NEEDS_PORT_443="$needs_port_443"
POSTMAN_TEST_DAEMON_PORT="443"  # Always 443 for HTTPS interception
EOF
    
    echo "$temp_dir"
}

# Check if port is available
is_port_available() {
    local port="$1"
    ! lsof -i :"$port" >/dev/null 2>&1
}

# Wait for port to become available
wait_for_port_available() {
    local port="$1"
    local timeout="${2:-30}"
    local elapsed=0
    
    while ! is_port_available "$port" && [ $elapsed -lt $timeout ]; do
        sleep 1
        ((elapsed++))
    done
    
    [ $elapsed -lt $timeout ]
}

# Validate resource allocation
validate_resource_allocation() {
    local temp_dir="$1"
    local suite_name="$2"
    
    if [ ! -f "$temp_dir/resources.env" ]; then
        log_error "Resource allocation file missing for $suite_name"
        return 1
    fi
    
    # Source the resource allocation
    source "$temp_dir/resources.env"
    
    # Check port availability
    local port_conflicts=0
    for port in "$POSTMAN_TEST_PRIMARY_PORT" "$POSTMAN_TEST_SECONDARY_PORT" "$POSTMAN_TEST_HEALTH_PORT"; do
        if ! is_port_available "$port"; then
            log_warning "Port conflict detected: $port (suite: $suite_name)"
            ((port_conflicts++))
        fi
    done
    
    if [ $port_conflicts -gt 0 ]; then
        log_warning "$port_conflicts port conflicts for $suite_name - tests may need port alternatives"
    fi
    
    # Create lock file to prevent resource conflicts
    echo "$suite_name:$$:$(date +%s)" > "$temp_dir/resource.lock"
    
    return 0
}

# Clean up allocated resources
cleanup_test_resources() {
    local temp_dir="$1"
    local suite_name="$2"
    
    if [ -f "$temp_dir/resources.env" ]; then
        source "$temp_dir/resources.env"
        
        # Kill any processes using our ports
        for port in "$POSTMAN_TEST_PRIMARY_PORT" "$POSTMAN_TEST_SECONDARY_PORT" "$POSTMAN_TEST_HEALTH_PORT" "$POSTMAN_TEST_DEBUG_PORT"; do
            local pids=$(lsof -t -i :"$port" 2>/dev/null || true)
            if [ -n "$pids" ]; then
                log_info "Cleaning up processes on port $port for $suite_name"
                echo "$pids" | xargs kill -TERM 2>/dev/null || true
                sleep 1
                echo "$pids" | xargs kill -KILL 2>/dev/null || true
            fi
        done
        
        # Wait for ports to be released
        for port in "$POSTMAN_TEST_PRIMARY_PORT" "$POSTMAN_TEST_SECONDARY_PORT" "$POSTMAN_TEST_HEALTH_PORT"; do
            wait_for_port_available "$port" 10 || log_warning "Port $port may still be in use after cleanup"
        done
    fi
    
    # Remove resource lock
    rm -f "$temp_dir/resource.lock" 2>/dev/null || true
    
    # Archive logs if there were failures
    if [ -d "$temp_dir/logs" ] && [ "$TOTAL_FAILURES" -gt 0 ]; then
        local archive_dir="$SCRIPT_DIR/archived_logs_${suite_name}_$(date +%s)"
        mv "$temp_dir/logs" "$archive_dir" 2>/dev/null || true
        log_info "Archived logs for $suite_name to: $archive_dir"
    fi
}

# Create isolated test environment for parallel execution
create_test_environment() {
    local suite_name="$1"
    local job_index="${2:-0}"
    
    if $USE_RESOURCE_ISOLATION; then
        local temp_dir=$(allocate_test_resources "$suite_name" "$job_index")
        validate_resource_allocation "$temp_dir" "$suite_name" || {
            log_error "Resource allocation failed for $suite_name"
            return 1
        }
    else
        # Simple temp directory without resource isolation
        local temp_dir="$JOB_DIR/${suite_name}_env_$$"
        mkdir -p "$temp_dir"
        
        # Create basic resource file for backwards compatibility
        cat > "$temp_dir/resources.env" <<EOF
POSTMAN_TEST_TEMP_DIR="$temp_dir"
POSTMAN_TEST_LOG_DIR="$temp_dir"
POSTMAN_TEST_SUITE_NAME="$suite_name"
POSTMAN_TEST_PRIMARY_PORT="443"
EOF
    fi
    
    echo "$temp_dir"
}

# Wait for available job slot
wait_for_job_slot() {
    while [ ${#JOB_PIDS[@]} -ge $MAX_PARALLEL_JOBS ]; do
        check_completed_jobs
        sleep 0.1
    done
}

# Check for completed background jobs
check_completed_jobs() {
    local i=0
    while [ $i -lt ${#JOB_PIDS[@]} ]; do
        local pid=${JOB_PIDS[$i]}
        local name=${JOB_NAMES[$i]}
        
        if ! kill -0 "$pid" 2>/dev/null; then
            # Job completed, check result
            wait "$pid"
            local exit_code=$?
            
            # Clean up job resources
            local env_path_file="$JOB_DIR/${name}.env_path"
            if [ -f "$env_path_file" ]; then
                local temp_dir=$(cat "$env_path_file")
                cleanup_test_resources "$temp_dir" "$name"
            fi
            
            # Release port 443 lock if held
            release_port_443_lock "$name"
            
            # Record result
            if [ $exit_code -eq 0 ]; then
                echo "success" > "$JOB_DIR/${name}.result"
                log_success "Parallel job completed: $name"
            else
                echo "failed:$exit_code" > "$JOB_DIR/${name}.result"
                log_error "Parallel job failed: $name (exit: $exit_code)"
                ((TOTAL_FAILURES++))
            fi
            
            # Remove from arrays
            JOB_PIDS=("${JOB_PIDS[@]:0:$i}" "${JOB_PIDS[@]:$((i+1))}")
            JOB_NAMES=("${JOB_NAMES[@]:0:$i}" "${JOB_NAMES[@]:$((i+1))}")
            JOB_START_TIMES=("${JOB_START_TIMES[@]:0:$i}" "${JOB_START_TIMES[@]:$((i+1))}")
        else
            ((i++))
        fi
    done
}

# Start background test job
start_background_job() {
    local suite_name="$1"
    local test_script="$2"
    
    wait_for_job_slot
    
    log_info "Starting parallel job: $suite_name"
    
    # Get job index for resource allocation
    local job_index=${#JOB_PIDS[@]}
    
    # Create isolated environment with resource allocation
    local temp_dir=$(create_test_environment "$suite_name" "$job_index")
    local job_log="$JOB_DIR/${suite_name}.log"
    
    if [ -z "$temp_dir" ]; then
        log_error "Failed to create test environment for $suite_name"
        return 1
    fi
    
    # Start job in background with timeout
    (
        # Set up job environment
        exec > "$job_log" 2>&1
        cd "$PROJECT_ROOT"
        
        # Source resource allocation if available
        if [ -f "$temp_dir/resources.env" ]; then
            source "$temp_dir/resources.env"
            log_info "Resource allocation for $suite_name:"
            log_info "  Temp dir: $POSTMAN_TEST_TEMP_DIR"
            log_info "  Auxiliary ports: $POSTMAN_TEST_PORT_START-$POSTMAN_TEST_PORT_END"
            if [[ "$POSTMAN_TEST_NEEDS_PORT_443" == "yes" ]]; then
                log_info "  HTTPS port: 443 (will acquire lock when needed)"
                # Try to acquire port 443 lock
                if ! acquire_port_443_lock "$suite_name" 120; then
                    log_error "Cannot run $suite_name - port 443 unavailable"
                    exit 1
                fi
            fi
        fi
        
        # Export environment for the test script
        export POSTMAN_TEST_SPEED_MODE="$SPEED_MODE"
        export POSTMAN_TEST_USE_CACHE="$USE_CACHE"
        export POSTMAN_CACHE_MANAGER="$CACHE_MANAGER"
        export POSTMAN_ENABLE_PARALLEL="$ENABLE_PARALLEL"
        export POSTMAN_USE_RESOURCE_ISOLATION="$USE_RESOURCE_ISOLATION"
        
        # Export all resource allocation variables if they exist
        if [ -f "$temp_dir/resources.env" ]; then
            source "$temp_dir/resources.env"
            # Export all POSTMAN_TEST_* variables
            export POSTMAN_TEST_TEMP_DIR
            export POSTMAN_TEST_LOG_DIR
            export POSTMAN_TEST_SUITE_NAME
            export POSTMAN_TEST_PORT_START
            export POSTMAN_TEST_PORT_END
            export POSTMAN_TEST_PRIMARY_PORT
            export POSTMAN_TEST_SECONDARY_PORT
            export POSTMAN_TEST_HEALTH_PORT
            export POSTMAN_TEST_DEBUG_PORT
        fi
        
        # Run the test script with timeout
        timeout $JOB_TIMEOUT "$test_script"
    ) &
    
    local job_pid=$!
    
    # Record job info
    JOB_PIDS+=("$job_pid")
    JOB_NAMES+=("$suite_name")
    JOB_START_TIMES+=($(date +%s))
    
    # Write PID file and resource info for monitoring
    echo "$job_pid" > "$JOB_DIR/${suite_name}.pid"
    echo "$temp_dir" > "$JOB_DIR/${suite_name}.env_path"
    
    if $USE_RESOURCE_ISOLATION && [ -f "$temp_dir/resources.env" ]; then
        source "$temp_dir/resources.env"
        log_info "Started job $suite_name (PID: $job_pid, ports: $POSTMAN_TEST_PORT_START-$POSTMAN_TEST_PORT_END)"
    else
        log_info "Started job $suite_name (PID: $job_pid)"
    fi
}

# Wait for all background jobs to complete
wait_all_jobs() {
    log_info "Waiting for ${#JOB_PIDS[@]} parallel jobs to complete..."
    
    local timeout=0
    local max_timeout=1800  # 30 minutes total
    
    while [ ${#JOB_PIDS[@]} -gt 0 ] && [ $timeout -lt $max_timeout ]; do
        check_completed_jobs
        
        if [ ${#JOB_PIDS[@]} -gt 0 ]; then
            sleep 1
            ((timeout++))
            
            # Show progress every 30 seconds
            if [ $((timeout % 30)) -eq 0 ]; then
                log_info "Still waiting for ${#JOB_PIDS[@]} jobs (${timeout}s elapsed)"
            fi
        fi
    done
    
    # Kill any remaining jobs that timed out
    if [ ${#JOB_PIDS[@]} -gt 0 ]; then
        log_warning "Timeout reached, terminating remaining jobs"
        for pid in "${JOB_PIDS[@]}"; do
            kill -TERM "$pid" 2>/dev/null || true
        done
        sleep 2
        for pid in "${JOB_PIDS[@]}"; do
            kill -KILL "$pid" 2>/dev/null || true
        done
    fi
    
    log_success "All parallel jobs completed"
}

# Collect results from parallel jobs
collect_parallel_results() {
    local failed_suites=""
    local suite_results="$JOB_DIR/suite_results.txt"
    
    echo "Parallel Test Results:" > "$suite_results"
    echo "=====================" >> "$suite_results"
    
    for suite in build daemon integration browser dns cleanup privilege cache download; do
        local result_file="$JOB_DIR/${suite}.result"
        local log_file="$JOB_DIR/${suite}.log"
        
        if [ -f "$result_file" ]; then
            local result=$(cat "$result_file")
            if [[ "$result" == "success" ]]; then
                echo "[PASS] $suite tests" >> "$suite_results"
                log_success "$suite tests: PASSED"
            else
                echo "[FAIL] $suite tests - $result" >> "$suite_results"
                log_error "$suite tests: FAILED"
                failed_suites+="$suite "
            fi
            
            # Include test output summary
            if [ -f "$log_file" ]; then
                echo "  Log: $log_file" >> "$suite_results"
                local line_count=$(wc -l < "$log_file" 2>/dev/null || echo 0)
                echo "  Output: $line_count lines" >> "$suite_results"
            fi
        else
            echo "[UNKNOWN] $suite tests - no result file" >> "$suite_results"
            log_error "$suite tests: NO RESULT"
            failed_suites+="$suite "
            ((TOTAL_FAILURES++))
        fi
        echo "" >> "$suite_results"
    done
    
    echo "$failed_suites"
}

# Cleanup parallel execution system
cleanup_parallel_system() {
    if $ENABLE_PARALLEL && [ -d "$JOB_DIR" ]; then
        log_info "Cleaning up parallel execution artifacts..."
        
        # Clean up remaining job resources first
        for i in "${!JOB_NAMES[@]}"; do
            local name="${JOB_NAMES[$i]}"
            local env_path_file="$JOB_DIR/${name}.env_path"
            if [ -f "$env_path_file" ]; then
                local temp_dir=$(cat "$env_path_file")
                log_info "Cleaning up resources for $name"
                cleanup_test_resources "$temp_dir" "$name"
            fi
        done
        
        # Kill any remaining jobs
        for pid in "${JOB_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                kill -TERM "$pid" 2>/dev/null || true
            fi
        done
        
        # Wait a moment then force kill
        sleep 2
        for pid in "${JOB_PIDS[@]}"; do
            if kill -0 "$pid" 2>/dev/null; then
                kill -KILL "$pid" 2>/dev/null || true
            fi
        done
        
        # Clean up any remaining port conflicts
        if $USE_RESOURCE_ISOLATION; then
            log_info "Checking for remaining port conflicts..."
            local conflicts=0
            local end_port=$((BASE_TEST_PORT + (MAX_PARALLEL_JOBS * PORT_RANGE_SIZE) - 1))
            for port in $(seq $BASE_TEST_PORT $end_port); do
                if ! is_port_available "$port"; then
                    local pids=$(lsof -t -i :"$port" 2>/dev/null || true)
                    if [ -n "$pids" ]; then
                        log_warning "Cleaning up remaining processes on port $port"
                        echo "$pids" | xargs kill -TERM 2>/dev/null || true
                        ((conflicts++))
                    fi
                fi
            done
            if [ $conflicts -gt 0 ]; then
                sleep 2
                log_info "Resource cleanup completed ($conflicts conflicts resolved)"
            fi
        fi
        
        # Archive job artifacts for debugging
        if [ "$TOTAL_FAILURES" -gt 0 ] && [ -d "$JOB_DIR" ]; then
            local archive_dir="$SCRIPT_DIR/failed_job_artifacts_$(date +%s)"
            log_info "Archiving job artifacts to: $archive_dir"
            cp -r "$JOB_DIR" "$archive_dir" 2>/dev/null || true
        fi
        
        # Clean up job directory
        rm -rf "$JOB_DIR" 2>/dev/null || true
    fi
}

# Get speed mode description
get_speed_mode_description() {
    case "$SPEED_MODE" in
        "smoke")
            echo "Smoke tests only - critical functionality"
            ;;
        "fast") 
            echo "Fast/Unit tests - no system modifications"
            ;;
        "component")
            echo "Fast + Medium/Component tests - limited system changes"
            ;;
        "full")
            echo "All tests including Slow/Integration - full system testing"
            ;;
        *)
            echo "Unknown speed mode: $SPEED_MODE"
            ;;
    esac
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check if on macOS
    if [[ "$OSTYPE" != "darwin"* ]]; then
        log_error "This test suite requires macOS"
        exit 1
    fi
    
    # Check Go installation
    if ! command -v go &> /dev/null; then
        log_error "Go is not installed"
        exit 1
    fi
    
    # Check required tools
    local missing_tools=()
    for tool in openssl curl lsof plutil; do
        if ! command -v "$tool" &> /dev/null; then
            missing_tools+=("$tool")
        fi
    done
    
    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_warning "Missing tools: ${missing_tools[*]}"
        log_info "Some tests may be skipped"
    fi
    
    # Check permissions - CRITICAL for daemon testing
    if [ "$EUID" -eq 0 ]; then
        log_success "Running as root - full test coverage available"
    else
        log_warning "NOT RUNNING AS ROOT - Critical tests will be skipped!"
        log_warning "The following tests REQUIRE root privileges:"
        log_warning "  - Port 443 binding (HTTPS interception)"
        log_warning "  - DNS interception (/etc/hosts modification)"
        log_warning "  - Certificate trust installation"
        log_warning "  - LaunchDaemon operations"
        log_warning "  - Process management tests"
        echo ""
        log_error "For effective testing, please run: sudo $0 $*"
        echo ""
        read -p "Continue anyway with LIMITED testing? (y/N): " -n 1 -r
        echo ""
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log_info "Exiting. Please run with sudo for full testing."
            exit 1
        fi
        log_warning "Continuing with LIMITED testing capabilities..."
    fi
    
    log_success "Prerequisites check completed"
}

# Export speed mode for use in test scripts
export_test_config() {
    export POSTMAN_TEST_SPEED_MODE="$SPEED_MODE"
    export POSTMAN_TEST_USE_CACHE="$USE_CACHE"
    export POSTMAN_CACHE_MANAGER="$CACHE_MANAGER"
}

# Run build script tests
run_build_tests() {
    log_separator
    echo -e "${YELLOW}Running Build Script Tests${NC}"
    log_separator
    
    local test_script="$SCRIPT_DIR/test_macos_build.sh"
    
    if [ ! -x "$test_script" ]; then
        log_error "Build test script not found or not executable: $test_script"
        return 1
    fi
    
    if "$test_script"; then
        log_success "Build tests completed successfully"
        return 0
    else
        log_error "Build tests failed"
        return 1
    fi
}

# Get test script path for parallel execution
get_build_test_script() {
    echo "$SCRIPT_DIR/test_macos_build.sh"
}

# Run daemon functional tests
run_daemon_tests() {
    log_separator
    echo -e "${YELLOW}Running Daemon Functional Tests${NC}"
    log_separator
    
    local test_script="$SCRIPT_DIR/test_macos_daemon.sh"
    
    if [ ! -x "$test_script" ]; then
        log_error "Daemon test script not found or not executable: $test_script"
        return 1
    fi
    
    if "$test_script"; then
        log_success "Daemon tests completed successfully"
        return 0
    else
        log_error "Daemon tests failed"
        return 1
    fi
}

# Get test script path for parallel execution
get_daemon_test_script() {
    echo "$SCRIPT_DIR/test_macos_daemon.sh"
}

# Run integration tests
run_integration_tests() {
    log_separator
    echo -e "${YELLOW}Running Integration Tests${NC}"
    log_separator
    
    local test_script="$SCRIPT_DIR/test_macos_integration.sh"
    
    if [ ! -x "$test_script" ]; then
        log_error "Integration test script not found or not executable: $test_script"
        return 1
    fi
    
    if "$test_script"; then
        log_success "Integration tests completed successfully"
        return 0
    else
        log_error "Integration tests failed"
        return 1
    fi
}

# Get test script path for parallel execution
get_integration_test_script() {
    echo "$SCRIPT_DIR/test_macos_integration.sh"
}

# Run browser session tests
run_browser_tests() {
    log_separator
    echo -e "${YELLOW}Running Browser Session Tests${NC}"
    log_separator
    
    local test_script="$SCRIPT_DIR/test_browser_sessions.sh"
    
    if [ ! -x "$test_script" ]; then
        log_error "Browser test script not found or not executable: $test_script"
        return 1
    fi
    
    if "$test_script"; then
        log_success "Browser tests completed successfully"
        return 0
    else
        log_error "Browser tests failed"
        return 1
    fi
}

get_browser_test_script() {
    echo "$SCRIPT_DIR/test_browser_sessions.sh"
}

# Run DNS method tests
run_dns_tests() {
    log_separator
    echo -e "${YELLOW}Running DNS Method Tests${NC}"
    log_separator
    
    local test_script="$SCRIPT_DIR/test_dns_methods.sh"
    
    if [ ! -x "$test_script" ]; then
        log_error "DNS test script not found or not executable: $test_script"
        return 1
    fi
    
    if "$test_script"; then
        log_success "DNS tests completed successfully"
        return 0
    else
        log_error "DNS tests failed"
        return 1
    fi
}

get_dns_test_script() {
    echo "$SCRIPT_DIR/test_dns_methods.sh"
}

# Run cleanup manager tests
run_cleanup_tests() {
    log_separator
    echo -e "${YELLOW}Running Cleanup Manager Tests${NC}"
    log_separator
    
    local test_script="$SCRIPT_DIR/test_cleanup_manager.sh"
    
    if [ ! -x "$test_script" ]; then
        log_error "Cleanup test script not found or not executable: $test_script"
        return 1
    fi
    
    if "$test_script"; then
        log_success "Cleanup tests completed successfully"
        return 0
    else
        log_error "Cleanup tests failed"
        return 1
    fi
}

get_cleanup_test_script() {
    echo "$SCRIPT_DIR/test_cleanup_manager.sh"
}

# Run privilege escalation tests
run_privilege_tests() {
    log_separator
    echo -e "${YELLOW}Running Privilege Escalation Tests${NC}"
    log_separator
    
    local test_script="$SCRIPT_DIR/test_privilege_escalation.sh"
    
    if [ ! -x "$test_script" ]; then
        log_error "Privilege test script not found or not executable: $test_script"
        return 1
    fi
    
    if "$test_script"; then
        log_success "Privilege tests completed successfully"
        return 0
    else
        log_error "Privilege tests failed"
        return 1
    fi
}

get_privilege_test_script() {
    echo "$SCRIPT_DIR/test_privilege_escalation.sh"
}

# Run cache system tests
run_cache_tests() {
    log_separator
    echo -e "${YELLOW}Running Cache System Tests${NC}"
    log_separator
    
    local test_script="$SCRIPT_DIR/test_cache.sh"
    
    if [ ! -x "$test_script" ]; then
        log_error "Cache test script not found or not executable: $test_script"
        return 1
    fi
    
    if "$test_script" test; then
        log_success "Cache tests completed successfully"
        return 0
    else
        log_error "Cache tests failed"
        return 1
    fi
}

get_cache_test_script() {
    echo "$SCRIPT_DIR/test_cache.sh test"
}

# Run download robustness tests
run_download_tests() {
    log_separator
    echo -e "${YELLOW}Running Download Robustness Tests${NC}"
    log_separator
    
    local test_script="$SCRIPT_DIR/test_download_robustness.sh"
    
    if [ ! -x "$test_script" ]; then
        log_error "Download test script not found or not executable: $test_script"
        return 1
    fi
    
    if "$test_script"; then
        log_success "Download tests completed successfully"
        return 0
    else
        log_error "Download tests failed"
        return 1
    fi
}

get_download_test_script() {
    echo "$SCRIPT_DIR/test_download_robustness.sh"
}

# Parse command line arguments
RUN_SPECIFIC=""  # Global variable
parse_arguments() {
    local show_help=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --build)
                RUN_SPECIFIC="build"
                shift
                ;;
            --daemon)
                RUN_SPECIFIC="daemon"
                shift
                ;;
            --integration)
                RUN_SPECIFIC="integration"
                shift
                ;;
            --browser)
                RUN_SPECIFIC="browser"
                shift
                ;;
            --dns)
                RUN_SPECIFIC="dns"
                shift
                ;;
            --cleanup)
                RUN_SPECIFIC="cleanup"
                shift
                ;;
            --privilege)
                RUN_SPECIFIC="privilege"
                shift
                ;;
            --cache)
                RUN_SPECIFIC="cache"
                shift
                ;;
            --download)
                RUN_SPECIFIC="download"
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
            --parallel)
                ENABLE_PARALLEL=true
                if [[ $2 =~ ^[0-9]+$ ]] && [ $2 -gt 0 ]; then
                    MAX_PARALLEL_JOBS=$2
                    shift
                fi
                shift
                ;;
            --sequential)
                ENABLE_PARALLEL=false
                shift
                ;;
            --no-isolation)
                USE_RESOURCE_ISOLATION=false
                shift
                ;;
            --base-port)
                if [[ $2 =~ ^[0-9]+$ ]] && [ $2 -gt 1024 ] && [ $2 -lt 65000 ]; then
                    BASE_TEST_PORT=$2
                    shift
                else
                    log_error "Invalid base port: $2 (must be 1024-65000)"
                    show_help=true
                fi
                shift
                ;;
            --jobs|-j)
                if [[ $2 =~ ^[0-9]+$ ]] && [ $2 -gt 0 ]; then
                    MAX_PARALLEL_JOBS=$2
                    shift
                else
                    log_error "Invalid job count: $2"
                    show_help=true
                fi
                shift
                ;;
            --timeout)
                if [[ $2 =~ ^[0-9]+$ ]] && [ $2 -gt 0 ]; then
                    JOB_TIMEOUT=$2
                    shift
                else
                    log_error "Invalid timeout: $2"
                    show_help=true
                fi
                shift
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
        echo "Run macOS test suites for Postman AuthRouter"
        echo ""
        echo "Test Suite Options:"
        echo "  --build        Run only build script tests"
        echo "  --daemon       Run only daemon functional tests"
        echo "  --integration  Run only integration tests"
        echo "  --browser      Run only browser session tests"
        echo "  --dns          Run only DNS interception tests"
        echo "  --cleanup      Run only cleanup manager tests"
        echo "  --privilege    Run only privilege escalation tests"
        echo "  --cache        Run only cache system tests"
        echo "  --download     Run only download robustness tests"
        echo ""
        echo "Speed/Category Options:"
        echo "  --smoke        Run only critical smoke tests (fastest, 30-60s)"
        echo "  --fast         Run Fast/Unit tests only (2-3 minutes)"
        echo "  --component    Run Fast + Medium/Component tests (5-8 minutes)"
        echo "  --full         Run all tests including Slow/Integration (10-20 minutes)"
        echo ""
        echo "Caching Options:"
        echo "  --no-cache     Disable artifact caching (slower but always fresh)"
        echo ""
        echo "Parallel Execution Options:"
        echo "  --parallel [N] Enable parallel execution (default: 3 jobs)"
        echo "  --sequential   Disable parallel execution (run tests sequentially)"
        echo "  -j, --jobs N   Set maximum number of parallel jobs (default: 3)"
        echo "  --timeout N    Set job timeout in seconds (default: 600)"
        echo ""
        echo "Resource Isolation Options:"
        echo "  --no-isolation Disable resource isolation (use shared resources)"
        echo "  --base-port N  Set base port for test services (default: 8443)"
        echo ""
        echo "  --help, -h     Show this help message"
        echo ""
        echo "If no specific options are specified, --full mode is used."
        echo ""
        echo "Note: Some tests require root privileges for full functionality."
        echo "Run with sudo for comprehensive testing."
        exit 0
    fi
}

# Generate summary report
generate_summary() {
    local failed_suites="$1"
    
    log_separator
    echo -e "${YELLOW}Test Summary${NC}"
    log_separator
    
    if [ "$TOTAL_FAILURES" -eq 0 ]; then
        log_success "All test suites passed!"
    else
        log_error "Test suites failed: $TOTAL_FAILURES"
        if [ -n "$failed_suites" ]; then
            echo "Failed suites: $failed_suites"
        fi
    fi
    
    # Show result files
    echo ""
    log_info "Test result files:"
    for result_file in "$SCRIPT_DIR"/test_results_*.txt; do
        if [ -f "$result_file" ]; then
            echo "  - $(basename "$result_file")"
        fi
    done
    
    echo ""
    log_info "Test logs and artifacts stored in: $SCRIPT_DIR"
}

# Main test runner
main() {
    # Parse command line first
    parse_arguments "$@"
    
    # Handle sudo requirement for daemon/integration tests
    if [ "$EUID" -ne 0 ]; then
        case "$RUN_SPECIFIC" in
            daemon|integration)
                log_error "$RUN_SPECIFIC tests REQUIRE root privileges"
                log_info "Please run: sudo $0 --$RUN_SPECIFIC $*"
                exit 1
                ;;
            "")
                if [[ "$SPEED_MODE" != "smoke" ]]; then
                    log_warning "Full test suite includes tests requiring root"
                fi
                ;;
        esac
    fi
    
    echo "========================================"
    echo "macOS Test Suite Runner"
    echo "========================================"
    echo "Started: $(date)"
    echo "Platform: $(uname -a)"
    echo "Go version: $(go version)"
    echo "Speed mode: $SPEED_MODE ($(get_speed_mode_description))"
    echo "Cache: $($USE_CACHE && echo "enabled" || echo "disabled")"
    echo "Parallel execution: $($ENABLE_PARALLEL && echo "enabled (max jobs: $MAX_PARALLEL_JOBS)" || echo "disabled")"
    if $ENABLE_PARALLEL; then
        echo "Resource isolation: $($USE_RESOURCE_ISOLATION && echo "enabled (base port: $BASE_TEST_PORT)" || echo "disabled")"
    fi
    echo ""
    
    # Initialize systems
    init_cache_system
    init_parallel_system
    
    # Export test configuration
    export_test_config
    export POSTMAN_ENABLE_PARALLEL="$ENABLE_PARALLEL"
    export POSTMAN_USE_RESOURCE_ISOLATION="$USE_RESOURCE_ISOLATION"
    export POSTMAN_BASE_TEST_PORT="$BASE_TEST_PORT"
    
    # Check prerequisites
    check_prerequisites
    
    # Change to project root
    cd "$PROJECT_ROOT"
    
    local failed_suites=""
    
    # Run specific test suite or all
    if [ -n "$RUN_SPECIFIC" ]; then
        log_info "Running specific test suite: $RUN_SPECIFIC"
        case "$RUN_SPECIFIC" in
            build)
                if $ENABLE_PARALLEL; then
                    start_background_job "build" "$(get_build_test_script)"
                    wait_all_jobs
                    failed_suites=$(collect_parallel_results)
                else
                    run_build_tests || { ((TOTAL_FAILURES++)); failed_suites+="build "; }
                fi
                ;;
            daemon)
                if $ENABLE_PARALLEL; then
                    start_background_job "daemon" "$(get_daemon_test_script)"
                    wait_all_jobs
                    failed_suites=$(collect_parallel_results)
                else
                    run_daemon_tests || { ((TOTAL_FAILURES++)); failed_suites+="daemon "; }
                fi
                ;;
            integration)
                if $ENABLE_PARALLEL; then
                    start_background_job "integration" "$(get_integration_test_script)"
                    wait_all_jobs
                    failed_suites=$(collect_parallel_results)
                else
                    run_integration_tests || { ((TOTAL_FAILURES++)); failed_suites+="integration "; }
                fi
                ;;
            browser)
                if $ENABLE_PARALLEL; then
                    start_background_job "browser" "$(get_browser_test_script)"
                    wait_all_jobs
                    failed_suites=$(collect_parallel_results)
                else
                    run_browser_tests || { ((TOTAL_FAILURES++)); failed_suites+="browser "; }
                fi
                ;;
            dns)
                if $ENABLE_PARALLEL; then
                    start_background_job "dns" "$(get_dns_test_script)"
                    wait_all_jobs
                    failed_suites=$(collect_parallel_results)
                else
                    run_dns_tests || { ((TOTAL_FAILURES++)); failed_suites+="dns "; }
                fi
                ;;
            cleanup)
                if $ENABLE_PARALLEL; then
                    start_background_job "cleanup" "$(get_cleanup_test_script)"
                    wait_all_jobs
                    failed_suites=$(collect_parallel_results)
                else
                    run_cleanup_tests || { ((TOTAL_FAILURES++)); failed_suites+="cleanup "; }
                fi
                ;;
            privilege)
                if $ENABLE_PARALLEL; then
                    start_background_job "privilege" "$(get_privilege_test_script)"
                    wait_all_jobs
                    failed_suites=$(collect_parallel_results)
                else
                    run_privilege_tests || { ((TOTAL_FAILURES++)); failed_suites+="privilege "; }
                fi
                ;;
            cache)
                if $ENABLE_PARALLEL; then
                    start_background_job "cache" "$(get_cache_test_script)"
                    wait_all_jobs
                    failed_suites=$(collect_parallel_results)
                else
                    run_cache_tests || { ((TOTAL_FAILURES++)); failed_suites+="cache "; }
                fi
                ;;
            download)
                if $ENABLE_PARALLEL; then
                    start_background_job "download" "$(get_download_test_script)"
                    wait_all_jobs
                    failed_suites=$(collect_parallel_results)
                else
                    run_download_tests || { ((TOTAL_FAILURES++)); failed_suites+="download "; }
                fi
                ;;
        esac
    else
        log_info "Running all test suites"
        
        if $ENABLE_PARALLEL; then
            log_info "Starting parallel execution of all test suites"
            
            # Start all test suites in parallel
            start_background_job "build" "$(get_build_test_script)"
            start_background_job "daemon" "$(get_daemon_test_script)"
            start_background_job "integration" "$(get_integration_test_script)"
            start_background_job "browser" "$(get_browser_test_script)"
            start_background_job "dns" "$(get_dns_test_script)"
            start_background_job "cleanup" "$(get_cleanup_test_script)"
            start_background_job "privilege" "$(get_privilege_test_script)"
            start_background_job "cache" "$(get_cache_test_script)"
            start_background_job "download" "$(get_download_test_script)"
            
            # Wait for all jobs to complete
            wait_all_jobs
            
            # Collect and process results
            failed_suites=$(collect_parallel_results)
        else
            log_info "Running test suites sequentially"
            
            # Run all test suites sequentially
            run_build_tests || { ((TOTAL_FAILURES++)); failed_suites+="build "; }
            run_daemon_tests || { ((TOTAL_FAILURES++)); failed_suites+="daemon "; }
            run_integration_tests || { ((TOTAL_FAILURES++)); failed_suites+="integration "; }
            run_browser_tests || { ((TOTAL_FAILURES++)); failed_suites+="browser "; }
            run_dns_tests || { ((TOTAL_FAILURES++)); failed_suites+="dns "; }
            run_cleanup_tests || { ((TOTAL_FAILURES++)); failed_suites+="cleanup "; }
            run_privilege_tests || { ((TOTAL_FAILURES++)); failed_suites+="privilege "; }
            run_cache_tests || { ((TOTAL_FAILURES++)); failed_suites+="cache "; }
            run_download_tests || { ((TOTAL_FAILURES++)); failed_suites+="download "; }
        fi
    fi
    
    # Generate summary
    generate_summary "$failed_suites"
    
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