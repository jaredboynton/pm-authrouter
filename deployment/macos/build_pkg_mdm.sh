#!/bin/bash

# Build macOS PKG by modifying existing Postman Enterprise PKG
# Handles both ARM64 and Intel architectures automatically
# Extracts original PKG, adds AuthRouter daemon, rebuilds as combined installer
# Creates combined PKG with full Postman.app + AuthRouter daemon

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Find project root by locating go.mod
PROJECT_ROOT="$SCRIPT_DIR"
while [ ! -f "$PROJECT_ROOT/go.mod" ] && [ "$PROJECT_ROOT" != "/" ]; do
    PROJECT_ROOT="$(dirname "$PROJECT_ROOT")"
done

if [ ! -f "$PROJECT_ROOT/go.mod" ]; then
    log_error "Could not find project root (go.mod not found)"
    exit 1
fi

# Set SSL directory path early so it's available throughout script
SSL_DIR="$PROJECT_ROOT/ssl"

# Constants for validation thresholds (Fix 6: Replace hardcoded magic numbers)
readonly MIN_DOWNLOAD_SIZE_MB=10      # Minimum expected download size (10MB)
readonly MIN_PKG_SIZE_KB=1000         # Minimum PKG size (1MB)  
readonly MAX_PKG_SIZE_MB=500          # Maximum reasonable PKG size (500MB)
readonly MIN_BINARY_SIZE_KB=1000      # Minimum Go binary size (1MB)

# Configuration parameters (required)
TEAM_NAME="${TEAM_NAME:-}"
SAML_URL="${SAML_URL:-}"
IDENTIFIER="${IDENTIFIER:-com.postman.enterprise.authrouter}"
VERSION="${VERSION:-11.58.0}"
CERT_ORG="${CERT_ORG:-Postdot Technologies, Inc}"
QUIET="${QUIET:-false}"
DEBUG_MODE="${DEBUG_MODE:-0}"

# CI/CD behavior flags for enterprise deployment
SKIP_DEPS="${SKIP_DEPS:-false}"
OFFLINE_MODE="${OFFLINE_MODE:-false}"
NON_INTERACTIVE="${NON_INTERACTIVE:-false}"
FAIL_FAST="${FAIL_FAST:-true}"

# PKG Download URLs (configurable via environment)
ARM64_PKG_URL="${ARM64_PKG_URL:-https://dl.pstmn.io/download/latest/version/11/osx?channel=enterprise&filetype=pkg&arch=arm64}"
INTEL_PKG_URL="${INTEL_PKG_URL:-https://dl.pstmn.io/download/latest/version/11/osx?channel=enterprise&filetype=pkg&arch=x64}"

# Secure temp directory configuration
readonly TEMP_ROOT="${TMPDIR:-/tmp}"
readonly SCRIPT_VERSION="1.0"
readonly SCRIPT_NAME="$(basename "$0")"

# Enhanced logging with validation tracking
log() {
    local timestamp
    # Cross-platform timestamp (macOS doesn't support %N)
    if date '+%Y-%m-%d %H:%M:%S.%3N' 2>/dev/null | grep -q N; then
        # Fallback for systems without nanosecond support
        timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    else
        timestamp=$(date '+%Y-%m-%d %H:%M:%S.%3N')
    fi
    
    local level="$1"
    shift
    local message="$*"
    
    # Only show output if not quiet (fully suppress in quiet mode)
    if [[ "$QUIET" != "true" ]]; then
        echo "[$timestamp] [$level] $message"
    fi
    
    # Always write debug info for important events
    if [[ "$DEBUG_MODE" == "1" ]] || [[ "$level" =~ ^(DEBUG|ERROR|VALIDATION_ERROR|VALIDATION_SUCCESS)$ ]]; then
        echo "[$timestamp] [PID:$$] [$level] [PWD:$(pwd)] $message" >> "${TMPDIR:-/tmp}/build_pkg_debug_$(date +%Y%m%d).log" 2>/dev/null || true
    fi
}

log_error() {
    log "ERROR" "$@"
}

# Debug file operations
debug_file_op() {
    local operation="$1"  # READ, WRITE, DELETE, MODIFY
    local file="$2"
    local context="${3:-}"
    
    local size=""
    local checksum=""
    
    if [[ -f "$file" ]]; then
        size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "unknown")
        checksum=$(openssl dgst -md5 "$file" 2>/dev/null | awk '{print $2}' || echo "unknown")
    fi
    
    log "DEBUG" "FILE_${operation}: $file [size: $size] [md5: $checksum] ${context:+[$context]}"
}

# Enhanced command logging
log_cmd() {
    local cmd="$1"
    shift
    
    local cmd_start=$(date +%s)
    log "CMD" "Executing: $cmd $*"
    
    if [[ "$DEBUG_MODE" == "1" ]]; then
        log "DEBUG" "CMD_ARGS: $(printf '%q ' "$@")"
    fi
    
    local exit_code=0
    if "$cmd" "$@"; then
        local cmd_end=$(date +%s)
        local duration=$(( cmd_end - cmd_start ))
        log "SUCCESS" "Command completed: $cmd [duration: ${duration}s]"
    else
        exit_code=$?
        local cmd_end=$(date +%s)
        local duration=$(( cmd_end - cmd_start ))
        log "ERROR" "Command failed with exit code $exit_code: $cmd [duration: ${duration}s]"
    fi
    
    return $exit_code
}

validation_error() {
    local phase="$1"
    local error="$2"
    
    log "VALIDATION_ERROR" "[$phase] $error"
    log "DEBUG" "STACK_TRACE: ${BASH_SOURCE[*]}"
    log "DEBUG" "LINE_NUMBERS: ${BASH_LINENO[*]}"
    log "DEBUG" "FUNCTION_STACK: ${FUNCNAME[*]}"
    
    exit 1
}

validation_success() {
    local phase="$1"
    local message="$2"
    log "VALIDATION_SUCCESS" "[$phase] $message"
}

# Single MDM profile generation function to avoid duplication
generate_mdm_profile() {
    local INPUT_CERT="$1"
    local OUTPUT_FILE="$2"
    
    if [ ! -f "$INPUT_CERT" ]; then
        validation_error "MDM_PROFILE_GENERATION" "Certificate file not found: $INPUT_CERT"
    fi
    
    # Read certificate and encode it for the profile
    local CERT_BASE64=$(cat "$INPUT_CERT" | grep -v "BEGIN CERTIFICATE" | grep -v "END CERTIFICATE" | tr -d '\n')
    
    # Generate UUID for profile
    local PROFILE_UUID=$(uuidgen)
    local PAYLOAD_UUID=$(uuidgen)
    
    # Get certificate SHA-1 fingerprint for trust settings
    local CERT_SHA1=$(openssl x509 -in "$INPUT_CERT" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')
    
    # Create the configuration profile
    cat > "$OUTPUT_FILE" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <!-- Install the certificate -->
        <dict>
            <key>PayloadCertificateFileName</key>
            <string>identity.getpostman.com.crt</string>
            <key>PayloadContent</key>
            <data>
$CERT_BASE64
            </data>
            <key>PayloadDescription</key>
            <string>Installs the Postman AuthRouter SSL certificate for SAML enforcement</string>
            <key>PayloadDisplayName</key>
            <string>Postman AuthRouter Certificate</string>
            <key>PayloadIdentifier</key>
            <string>com.postman.authrouter.certificate.$PAYLOAD_UUID</string>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadUUID</key>
            <string>$PAYLOAD_UUID</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>AllowAllAppsAccess</key>
            <true/>
        </dict>
        <!-- Configure trust settings for the certificate -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.security.certificatetrust</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.postman.authrouter.trust.$(uuidgen)</string>
            <key>PayloadUUID</key>
            <string>$(uuidgen)</string>
            <key>PayloadDisplayName</key>
            <string>Certificate Trust Settings</string>
            <key>PayloadDescription</key>
            <string>Trust settings for Postman AuthRouter certificate</string>
            <key>PayloadOrganization</key>
            <string>Postman</string>
            <key>TrustedCertificates</key>
            <array>
                <dict>
                    <key>SHA1Fingerprint</key>
                    <data>$(echo -n "$CERT_SHA1" | xxd -r -p | base64)</data>
                    <key>TrustSettings</key>
                    <dict>
                        <key>kSecTrustSettingsAllowedError</key>
                        <integer>-2147408896</integer>
                        <key>kSecTrustSettingsResult</key>
                        <integer>1</integer>
                    </dict>
                </dict>
            </array>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>This profile installs the Postman AuthRouter SSL certificate as a trusted root certificate to enable SAML enforcement for identity.getpostman.com. This is required for the Postman Enterprise SAML integration to function properly.</string>
    <key>PayloadDisplayName</key>
    <string>Postman Enterprise AuthRouter Certificate Trust</string>
    <key>PayloadIdentifier</key>
    <string>com.postman.authrouter.certificate</string>
    <key>PayloadOrganization</key>
    <string>Postman</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadScope</key>
    <string>System</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>$PROFILE_UUID</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
EOF
}

# XML escaping function (Fix 8: Add XML escaping for variables)
xml_escape() {
    local text="$1"
    text="${text//&/&amp;}"      # Must be first
    text="${text//</&lt;}"       
    text="${text//>/&gt;}"       
    text="${text//\"/&quot;}"    
    text="${text//\'/&#39;}"     
    echo "$text"
}

# Enhanced cleanup handler for graceful shutdown (Fix 1: Function order)
cleanup() {
    local exit_code=$?
    
    log "INFO" "Starting cleanup process..."
    
    # Clean up architecture-specific files
    rm -f "$SCRIPT_DIR"/pm-authrouter-* 2>/dev/null || true
    rm -rf "$SCRIPT_DIR"/combined_root_* 2>/dev/null || true
    rm -rf "$SCRIPT_DIR"/extracted_pkg_* 2>/dev/null || true
    
    # Fix 7: Safe temp file cleanup - use specific PID patterns and safety checks
    if [[ -n "${TEMP_ROOT:-}" ]]; then
        find "$TEMP_ROOT" -maxdepth 1 -name "postman-*-$$-*" -type d 2>/dev/null | while read -r tmpdir; do
            if [[ -d "$tmpdir" && "$tmpdir" =~ ^${TEMP_ROOT}/postman-.*-[0-9]+-.* ]]; then
                log "DEBUG" "Removing process-specific temp directory: $tmpdir"
                rm -rf "$tmpdir" 2>/dev/null || true
            fi
        done
        
        # Clean up other temp patterns we create
        find "$TEMP_ROOT" -maxdepth 1 \( -name "pkg-validate-$$-*" -o -name "pkg_expand_$$_*" -o -name "pkg_welcome_$$_*" -o -name "cert-gen-$$-*" -o -name "final-validate-$$-*" \) -type d 2>/dev/null | while read -r tmpdir; do
            if [[ -d "$tmpdir" ]]; then
                log "DEBUG" "Removing temp directory: $tmpdir" 
                rm -rf "$tmpdir" 2>/dev/null || true
            fi
        done
    fi
    
    if [[ $exit_code -ne 0 ]]; then
        log "ERROR" "Build process failed with exit code $exit_code"
    else
        log "INFO" "Cleanup completed successfully"
    fi
    
    exit $exit_code
}

# Set trap for cleanup on error
trap cleanup EXIT

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --team)
            TEAM_NAME="$2"
            shift 2
            ;;
        --saml-url)
            SAML_URL="$2"
            shift 2
            ;;
        --output)
            CUSTOM_PKG_NAME="$2"
            shift 2
            ;;
        --cert-org)
            CERT_ORG="$2"
            shift 2
            ;;
        --quiet)
            QUIET="true"
            shift
            ;;
        --debug)
            DEBUG_MODE="1"
            log "INFO" "Debug mode enabled"
            shift
            ;;
        --skip-deps)
            SKIP_DEPS="true"
            log "INFO" "Dependency checks disabled"
            shift
            ;;
        --offline)
            OFFLINE_MODE="true"
            log "INFO" "Offline mode enabled - no downloads"
            shift
            ;;
        --version)
            echo "$SCRIPT_NAME version $SCRIPT_VERSION"
            echo "Enterprise PKG builder for Postman AuthRouter"
            echo ""
            echo "Build Environment:"
            echo "  OS: $(uname -s) $(uname -r)"
            echo "  Architecture: $(uname -m)"
            echo "  Go Version: $(go version 2>/dev/null | awk '{print $3}' || echo 'not installed')"
            echo "  pkgbuild: $(pkgbuild --version 2>/dev/null | head -1 || echo 'not found')"
            echo "  productbuild: $(productbuild --version 2>/dev/null | head -1 || echo 'not found')"
            echo "  OpenSSL: $(openssl version 2>/dev/null || echo 'not found')"
            echo ""
            echo "Configuration:"
            echo "  Team Name: ${TEAM_NAME:-[not set]}"
            echo "  SAML URL: ${SAML_URL:-[not set]}"
            echo "  Certificate Organization: ${CERT_ORG:-[default]}"
            echo ""
            echo "CI/CD Flags:"
            echo "  SKIP_DEPS: ${SKIP_DEPS:-false}"
            echo "  OFFLINE_MODE: ${OFFLINE_MODE:-false}"
            echo "  NON_INTERACTIVE: ${NON_INTERACTIVE:-false}"
            echo "  FAIL_FAST: ${FAIL_FAST:-true}"
            exit 0
            ;;
        --help)
            echo "Usage: $0 [options]"
            echo "All parameters are optional - service will be installed but requires configuration:"
            echo "  --team <name>         Set team name (optional - can be set at install time)"
            echo "  --saml-url <url>      Set SAML URL (optional - can be set at install time)"
            echo "  --output <file>       Output PKG filename (auto-generated from original PKG name)"
            echo "  --cert-org <org>      Certificate organization name (default: Postdot Technologies, Inc)"
            echo "  --quiet              Reduce output for CI/CD environments"
            echo "  --debug              Enable debug logging and file operation tracking"
            echo "  --skip-deps          Skip dependency validation (for CI/CD with pre-validated environment)"
            echo "  --offline            Disable automatic PKG downloads (requires pre-placed PKG files)"
            echo "  --version            Show version and build environment information"
            echo "  --help               Show this help message"
            echo ""
            echo "Install-time configuration (overrides build-time values):"
            echo "  sudo launchctl setenv INSTALLER_TEAM_NAME 'myteam'"
            echo "  sudo launchctl setenv INSTALLER_SAML_URL 'https://...'"
            echo "  sudo installer -pkg package.pkg -target /"
            echo "  sudo launchctl unsetenv INSTALLER_TEAM_NAME INSTALLER_SAML_URL"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Phase 1: Dependency Management and Feature Detection
check_dependencies() {
    if [[ "$SKIP_DEPS" == "true" ]]; then
        log "INFO" "=== Phase 1: Dependency Management (SKIPPED - CI/CD Mode) ==="
        log "WARN" "Dependency validation disabled - assuming pre-validated CI/CD environment"
        return 0
    fi
    
    log "INFO" "=== Phase 1: Dependency Management and Feature Detection ==="
    
    local missing_tools=()
    local required_tools=(pkgutil pkgbuild productbuild openssl go uuidgen)
    
    # Add curl dependency if not in offline mode
    if [[ "$OFFLINE_MODE" != "true" ]]; then
        required_tools+=(curl)
    fi
    
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
            log "ERROR" "Missing required tool: $tool"
        else
            local tool_path=$(which "$tool")
            local tool_version=""
            
            case "$tool" in
                go)
                    tool_version=$(go version 2>/dev/null | awk '{print $3}' || echo "unknown")
                    ;;
                openssl)
                    tool_version=$(openssl version 2>/dev/null | awk '{print $2}' || echo "unknown")
                    ;;
                *)
                    tool_version="available"
                    ;;
            esac
            
            log "INFO" "Found tool: $tool at $tool_path ($tool_version)"
        fi
    done
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        validation_error "DEPENDENCY_CHECK" "Missing required tools: ${missing_tools[*]}. Please install using: brew install ${missing_tools[*]}"
    fi
    
    # Validate Go can cross-compile to Darwin
    if ! GOOS=darwin GOARCH=arm64 go env GOROOT >/dev/null 2>&1; then
        validation_error "DEPENDENCY_CHECK" "Go cross-compilation not available for Darwin"
    fi
    
    validation_success "DEPENDENCY_CHECK" "All required tools are available and functional"
}

log "INFO" "=== PKG Builder v$SCRIPT_VERSION - Enterprise Grade with Validation ==="
log "INFO" "Building Combined Postman Enterprise + AuthRouter PKG"
log "INFO" "Team Name: ${TEAM_NAME:-[not configured - will be set at install time]}"
log "INFO" "SAML URL: ${SAML_URL:-[not configured - will be set at install time]}"

# Comprehensive argument validation
validate_arguments() {
    log "INFO" "=== Argument Validation ==="
    
    # SAML URL validation - OPTIONAL (warn only)
    if [[ -z "$SAML_URL" ]]; then
        log "WARN" "No SAML URL provided. Service will be installed but not activated until configured via MDM/install-time parameters."
        log "INFO" "  Configuration options:"
        log "INFO" "  - MDM: Deploy Configuration Profile with samlUrl key"
        log "INFO" "  - Command line: Use --saml-url during installation" 
        log "INFO" "  - Jamf: Use script parameters to set configuration"
    else
        if [[ ! "$SAML_URL" =~ ^https?:// ]]; then
            log "WARN" "SAML URL should be a valid HTTP/HTTPS URL: $SAML_URL"
        fi
        
        # SAML URLs should end with /init for proper SAML initialization flow
        if [[ ! "$SAML_URL" =~ /init$ ]]; then
            log "WARN" "SAML URL should end with '/init' for proper SAML initialization: $SAML_URL"
        fi
        
        # Check for common SAML URL patterns
        if [[ ! "$SAML_URL" =~ (identity\.getpostman\.com|sso\.|login\.|auth\.|saml\.|adfs\.|okta\.) ]]; then
            log "WARN" "SAML URL doesn't match expected patterns - verify this is correct: $SAML_URL"
        fi
    fi
    
    # Team name validation - OPTIONAL (warn only)
    if [[ -z "$TEAM_NAME" ]]; then
        log "WARN" "No team name provided. Service will be installed but not activated until configured via MDM/install-time parameters."
        log "INFO" "  Configuration options:"
        log "INFO" "  - MDM: Deploy Configuration Profile with teamName key"
        log "INFO" "  - Command line: Use --team during installation"
        log "INFO" "  - Jamf: Use script parameters to set configuration"
    else
        # Check for valid team name format (basic validation)
        if [[ ${#TEAM_NAME} -lt 2 ]]; then
            log "WARN" "Team name too short (minimum 2 characters recommended): $TEAM_NAME"
        fi
        
        if [[ ${#TEAM_NAME} -gt 100 ]]; then
            log "WARN" "Team name too long (maximum 100 characters recommended): $TEAM_NAME"
        fi
        
        # Check for potentially problematic characters
        if [[ "$TEAM_NAME" == *\"* ]] || [[ "$TEAM_NAME" == *\'* ]] || [[ "$TEAM_NAME" == *\<* ]] || [[ "$TEAM_NAME" == *\>* ]] || [[ "$TEAM_NAME" == *\&* ]]; then
            log "WARN" "Team name contains special characters that may need escaping: $TEAM_NAME"
        fi
    fi
    
    # Output filename validation
    if [[ -n "$CUSTOM_PKG_NAME" ]]; then
        # Check file extension
        if [[ ! "$CUSTOM_PKG_NAME" =~ \.pkg$ ]]; then
            validation_error "ARGUMENT_VALIDATION" "Output filename must end with .pkg: $CUSTOM_PKG_NAME"
        fi
        
        # Check for path traversal attempts
        if [[ "$CUSTOM_PKG_NAME" =~ \.\./|\.\.\\ ]]; then
            validation_error "ARGUMENT_VALIDATION" "Output filename cannot contain path traversal: $CUSTOM_PKG_NAME"
        fi
    fi
    
    # Certificate organization validation
    if [[ -n "$CERT_ORG" ]]; then
        if [[ ${#CERT_ORG} -gt 200 ]]; then
            validation_error "ARGUMENT_VALIDATION" "Certificate organization name too long (maximum 200 characters): $CERT_ORG"
        fi
    fi
    
    # Configuration completeness check
    if [[ -n "$TEAM_NAME" && -z "$SAML_URL" ]]; then
        log "WARN" "Team name provided but SAML URL missing - daemon will not activate automatically"
    fi
    
    if [[ -z "$TEAM_NAME" && -n "$SAML_URL" ]]; then
        log "WARN" "SAML URL provided but team name missing - daemon will not activate automatically"
    fi
    
    validation_success "ARGUMENT_VALIDATION" "All command line arguments are valid"
}

check_dependencies
validate_arguments

# Function to download and validate PKG files
download_pkg() {
    local arch="$1"
    local url="$2"
    local expected_filename_pattern="$3"
    
    log "INFO" "=== Downloading $arch PKG ==="
    
    if [[ "$OFFLINE_MODE" == "true" ]]; then
        log "INFO" "Offline mode enabled - skipping download for $arch"
        return 1
    fi
    
    # Create a temp file for the download
    local temp_pkg
    temp_pkg=$(mktemp "$TEMP_ROOT/postman-pkg-$$-$arch-XXXXXX.pkg") || {
        validation_error "PKG_DOWNLOAD" "Failed to create temp file for $arch download"
    }
    
    log "INFO" "Downloading $arch PKG from: $url"
    log "INFO" "Download destination: $temp_pkg"
    log "INFO" "Final location will be: $SCRIPT_DIR/Postman-Enterprise-latest-$arch.pkg"
    
    # Download with curl (with retry logic)
    local download_attempts=0
    local max_attempts=3
    local download_success=false
    
    while [[ $download_attempts -lt $max_attempts ]] && [[ "$download_success" == "false" ]]; do
        download_attempts=$((download_attempts + 1))
        log "INFO" "Download attempt $download_attempts/$max_attempts..."
        log "DEBUG" "Downloading from: $url"
        log "DEBUG" "Saving to: $temp_pkg"
        
        # Enhanced curl logging - remove --silent in debug mode for more verbose output
        local curl_opts=(-L --connect-timeout 57 --max-time 900 --retry 2 --retry-delay 3 --retry-max-time 300 -C - -A "pm-authrouter" -o "$temp_pkg")
        if [[ "$DEBUG_MODE" == "1" ]]; then
            # Debug mode: verbose output, show progress
            curl_opts+=(--verbose --progress-bar)
            log "DEBUG" "Running curl with debug options: ${curl_opts[*]} \"$url\""
        else
            # Normal mode: silent with error reporting
            curl_opts+=(--silent --show-error)
        fi
        
        log "INFO" "Starting curl download (attempt $download_attempts/$max_attempts)..."
        if log_cmd curl "${curl_opts[@]}" "$url"; then
            download_success=true
            if [[ -f "$temp_pkg" ]]; then
                local file_size=$(stat -f%z "$temp_pkg" 2>/dev/null || stat -c%s "$temp_pkg" 2>/dev/null || echo "unknown")
                local file_size_mb=$(( file_size / 1024 / 1024 ))
                log "SUCCESS" "Download completed: $(basename "$temp_pkg") (${file_size_mb}MB / $file_size bytes)"
                log "INFO" "Downloaded to: $temp_pkg"
            fi
        else
            local curl_exit=$?
            log "WARN" "Download attempt $download_attempts failed (curl exit code: $curl_exit)"
            log "DEBUG" "Failed download URL: $url"
            log "DEBUG" "Failed download destination: $temp_pkg"
            if [[ -f "$temp_pkg" && -s "$temp_pkg" ]]; then
                local partial_size=$(stat -f%z "$temp_pkg" 2>/dev/null || stat -c%s "$temp_pkg" 2>/dev/null || echo "unknown")
                local partial_mb=$(( partial_size / 1024 / 1024 ))
                log "DEBUG" "Partial file exists: $(basename "$temp_pkg") (${partial_mb}MB / $partial_size bytes)"
            else
                log "DEBUG" "No partial file created"
            fi
            if [[ $download_attempts -lt $max_attempts ]]; then
                log "INFO" "Retrying download in 5 seconds..."
                sleep 5
            fi
        fi
    done
    
    if [[ "$download_success" == "false" ]]; then
        rm -f "$temp_pkg"
        log "ERROR" "Failed to download $arch PKG after $max_attempts attempts"
        return 1
    fi
    
    # Validate downloaded file (Fix 6: Use constants instead of hardcoded numbers)
    local download_size=$(stat -f%z "$temp_pkg" 2>/dev/null || stat -c%s "$temp_pkg")
    local min_download_size=$((MIN_DOWNLOAD_SIZE_MB * 1024 * 1024))
    if [[ $download_size -lt $min_download_size ]]; then
        rm -f "$temp_pkg"
        log "ERROR" "Downloaded $arch PKG too small: $(($download_size/1024/1024))MB (minimum: ${MIN_DOWNLOAD_SIZE_MB}MB)"
        return 1
    fi
    
    # PKG integrity validation - ensure it can be expanded
    local test_expand_dir
    test_expand_dir=$(mktemp -d "$TEMP_ROOT/pkg-integrity-test-$$-XXXXXX") || {
        rm -f "$temp_pkg"
        validation_error "PKG_DOWNLOAD" "Failed to create temp directory for PKG integrity test"
    }
    
    # pkgutil requires non-existent destination directory
    local expand_dest="$test_expand_dir/expand"
    local expand_err
    if ! expand_err=$(pkgutil --expand "$temp_pkg" "$expand_dest" 2>&1); then
        log "ERROR" "pkgutil --expand failed: $expand_err"
        rm -rf "$test_expand_dir"
        rm -f "$temp_pkg"
        log "ERROR" "Downloaded $arch PKG is corrupted and cannot be expanded"
        return 1
    fi
    rm -rf "$test_expand_dir"
    log "INFO" "PKG integrity validation passed"
    
    # Basic PKG validation
    if ! pkgutil --check-signature "$temp_pkg" >/dev/null 2>&1; then
        log "WARN" "Downloaded $arch PKG signature validation failed - this may be expected for enterprise builds"
    fi
    
    # Try to extract a more descriptive filename using HTTP headers or file inspection
    local final_filename="Postman-Enterprise-latest-$arch.pkg"
    
    # Move to final location with descriptive name
    local final_path="$SCRIPT_DIR/$final_filename"
    if ! mv "$temp_pkg" "$final_path"; then
        rm -f "$temp_pkg"
        validation_error "PKG_DOWNLOAD" "Failed to move downloaded $arch PKG to final location: $final_path"
    fi
    
    debug_file_op "WRITE" "$final_path" "PKG download completed"
    log "INFO" "$arch PKG downloaded successfully: $(basename "$final_path") ($(($download_size/1024/1024))MB)"
    log "INFO" "Final PKG location: $final_path"
    
    # Return the path for use
    echo "$final_path"
}

# Find existing PKGs or download if missing
ARM64_PKG=""
INTEL_PKG=""

log "INFO" "=== PKG Discovery and Download Phase ==="

# Enhanced PKG discovery function with flexible pattern matching
find_best_pkg() {
    local arch_pattern="$1"  # "arm64" or "x64"
    local found_pkgs=()
    
    # Try multiple naming patterns to handle different PKG sources
    local patterns=(
        "$SCRIPT_DIR/Postman-Enterprise-*-${arch_pattern}.pkg"           # Downloaded format
        "$SCRIPT_DIR/Postman Enterprise*${arch_pattern}*.pkg"            # Official format with spaces
        "$SCRIPT_DIR/Postman_Enterprise*${arch_pattern}*.pkg"            # Underscore variant
        "$SCRIPT_DIR/postman-enterprise-*-${arch_pattern}.pkg"           # Lowercase variant
    )
    
    # Additional patterns for Intel (handle both x64 and x86_64)
    if [[ "$arch_pattern" == "x64" ]]; then
        patterns+=(
            "$SCRIPT_DIR/Postman-Enterprise-*-x86_64.pkg"
            "$SCRIPT_DIR/Postman Enterprise*x86_64*.pkg"
            "$SCRIPT_DIR/Postman_Enterprise*x86_64*.pkg"
            "$SCRIPT_DIR/postman-enterprise-*-x86_64.pkg"
        )
    fi
    
    # Collect all matching files from all patterns
    for pattern in "${patterns[@]}"; do
        for pkg in $pattern; do
            [[ ! -f "$pkg" ]] && continue
            # Skip our own SAML outputs to avoid recursion
            [[ "$(basename "$pkg")" == *"-saml"* || "$(basename "$pkg")" == *"-SAML"* ]] && continue
            found_pkgs+=("$pkg")
        done
    done
    
    # Return nothing if no PKGs found
    [[ ${#found_pkgs[@]} -eq 0 ]] && return 1
    
    # If only one PKG found, return it
    [[ ${#found_pkgs[@]} -eq 1 ]] && { echo "${found_pkgs[0]}"; return 0; }
    
    # Multiple PKGs found - pick the newest by modification time
    local newest_pkg=""
    local newest_time=0
    
    for pkg in "${found_pkgs[@]}"; do
        local mtime=$(stat -f%m "$pkg" 2>/dev/null || stat -c%Y "$pkg" 2>/dev/null || echo 0)
        if [[ $mtime -gt $newest_time ]]; then
            newest_time=$mtime
            newest_pkg="$pkg"
        fi
    done
    
    if [[ -n "$newest_pkg" ]]; then
        if [[ ${#found_pkgs[@]} -gt 1 ]]; then
            log "INFO" "Multiple ${arch_pattern} PKGs found, selected newest: $(basename "$newest_pkg")"
        fi
        echo "$newest_pkg"
        return 0
    fi
    
    return 1
}

# First, try to find existing PKGs using enhanced discovery
if ARM64_PKG=$(find_best_pkg "arm64"); then
    log "INFO" "Found existing ARM64 PKG: $(basename "$ARM64_PKG")"
fi

if INTEL_PKG=$(find_best_pkg "x64"); then
    log "INFO" "Found existing Intel PKG: $(basename "$INTEL_PKG")"
fi

# Enhanced architecture detection with Rosetta support
detect_architecture() {
    local process_arch=$(uname -m)
    local hardware_arch="$process_arch"
    local running_rosetta=false
    
    # On macOS, detect if we're running under Rosetta on Apple Silicon
    if [[ "$(uname -s)" == "Darwin" ]]; then
        # Check if running under Rosetta (process is x86_64 but hardware supports ARM64)
        if [[ "$process_arch" == "x86_64" ]]; then
            # Check if hardware actually supports ARM64
            if sysctl -n hw.optional.arm64 2>/dev/null | grep -q "1"; then
                hardware_arch="arm64"
                running_rosetta=true
                log "INFO" "Detected: Running x86_64 process under Rosetta on ARM64 hardware"
            fi
        fi
        
        # Verify Rosetta detection with sysctl.proc_translated if available
        if [[ "$running_rosetta" == "true" ]]; then
            local translated=$(sysctl -n sysctl.proc_translated 2>/dev/null || echo "0")
            if [[ "$translated" == "1" ]]; then
                log "INFO" "Rosetta translation confirmed (sysctl.proc_translated=1)"
            fi
        fi
    fi
    
    # Export detected information
    echo "$hardware_arch"
    
    if [[ "$running_rosetta" == "true" ]]; then
        log "INFO" "Hardware architecture: $hardware_arch (ARM64 native preferred)"
        log "INFO" "Process architecture: $process_arch (running under Rosetta)"
    else
        log "INFO" "System architecture: $hardware_arch"
    fi
}

# Detect current system architecture for intelligent downloading
SYSTEM_ARCH=$(detect_architecture)
HARDWARE_ARCH="$SYSTEM_ARCH"  # For clarity in download logic

# Only attempt downloads if not in offline mode
if [[ "$OFFLINE_MODE" != "true" ]]; then
    log "INFO" "Online mode - checking for missing PKGs to download..."
    
    # Download missing PKGs based on hardware architecture (Rosetta-aware)
    if [[ -z "$ARM64_PKG" ]]; then
        if [[ "$HARDWARE_ARCH" == "arm64" ]] || [[ "$HARDWARE_ARCH" == "aarch64" ]]; then
            # Prioritize ARM64 on Apple Silicon (including when running under Rosetta)
            log "INFO" "ARM64 hardware detected - downloading ARM64 PKG..."
            if ARM64_PKG=$(download_pkg "arm64" "$ARM64_PKG_URL" "arm64"); then
                log "INFO" "ARM64 PKG download completed successfully"
            else
                log "WARN" "ARM64 PKG download failed"
            fi
        fi
    fi

    if [[ -z "$INTEL_PKG" ]]; then
        # Only download Intel on actual Intel hardware, not as fallback on ARM
        if [[ "$HARDWARE_ARCH" == "x86_64" ]]; then
            log "INFO" "Intel hardware detected - downloading Intel PKG..."
            if INTEL_PKG=$(download_pkg "x64" "$INTEL_PKG_URL" "x64"); then
                log "INFO" "Intel PKG download completed successfully"
            else
                log "WARN" "Intel PKG download failed"
            fi
        elif [[ -z "$ARM64_PKG" ]]; then
            # Fallback: download Intel only if no ARM64 PKG available on ARM hardware
            log "INFO" "No ARM64 PKG available, downloading Intel PKG as fallback..."
            if INTEL_PKG=$(download_pkg "x64" "$INTEL_PKG_URL" "x64"); then
                log "INFO" "Intel PKG (fallback) download completed successfully"
            else
                log "WARN" "Intel PKG (fallback) download failed"
            fi
        fi
    fi
else
    log "INFO" "Offline mode enabled - skipping all download attempts"
    log "INFO" "Using only PKGs found during discovery phase"
fi

# Final validation - ensure we have at least one PKG
if [[ -z "$ARM64_PKG" && -z "$INTEL_PKG" ]]; then
    log_error "No Postman Enterprise PKG available and downloads failed/disabled"
    log_error "Options:"
    log_error "  1. Place Postman-Enterprise-*-arm64.pkg or Postman-Enterprise-*-x64.pkg in $SCRIPT_DIR"
    log_error "  2. Enable downloads by removing --offline flag or OFFLINE_MODE=true"
    log_error "  3. Check network connectivity and try again"
    exit 1
fi

# Report final status
log ""
log "=== PKG Status Summary ==="
if [[ -n "$ARM64_PKG" ]]; then
    log "INFO" "ARM64 PKG ready: $(basename "$ARM64_PKG")"
fi
if [[ -n "$INTEL_PKG" ]]; then
    log "INFO" "Intel PKG ready: $(basename "$INTEL_PKG")"
fi
log ""

# Phase 2: Original PKG Validation
validate_original_pkg() {
    local pkg_path="$1"
    local arch="$2"
    
    log "INFO" "=== Phase 2A: Original PKG Validation ($arch) ==="
    
    # Basic PKG integrity check
    if [[ ! -f "$pkg_path" ]]; then
        validation_error "ORIGINAL_PKG" "PKG file not found: $pkg_path"
    fi
    
    local pkg_size=$(stat -f%z "$pkg_path" 2>/dev/null || stat -c%s "$pkg_path")
    local min_pkg_size=$((MIN_PKG_SIZE_KB * 1024))
    if [[ $pkg_size -lt $min_pkg_size ]]; then
        validation_error "ORIGINAL_PKG" "PKG file too small: $(($pkg_size/1024))KB (minimum: ${MIN_PKG_SIZE_KB}KB)"
    fi
    
    # Validate PKG can be expanded
    local temp_validate_root
    temp_validate_root=$(mktemp -d "$TEMP_ROOT/pkg-validate-$$-XXXXXX") || {
        validation_error "ORIGINAL_PKG" "Failed to create validation temp directory"
    }
    
    # pkgutil requires non-existent destination directory
    local expand_dest="$temp_validate_root/expand"
    local expand_err
    if ! expand_err=$(pkgutil --expand "$pkg_path" "$expand_dest" 2>&1); then
        log "ERROR" "pkgutil --expand failed: $expand_err"
        rm -rf "$temp_validate_root"
        validation_error "ORIGINAL_PKG" "PKG file cannot be expanded (corrupted)"
    fi
    
    # Check for required components
    if [[ ! -f "$expand_dest/Distribution" ]]; then
        rm -rf "$temp_validate_root"
        validation_error "ORIGINAL_PKG" "PKG missing Distribution file"
    fi
    
    local component_count=$(find "$expand_dest" -name "*.pkg" | wc -l)
    if [[ $component_count -eq 0 ]]; then
        rm -rf "$temp_validate_root"
        validation_error "ORIGINAL_PKG" "PKG contains no component packages"
    fi
    
    debug_file_op "READ" "$pkg_path" "Original PKG validation"
    rm -rf "$temp_validate_root"
    
    log "INFO" "Original PKG validated - Size: $(($pkg_size/1024/1024))MB, Components: $component_count"
    validation_success "ORIGINAL_PKG" "Original PKG structure is valid and complete"
}

# Phase 3: Source Component Validation  
validate_binary_component() {
    local binary_path="$1"
    local arch="$2"
    
    log "INFO" "=== Phase 3A: Binary Component Validation ($arch) ==="
    
    if [[ ! -f "$binary_path" ]]; then
        validation_error "SOURCE_COMPONENTS" "AuthRouter binary missing: $binary_path"
    fi
    
    # Check if it's a valid Mach-O executable
    if ! file "$binary_path" | grep -q "Mach-O.*executable"; then
        validation_error "SOURCE_COMPONENTS" "AuthRouter binary is not a valid Mach-O executable"
    fi
    
    # Validate architecture matches
    local binary_arch=$(file "$binary_path" | grep -o "arm64\|x86_64" | head -1)
    case "$arch" in
        "ARM64")
            if [[ "$binary_arch" != "arm64" ]]; then
                validation_error "SOURCE_COMPONENTS" "Architecture mismatch: expected arm64, got $binary_arch"
            fi
            ;;
        "Intel")
            if [[ "$binary_arch" != "x86_64" ]]; then
                validation_error "SOURCE_COMPONENTS" "Architecture mismatch: expected x86_64, got $binary_arch"
            fi
            ;;
    esac
    
    # Validate binary size (Go binaries should be at least a few MB)
    local binary_size=$(stat -f%z "$binary_path" 2>/dev/null || stat -c%s "$binary_path")
    local min_binary_size=$((MIN_BINARY_SIZE_KB * 1024))
    if [[ $binary_size -lt $min_binary_size ]]; then
        validation_error "SOURCE_COMPONENTS" "Binary too small: $(($binary_size/1024))KB (minimum: ${MIN_BINARY_SIZE_KB}KB - likely build failed)"
    fi
    
    debug_file_op "READ" "$binary_path" "AuthRouter binary validation"
    log "INFO" "Binary validated - Architecture: $binary_arch, Size: $(($binary_size/1024/1024))MB"
    validation_success "SOURCE_COMPONENTS" "AuthRouter binary is valid and correctly compiled for $arch"
}

# Function to build PKG for a specific architecture
build_pkg_for_arch() {
    local ORIGINAL_PKG="$1"
    local ARCH="$2"
    local GOARCH="$3"
    
    log "INFO" "=== Processing $ARCH package ==="
    
    # Phase 2A: Validate original PKG
    validate_original_pkg "$ORIGINAL_PKG" "$ARCH"
    
    # Extract version from original package name and generate output filename
    local PKG_BASENAME=$(basename "$ORIGINAL_PKG" .pkg)
    local PKG_NAME="${CUSTOM_PKG_NAME:-${PKG_BASENAME}-saml.pkg}"
    
    # Extract version from PKG using pkgutil
    log "Extracting version from original PKG..."
    local PKG_VERSION=$(pkgutil --pkg-info-plist com.postmanlabs.enterprise.mac "$ORIGINAL_PKG" 2>/dev/null | grep -A1 'CFBundleVersion' | tail -1 | sed 's/.*<string>\(.*\)<\/string>.*/\1/' | head -1)
    if [ -z "$PKG_VERSION" ]; then
        # Try alternative method - expand and read from Distribution
        local TEMP_EXPAND
        TEMP_EXPAND=$(mktemp -d "$TEMP_ROOT/pkg_expand_$$_XXXXXX") || {
            validation_error "VERSION_EXTRACTION" "Failed to create secure temporary directory for version extraction"
        }
        # pkgutil requires non-existent destination directory
        local EXPAND_DIR="$TEMP_EXPAND/expand"
        if pkgutil --expand "$ORIGINAL_PKG" "$EXPAND_DIR" >/dev/null 2>&1; then
            if [ -f "$EXPAND_DIR/Distribution" ]; then
                PKG_VERSION=$(grep -o 'version="[0-9][^"]*"' "$EXPAND_DIR/Distribution" | head -1 | sed 's/version="//;s/"//')
            fi
        fi
        rm -rf "$TEMP_EXPAND"
    fi
    if [ -z "$PKG_VERSION" ]; then
        # Fallback to extracting from filename
        PKG_VERSION=$(echo "$PKG_BASENAME" | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1)
        if [ -z "$PKG_VERSION" ]; then
            PKG_VERSION="11.58.0"
        fi
    fi
    log "Using version: $PKG_VERSION"
    
    log "Found original PKG: $(basename "$ORIGINAL_PKG")"
    log "Output will be: $(basename "$PKG_NAME")"
    
    # Create secure build directory
    local BUILD_DIR
    BUILD_DIR=$(mktemp -d "$TEMP_ROOT/postman-pkg-$$-$ARCH-XXXXXX") || {
        validation_error "BUILD_SETUP" "Failed to create secure build directory"
    }
    
    debug_file_op "WRITE" "$BUILD_DIR" "Build directory created"
    
    log ""
    log "INFO" "=== Step 1: Building AuthRouter Binary for $ARCH ==="
    cd "$PROJECT_ROOT" || {
        validation_error "BUILD_SETUP" "Failed to change to project root: $PROJECT_ROOT"
    }
    
    if ! log_cmd env GOOS=darwin GOARCH=$GOARCH go build -ldflags="-w" -o "$SCRIPT_DIR/pm-authrouter-$ARCH" ./cmd/pm-authrouter; then
        validation_error "BINARY_BUILD" "Failed to build AuthRouter binary for $ARCH"
    fi
    
    # Phase 3A: Validate binary component  
    validate_binary_component "$SCRIPT_DIR/pm-authrouter-$ARCH" "$ARCH"
    
    log ""
    log "=== Step 2: Extracting Original PKG Structure ==="
    cd "$SCRIPT_DIR" || {
        log_error "Failed to change to script directory: $SCRIPT_DIR"
        return 1
    }
    
    # Clean up previous extractions
    rm -rf "extracted_pkg_$ARCH" "combined_root_$ARCH"
    
    # Extract original PKG
    log "Extracting original PKG..."
    if ! pkgutil --expand "$ORIGINAL_PKG" "./extracted_pkg_$ARCH/"; then
        log_error "Failed to expand original PKG: $ORIGINAL_PKG"
        return 1
    fi

    # Extract application files from Payload
    log "Extracting Postman.app from Payload..."
    cd "./extracted_pkg_$ARCH/com.postmanlabs.enterprise.mac.pkg" || {
        log_error "Failed to find PKG component directory"
        return 1
    }
    
    rm -rf extracted_files
    mkdir -p extracted_files || {
        log_error "Failed to create extraction directory"
        return 1
    }
    
    if ! (cat Payload | gzip -d | (cd extracted_files && cpio -i)); then
        log_error "Failed to extract Payload from original PKG"
        return 1
    fi
    
    log ""
    log "=== Step 3: Creating Combined Package Root ==="
    cd "$SCRIPT_DIR" || {
        log_error "Failed to change back to script directory"
        return 1
    }
    
    # Create combined package root directory
    mkdir -p "combined_root_$ARCH/Applications"
    mkdir -p "combined_root_$ARCH/Library/LaunchDaemons"
    mkdir -p "combined_root_$ARCH/usr/local/bin/postman"
    mkdir -p "combined_root_$ARCH/var/log/postman"
    
    # Copy Postman Enterprise.app from extracted files
    cp -R "extracted_pkg_$ARCH/com.postmanlabs.enterprise.mac.pkg/extracted_files/Applications/Postman Enterprise.app" "combined_root_$ARCH/Applications/"
    
    # Copy AuthRouter binary to /usr/local/bin/postman
    cp "pm-authrouter-$ARCH" "combined_root_$ARCH/usr/local/bin/postman/pm-authrouter"
    chmod +x "combined_root_$ARCH/usr/local/bin/postman/pm-authrouter"
    
    # Copy stable certificates from /ssl/ directory
    cp "$SSL_DIR/identity.getpostman.com.crt" "combined_root_$ARCH/usr/local/bin/postman/"
    cp "$SSL_DIR/identity.getpostman.com.key" "combined_root_$ARCH/usr/local/bin/postman/"
    chmod 644 "combined_root_$ARCH/usr/local/bin/postman/identity.getpostman.com.crt"
    chmod 600 "combined_root_$ARCH/usr/local/bin/postman/identity.getpostman.com.key"
    
    # Create inline MDM profile generator script
    cat > "combined_root_$ARCH/usr/local/bin/postman/generate_mdm_profile.sh" << MDM_PROFILE_GENERATOR
#!/bin/bash

# Generate MDM Configuration Profile for Postman AuthRouter Certificate Trust
# This creates a .mobileconfig file that can be deployed via Jamf, Workspace ONE, etc.

set -e

CERT_DIR="/usr/local/bin/postman"
CERT_PATH="\${1:-\$CERT_DIR/identity.getpostman.com.crt}"
OUTPUT_PATH="\${2:-\$CERT_DIR/PostmanAuthRouterCertificate.mobileconfig}"
CERT_ORG="$CERT_ORG"

# Check if certificate exists
if [ ! -f "\$CERT_PATH" ]; then
    echo "ERROR: Certificate not found at \$CERT_PATH"
    echo "The package installation may be corrupted."
    exit 1
fi

# Verify certificate is valid
if ! openssl x509 -in "\$CERT_PATH" -noout -checkend 2592000 >/dev/null 2>&1; then
    echo "WARNING: Certificate is expiring within 30 days"
    echo "Please regenerate and redeploy the package"
fi

# Use the shared MDM profile generation logic
# Read certificate and encode it for the profile
CERT_BASE64=\$(cat "\$CERT_PATH" | grep -v "BEGIN CERTIFICATE" | grep -v "END CERTIFICATE" | tr -d '\\n')

# Generate UUID for profile
PROFILE_UUID=\$(uuidgen)
PAYLOAD_UUID=\$(uuidgen)

# Get certificate SHA-1 fingerprint for trust settings
CERT_SHA1=\$(openssl x509 -in "\$CERT_PATH" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')

$(cat << 'PROFILE_TEMPLATE'
# Create the configuration profile with certificate and trust settings
cat > "$OUTPUT_PATH" << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <!-- Install the certificate -->
        <dict>
            <key>PayloadCertificateFileName</key>
            <string>identity.getpostman.com.crt</string>
            <key>PayloadContent</key>
            <data>
'$CERT_BASE64'
            </data>
            <key>PayloadDescription</key>
            <string>Installs the Postman AuthRouter SSL certificate for SAML enforcement</string>
            <key>PayloadDisplayName</key>
            <string>Postman AuthRouter Certificate</string>
            <key>PayloadIdentifier</key>
            <string>com.postman.authrouter.certificate.'$PAYLOAD_UUID'</string>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadUUID</key>
            <string>'$PAYLOAD_UUID'</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>AllowAllAppsAccess</key>
            <true/>
        </dict>
        <!-- Configure trust settings for the certificate -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.security.certificatetrust</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.postman.authrouter.trust.$(uuidgen)</string>
            <key>PayloadUUID</key>
            <string>$(uuidgen)</string>
            <key>PayloadDisplayName</key>
            <string>Certificate Trust Settings</string>
            <key>PayloadDescription</key>
            <string>Trust settings for Postman AuthRouter certificate</string>
            <key>PayloadOrganization</key>
            <string>Postman</string>
            <key>TrustedCertificates</key>
            <array>
                <dict>
                    <key>SHA1Fingerprint</key>
                    <data>$(echo -n "$CERT_SHA1" | xxd -r -p | base64)</data>
                    <key>TrustSettings</key>
                    <dict>
                        <key>kSecTrustSettingsAllowedError</key>
                        <integer>-2147408896</integer>
                        <key>kSecTrustSettingsResult</key>
                        <integer>1</integer>
                    </dict>
                </dict>
            </array>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>This profile installs the Postman AuthRouter SSL certificate as a trusted root certificate to enable SAML enforcement for identity.getpostman.com. This is required for the Postman Enterprise SAML integration to function properly.</string>
    <key>PayloadDisplayName</key>
    <string>Postman Enterprise AuthRouter Certificate Trust</string>
    <key>PayloadIdentifier</key>
    <string>com.postman.authrouter.certificate</string>
    <key>PayloadOrganization</key>
    <string>Postman</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadScope</key>
    <string>System</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>'$PROFILE_UUID'</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
EOF
PROFILE_TEMPLATE
)

echo "MDM Configuration Profile created: \$OUTPUT_PATH"
echo ""
echo "Certificate Details:"
echo "===================="
openssl x509 -in "\$CERT_PATH" -noout -subject -issuer -dates | sed 's/^/  /'
echo "  SHA-1: \$CERT_SHA1"
MDM_PROFILE_GENERATOR
    
    chmod +x "combined_root_$ARCH/usr/local/bin/postman/generate_mdm_profile.sh"
    
    # Note: Certificate trust is handled via MDM profile, not via helper scripts
    
    # Create uninstall script
    cat > "combined_root_$ARCH/usr/local/bin/postman/uninstall.sh" << 'UNINSTALL_SCRIPT'
#!/bin/bash

# Postman AuthRouter Uninstaller for macOS
# This script removes all components installed by the PKG

echo "Postman AuthRouter Uninstaller"
echo "=================================="
echo ""

# Check for root
if [ "$EUID" -ne 0 ]; then 
    echo "This script must be run as root (use sudo)"
    exit 1
fi

# Enterprise automation: Non-interactive by default
# Check for INTERACTIVE mode to enable prompts (opposite of before)
if [[ "${INTERACTIVE:-false}" == "true" ]] || [[ "$1" == "--interactive" ]] || [[ "$1" == "-i" ]]; then
    echo "This will remove:"
    echo "  - AuthRouter daemon"
    echo "  - LaunchDaemon configuration"
    echo "  - SSL certificates from trust store"
    echo "  - Generated certificate files"
    echo "  - Hosts file modifications"
    echo ""
    read -p "Continue? (y/N) " -n 1 -r
    echo ""

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Uninstall cancelled"
        echo "To run without prompts: sudo /usr/local/bin/postman/uninstall.sh"
        exit 0
    fi
else
    echo "Running in non-interactive mode - proceeding with removal..."
    echo "This will remove:"
    echo "  - AuthRouter daemon"
    echo "  - LaunchDaemon configuration" 
    echo "  - SSL certificates from trust store"
    echo "  - Generated certificate files"
    echo "  - Hosts file modifications"
    echo ""
    echo "Note: Use --interactive flag to enable confirmation prompts"
fi

echo ""
echo "Stopping daemon..."

# Stop and unload the daemon
if launchctl list | grep -q com.postman.pm-authrouter; then
    launchctl unload /Library/LaunchDaemons/com.postman.pm-authrouter.plist 2>/dev/null
    echo "   Daemon stopped"
else
    echo "  - Daemon not running"
fi

echo "Removing files..."

# Remove LaunchDaemon plist
if [ -f /Library/LaunchDaemons/com.postman.pm-authrouter.plist ]; then
    rm -f /Library/LaunchDaemons/com.postman.pm-authrouter.plist
    echo "   LaunchDaemon configuration removed"
fi

# Remove daemon binary and certificates
if [ -d /usr/local/bin/postman ]; then
    rm -rf /usr/local/bin/postman
    echo "   Daemon and certificate files removed"
fi

# Remove log directory
if [ -d /var/log/postman ]; then
    rm -rf /var/log/postman
    echo "   Log files removed"
fi

echo "Removing certificate from trust store..."

# Remove certificate from system keychain
if security find-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain >/dev/null 2>&1; then
    security delete-certificate -c "identity.getpostman.com" /Library/Keychains/System.keychain 2>/dev/null
    echo "   Certificate removed from trust store"
else
    echo "  - Certificate not found in trust store"
fi

echo "Cleaning hosts file..."

# Remove hosts file entry
if grep -q "identity.getpostman.com" /etc/hosts; then
    # Create backup
    cp /etc/hosts /etc/hosts.backup.$(date +%Y%m%d%H%M%S)
    # Remove the line
    sed -i '' '/identity\.getpostman\.com/d' /etc/hosts
    echo "   Hosts file cleaned (backup saved)"
else
    echo "  - No hosts file modifications found"
fi

echo ""
echo "Uninstall complete!"
echo ""
echo "Note: Postman Enterprise.app was NOT removed."
echo "To remove Postman, drag it from /Applications to Trash."
UNINSTALL_SCRIPT
    
    chmod +x "combined_root_$ARCH/usr/local/bin/postman/uninstall.sh"

    log ""
    log "=== Step 4: Creating LaunchDaemon Configuration ==="
    
    # Create LaunchDaemon plist with command-line arguments (Fix 8: XML escaping)
    local escaped_team_name=""
    local escaped_saml_url=""
    
    if [[ -n "$TEAM_NAME" ]]; then
        escaped_team_name=$(xml_escape "$TEAM_NAME")
    fi
    
    if [[ -n "$SAML_URL" ]]; then
        escaped_saml_url=$(xml_escape "$SAML_URL") 
    fi
    
    cat > "combined_root_$ARCH/Library/LaunchDaemons/com.postman.pm-authrouter.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.postman.pm-authrouter</string>
    
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/postman/pm-authrouter</string>$([ -n "$TEAM_NAME" ] && echo "
        <string>--team</string>
        <string>$escaped_team_name</string>")$([ -n "$SAML_URL" ] && echo "
        <string>--saml-url</string>
        <string>$escaped_saml_url</string>")
    </array>
    
    <key>RunAtLoad</key>
    <true/>
    
    <key>KeepAlive</key>
    <true/>
    
    <key>ThrottleInterval</key>
    <integer>60</integer>
    
    <key>SessionCreate</key>
    <true/>
    
    <key>StandardOutPath</key>
    <string>/var/log/postman/pm-authrouter.log</string>
    
    <key>StandardErrorPath</key>
    <string>/var/log/postman/pm-authrouter.error.log</string>
    
    <key>WorkingDirectory</key>
    <string>/usr/local/bin/postman</string>
    
    <key>UserName</key>
    <string>root</string>
</dict>
</plist>
EOF

    log ""
    log "=== Step 5: Creating Combined Installation Scripts ==="
    
    # Create postinstall script that handles both Postman and AuthRouter
    cat > "$BUILD_DIR/postinstall" << 'POSTINSTALL'
#!/bin/bash

echo "=== Postman Enterprise + AuthRouter Installation ==="

# Create log directory and binary directory
mkdir -p /var/log/postman
chmod 755 /var/log/postman
mkdir -p /usr/local/bin/postman
chmod 755 /usr/local/bin/postman

# Set permissions for AuthRouter
chmod 755 "/usr/local/bin/postman/pm-authrouter"
chmod 644 /Library/LaunchDaemons/com.postman.pm-authrouter.plist

# Generate 10-year certificates if they don't exist
CERT_PATH="/usr/local/bin/postman/identity.getpostman.com.crt"
KEY_PATH="/usr/local/bin/postman/identity.getpostman.com.key"

if [ ! -f "$CERT_PATH" ] || [ ! -f "$KEY_PATH" ]; then
    echo "ERROR: SSL certificates not found!"
    echo "Expected certificate at: $CERT_PATH"
    echo "Expected private key at: $KEY_PATH"
    echo "The package installation may be corrupted."
    exit 1
fi

# Set proper permissions on stable certificates from package
chmod 644 "$CERT_PATH"
chmod 600 "$KEY_PATH"
chown root:wheel "$CERT_PATH" "$KEY_PATH"

echo "Using stable certificates from package"

# Note: Certificate trust must be established via MDM deployment
echo "Certificate generated. Trust must be established via MDM profile deployment."

# Certificate trust is handled via MDM profile deployment only
# No helper scripts needed as modern macOS requires MDM for headless trust

# Verify Postman Enterprise.app was installed
if [ -d "/Applications/Postman Enterprise.app" ]; then
    echo "Postman Enterprise.app installed successfully"
else
    echo "Warning: Postman Enterprise.app not found"
fi

# Check for runtime parameters
# Method 1: Via config file (works with SIP)
if [ -n "$POSTMAN_SAML_CONFIG_FILE" ] && [ -f "$POSTMAN_SAML_CONFIG_FILE" ]; then
    source "$POSTMAN_SAML_CONFIG_FILE"
    RUNTIME_TEAM="${INSTALLER_TEAM_NAME:-}"
    RUNTIME_SAML="${INSTALLER_SAML_URL:-}"
else
    # Method 2: Via launchctl (may not work with SIP)
    RUNTIME_TEAM="$(launchctl getenv INSTALLER_TEAM_NAME 2>/dev/null || echo '')"
    RUNTIME_SAML="$(launchctl getenv INSTALLER_SAML_URL 2>/dev/null || echo '')"
fi

# If runtime parameters provided, update the plist
PLIST="/Library/LaunchDaemons/com.postman.pm-authrouter.plist"
if [ -n "$RUNTIME_TEAM" ] || [ -n "$RUNTIME_SAML" ]; then
    echo "Applying runtime configuration..."
    
    # Read current configuration
    CURRENT_TEAM=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:2" "$PLIST" 2>/dev/null)
    CURRENT_SAML=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:4" "$PLIST" 2>/dev/null)
    
    # Update with runtime values if provided
    if [ -n "$RUNTIME_TEAM" ]; then
        if [ -n "$CURRENT_TEAM" ]; then
            /usr/libexec/PlistBuddy -c "Set :ProgramArguments:2 '$RUNTIME_TEAM'" "$PLIST"
        else
            # Add team arguments if not present
            /usr/libexec/PlistBuddy -c "Add :ProgramArguments:1 string '--team'" "$PLIST"
            /usr/libexec/PlistBuddy -c "Add :ProgramArguments:2 string '$RUNTIME_TEAM'" "$PLIST"
        fi
    fi
    
    if [ -n "$RUNTIME_SAML" ]; then
        if [ -n "$CURRENT_SAML" ]; then
            /usr/libexec/PlistBuddy -c "Set :ProgramArguments:4 '$RUNTIME_SAML'" "$PLIST"
        else
            # Add SAML arguments if not present
            /usr/libexec/PlistBuddy -c "Add :ProgramArguments:3 string '--saml-url'" "$PLIST"
            /usr/libexec/PlistBuddy -c "Add :ProgramArguments:4 string '$RUNTIME_SAML'" "$PLIST"
        fi
    fi
fi

# Read final configuration
TEAM=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:2" "$PLIST" 2>/dev/null)
SAML=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:4" "$PLIST" 2>/dev/null)

echo "Configuration detected:"
echo "  Team: ${TEAM:-[not configured]}"
echo "  SAML URL: ${SAML:-[not configured]}"
echo ""

# Note about uninstaller
if [ -f "/usr/local/bin/postman/uninstall.sh" ]; then
    echo "Uninstaller available at: /usr/local/bin/postman/uninstall.sh"
    echo "To uninstall later: sudo /usr/local/bin/postman/uninstall.sh"
    echo ""
fi

# Stop existing daemon if running
if launchctl list | grep -q com.postman.pm-authrouter; then
    echo "Stopping existing daemon..."
    launchctl unload /Library/LaunchDaemons/com.postman.pm-authrouter.plist 2>/dev/null || true
fi

# Only start daemon if configuration is present
if [ -n "$TEAM" ] && [ -n "$SAML" ]; then
    echo "Starting AuthRouter daemon..."
    launchctl load -w /Library/LaunchDaemons/com.postman.pm-authrouter.plist
    
    # Verify it's running
    sleep 2
    if launchctl list | grep -q com.postman.pm-authrouter; then
        echo "AuthRouter daemon is running"
    else
        echo "Warning: Daemon may not have started. Check logs at /var/log/postman/"
    fi
else
    echo "AuthRouter daemon installed but not started (configuration required)"
    echo "To configure and start the daemon later, edit the plist file and run:"
    echo "  sudo launchctl load -w /Library/LaunchDaemons/com.postman.pm-authrouter.plist"
fi

# Generate MDM profile if certificate exists
if [ -f "/usr/local/bin/postman/identity.getpostman.com.crt" ] && [ -f "/usr/local/bin/postman/generate_mdm_profile.sh" ]; then
    echo ""
    echo "Generating MDM Configuration Profile for certificate trust..."
    /usr/local/bin/postman/generate_mdm_profile.sh "/usr/local/bin/postman/identity.getpostman.com.crt" "/usr/local/bin/postman/PostmanAuthRouterCertificate.mobileconfig" 2>/dev/null || true
    
    if [ -f "/usr/local/bin/postman/PostmanAuthRouterCertificate.mobileconfig" ]; then
        echo "MDM profile generated: /usr/local/bin/postman/PostmanAuthRouterCertificate.mobileconfig"
        echo ""
        echo "IMPORTANT: Deploy this configuration profile via your MDM solution"
        echo "           (Jamf, Workspace ONE, Intune, etc.) to trust the certificate"
    fi
fi

echo ""
echo "Installation complete!"
echo ""
echo "Postman Enterprise with AuthRouter is now installed:"
echo "  - Postman Enterprise.app -> /Applications/"
echo "  - AuthRouter daemon -> /usr/local/bin/postman/pm-authrouter"
echo "  - Configuration -> Team: $TEAM, SAML URL: $SAML"
echo ""
echo "Useful commands:"
echo "  View status:  sudo launchctl list | grep postman"
echo "  View logs:    tail -f /var/log/postman/pm-authrouter.log"
echo "  Stop daemon:  sudo launchctl unload -w $PLIST"
echo "  Start daemon: sudo launchctl load -w $PLIST"
echo "  Uninstall:    sudo /usr/local/bin/postman/uninstall.sh"

exit 0
POSTINSTALL

    chmod +x "$BUILD_DIR/postinstall"
    
    log ""
    log "=== Step 6: Building Combined PKG ==="
    
    # Create component PKG
    log "Building component package..."
    if ! pkgbuild \
        --root "combined_root_$ARCH" \
        --scripts "$BUILD_DIR" \
        --identifier "$IDENTIFIER" \
        --version "$PKG_VERSION" \
        --install-location "/" \
        "$BUILD_DIR/component.pkg"; then
        log_error "Failed to build component package"
        return 1
    fi
    
    # Create distribution XML
    cat > "$BUILD_DIR/distribution.xml" << EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>Postman Enterprise with AuthRouter</title>
    <organization>com.postman</organization>
    <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
    <options customize="never" require-scripts="true" rootVolumeOnly="true"/>
    <welcome file="welcome.txt"/>
    <choices-outline>
        <line choice="default">
            <line choice="$IDENTIFIER"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="$IDENTIFIER" visible="false">
        <pkg-ref id="$IDENTIFIER"/>
    </choice>
    <pkg-ref id="$IDENTIFIER" version="$PKG_VERSION" onConclusion="none">component.pkg</pkg-ref>
</installer-gui-script>
EOF

    # Extract welcome message from original PKG and add SAML note
    local TEMP_EXTRACT
    TEMP_EXTRACT=$(mktemp -d "$TEMP_ROOT/pkg_welcome_$$_XXXXXX") || {
        validation_error "WELCOME_EXTRACTION" "Failed to create secure temporary directory for welcome extraction"
    }
    # pkgutil requires non-existent destination directory
    local EXPAND_DIR="$TEMP_EXTRACT/expand"
    pkgutil --expand "$ORIGINAL_PKG" "$EXPAND_DIR" >/dev/null 2>&1
    
    if [ -f "$EXPAND_DIR/Resources/welcome.txt" ]; then
        # Use original welcome message
        cp "$EXPAND_DIR/Resources/welcome.txt" "$BUILD_DIR/welcome.txt"
        
        # Add SAML enforcement note
        echo "" >> "$BUILD_DIR/welcome.txt"
        
        if [ -n "$TEAM_NAME" ] && [ -n "$SAML_URL" ]; then
            echo "This package includes AuthRouter configured for team: $TEAM_NAME" >> "$BUILD_DIR/welcome.txt"
        else
            echo "This package includes an AuthRouter daemon (configuration required for activation)." >> "$BUILD_DIR/welcome.txt"
            echo "To enable AuthRouter, provide --team and --saml-url during installation." >> "$BUILD_DIR/welcome.txt"
        fi
    else
        # Fallback if no welcome.txt found
        cat > "$BUILD_DIR/welcome.txt" << EOF
You are about to install Postman Enterprise $PKG_VERSION.

This package includes an AuthRouter daemon that requires configuration.$([ -n "$TEAM_NAME" ] && [ -n "$SAML_URL" ] && echo "
Configured for team: $TEAM_NAME")$([ -z "$TEAM_NAME" ] || [ -z "$SAML_URL" ] && echo "
Note: To enable AuthRouter, install with command line arguments:
  sudo installer -pkg [package.pkg] -target / -applyChoiceChangesXML [config.xml]
  Or configure the daemon after installation.")
EOF
    fi
    
    rm -rf "$TEMP_EXTRACT"

    # Build final product archive
    log "Creating product archive..."
    local OUTPUT_PATH="$SCRIPT_DIR/$PKG_NAME"
    if ! productbuild \
        --distribution "$BUILD_DIR/distribution.xml" \
        --resources "$BUILD_DIR" \
        --package-path "$BUILD_DIR" \
        "$OUTPUT_PATH"; then
        log_error "Failed to create product archive"
        return 1
    fi
    
# Phase 4: Final PKG Validation
validate_final_pkg() {
    local pkg_path="$1"
    local arch="$2"
    
    log "INFO" "=== Phase 4A: Final PKG Validation ($arch) ==="
    
    if [[ ! -f "$pkg_path" ]]; then
        validation_error "FINAL_PKG" "Final PKG was not created: $pkg_path"
    fi
    
    # Basic integrity check
    local pkg_size=$(stat -f%z "$pkg_path" 2>/dev/null || stat -c%s "$pkg_path")
    local min_pkg_size=$((MIN_PKG_SIZE_KB * 1024))
    if [[ $pkg_size -lt $min_pkg_size ]]; then
        validation_error "FINAL_PKG" "Final PKG too small: $(($pkg_size/1024))KB (minimum: ${MIN_PKG_SIZE_KB}KB)"
    fi
    
    # Size validation (PKG shouldn't be unreasonably large) 
    local max_size=$((MAX_PKG_SIZE_MB * 1024 * 1024))
    if [[ $pkg_size -gt $max_size ]]; then
        validation_error "FINAL_PKG" "Final PKG too large: $(($pkg_size/1024/1024))MB > ${MAX_PKG_SIZE_MB}MB"
    fi
    
    # Validate PKG can be expanded
    local temp_final_root
    temp_final_root=$(mktemp -d "$TEMP_ROOT/final-validate-$$-XXXXXX") || {
        validation_error "FINAL_PKG" "Failed to create final validation temp directory"
    }
    
    # pkgutil requires non-existent destination directory
    local expand_dest="$temp_final_root/expand"
    local expand_err
    if ! expand_err=$(pkgutil --expand "$pkg_path" "$expand_dest" 2>&1); then
        log "ERROR" "pkgutil --expand failed: $expand_err"
        rm -rf "$temp_final_root"
        validation_error "FINAL_PKG" "Final PKG cannot be expanded (corrupted)"
    fi
    
    # Check for required components in final PKG
    if [[ ! -f "$expand_dest/Distribution" ]]; then
        rm -rf "$temp_final_root"
        validation_error "FINAL_PKG" "Final PKG missing Distribution file"
    fi
    
    # Verify our component is included
    local our_component_count=$(find "$expand_dest" -name "component.pkg" | wc -l)
    if [[ $our_component_count -eq 0 ]]; then
        rm -rf "$temp_final_root"
        validation_error "FINAL_PKG" "Final PKG missing our AuthRouter component"
    fi
    
    debug_file_op "READ" "$pkg_path" "Final PKG validation"
    rm -rf "$temp_final_root"
    
    log "INFO" "Final PKG validated - Size: $(($pkg_size/1024/1024))MB"
    validation_success "FINAL_PKG" "Final PKG structure is valid and installable"
}

    # Check final PKG size and validate
    if [ -f "$OUTPUT_PATH" ]; then
        # Phase 4A: Validate final PKG
        validate_final_pkg "$OUTPUT_PATH" "$ARCH"
        
        local PKG_SIZE=$(stat -f%z "$OUTPUT_PATH" 2>/dev/null || stat -c%s "$OUTPUT_PATH")
        local BINARY_SIZE=$(stat -f%z "$SCRIPT_DIR/pm-authrouter-$ARCH" 2>/dev/null || stat -c%s "$SCRIPT_DIR/pm-authrouter-$ARCH" 2>/dev/null || echo 0)
        log ""
        log "SUCCESS" "=== Build Complete for $ARCH ==="
        log "INFO" "Combined PKG created: $PKG_NAME"
        log "INFO" "PKG size: $(( PKG_SIZE / 1024 / 1024 )) MB"
        log ""
        log "This PKG contains:"
        log "INFO" "  - Full Postman Enterprise.app"
        log "INFO" "  - AuthRouter daemon ($(( BINARY_SIZE / 1024 / 1024 )) MB) -> /usr/local/bin/postman/"
        log "INFO" "  - Uninstaller script -> /usr/local/bin/postman/uninstall.sh"
        log "INFO" "  - LaunchDaemon configuration${TEAM_NAME:+ for team: $TEAM_NAME}"
        [[ -n "$SAML_URL" ]] && log "INFO" "  - SAML URL: $SAML_URL"
        log ""
        log "INFO" "Installation commands:"
        log "INFO" "  Basic: sudo installer -pkg \"$PKG_NAME\" -target /"
        log "INFO" "  With runtime config:"
        log "INFO" "    sudo launchctl setenv INSTALLER_TEAM_NAME 'team'"
        log "INFO" "    sudo launchctl setenv INSTALLER_SAML_URL 'https://...'"
        log "INFO" "    sudo installer -pkg \"$PKG_NAME\" -target /"
        log "INFO" "    sudo launchctl unsetenv INSTALLER_TEAM_NAME INSTALLER_SAML_URL"
        log ""
        log "INFO" "Or via Finder:"
        log "INFO" "  Double-click $PKG_NAME (uses build-time config if any)"
        log ""
        log "INFO" "To uninstall later:"
        log "INFO" "  sudo /usr/local/bin/postman/uninstall.sh"
    else
        log_error "Failed to create PKG for $ARCH"
        return 1
    fi
    
    # Clean up temporary files
    rm -f "pm-authrouter-$ARCH"
    rm -rf "combined_root_$ARCH" "extracted_pkg_$ARCH" "$BUILD_DIR"
    
    log ""
    log "Build completed for $ARCH!"
    log ""
}

# Build for each architecture found
if [ -f "$ARM64_PKG" ]; then
    build_pkg_for_arch "$ARM64_PKG" "ARM64" "arm64"
fi

if [ -f "$INTEL_PKG" ]; then
    build_pkg_for_arch "$INTEL_PKG" "Intel" "amd64"
fi

# Generate MDM profile ONCE (works for all architectures)
log ""
log "=== Generating MDM Configuration Profile ==="
log "This profile works for all architectures (ARM64 and Intel)"

# Extract version from one of the built PKGs for consistent naming
MDM_VERSION=""
for pkg in *-saml.pkg; do
    if [ -f "$pkg" ]; then
        # Extract version from filename (e.g., 11.58.0)
        MDM_VERSION=$(echo "$pkg" | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1)
        break
    fi
done

# Fallback if version extraction fails
if [ -z "$MDM_VERSION" ]; then
    MDM_VERSION="$VERSION"  # Use the VERSION variable from top of script
fi

# Check for stable certificates in /ssl/ directory, generate if needed
STABLE_CERT="$SSL_DIR/identity.getpostman.com.crt"
STABLE_KEY="$SSL_DIR/identity.getpostman.com.key"

# Generate certificates if they don't exist
if [ ! -f "$STABLE_CERT" ] || [ ! -f "$STABLE_KEY" ]; then
    log "Stable certificates not found in $SSL_DIR, generating them now..."
    
    # Ensure SSL directory exists
    mkdir -p "$SSL_DIR"
    
    # Generate certificates using the existing script
    if [ -f "$SSL_DIR/generate_stable_cert.sh" ]; then
        log "Running certificate generation script..."
        (cd "$SSL_DIR" && ./generate_stable_cert.sh)
    else
        # Inline certificate generation if script doesn't exist
        log "Generating certificates inline..."
        openssl genrsa -out "$STABLE_KEY" 2048 2>/dev/null
        openssl req -new -key "$STABLE_KEY" -out "$SSL_DIR/temp.csr" \
            -subj "/C=US/O=$CERT_ORG/CN=identity.getpostman.com" 2>/dev/null
        
        cat > "$SSL_DIR/temp.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = identity.getpostman.com
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
        
        openssl x509 -req -in "$SSL_DIR/temp.csr" -signkey "$STABLE_KEY" -out "$STABLE_CERT" \
            -days 3650 -sha256 -extfile "$SSL_DIR/temp.ext" 2>/dev/null
        
        rm -f "$SSL_DIR/temp.csr" "$SSL_DIR/temp.ext"
        chmod 644 "$STABLE_CERT"
        chmod 600 "$STABLE_KEY"
        
        # Generate metadata
        SHA1=$(openssl x509 -in "$STABLE_CERT" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')
        cat > "$SSL_DIR/metadata.json" <<JSON
{
  "generated": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "sha1": "$SHA1"
}
JSON
    fi
    
    log "Certificates generated successfully in $SSL_DIR"
fi

log "Using stable certificates from $SSL_DIR"
debug_file_op "READ" "$STABLE_CERT" "Using stable certificate for MDM profile"


# Use a descriptive name that matches the PKG naming convention
MDM_PROFILE_NAME="Postman-Enterprise-${MDM_VERSION}-enterprise01-auth.mobileconfig"

# Generate the profile using shared function with stable certificate
generate_mdm_profile "$STABLE_CERT" "$MDM_PROFILE_NAME"

if [ -f "$MDM_PROFILE_NAME" ]; then
    log "MDM profile generated: $MDM_PROFILE_NAME"
    log "This single profile works for all package architectures"
else
    log_error "Failed to generate MDM profile"
fi

log "SUCCESS" "================================================="
log "SUCCESS" "PKG Build Complete - All Validations Passed"
log "SUCCESS" "================================================="
echo "IMPORTANT - Two-Part Deployment Required:"
echo "========================================="
echo ""
echo "1. Deploy MDM Profile (FIRST or SIMULTANEOUSLY):"
echo "   - Upload .mobileconfig file to your MDM system"
echo "   - Deploy to target devices for certificate trust"
echo "   - Without this, users will see certificate warnings"
echo ""
echo "2. Deploy PKG (AFTER or WITH profile):"
echo "   - Upload .pkg file to your deployment system"
echo "   - Install on target devices"
echo ""
echo "Files Generated:"
echo ""
echo "PKG Files (architecture-specific):"
for file in *-saml.pkg; do
    if [ -f "$file" ]; then
        echo "  - $file"
    fi
done
echo ""
echo "MDM Profile (works for all architectures):"
if [ -f "$MDM_PROFILE_NAME" ]; then
    echo "  - $MDM_PROFILE_NAME"
else
    echo "  - (Profile generation failed)"
fi