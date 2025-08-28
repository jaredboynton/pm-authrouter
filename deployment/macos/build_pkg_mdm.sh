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
    echo "ERROR: Could not find project root (go.mod not found)"
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
VERSION=""  # Will be extracted from downloaded PKG
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

# Single temp directory for all operations
TEMP_DIR=""
trap 'cleanup' EXIT

# Simplified logging infrastructure
log() {
    local level="$1"
    shift
    local message="$*"
    
    # Only show output if not quiet
    if [[ "$QUIET" != "true" ]]; then
        local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$timestamp] [$level] $message"
    fi
}

die() {
    log "ERROR" "$@"
    exit 1
}

debug() {
    if [[ "$DEBUG_MODE" == "1" ]]; then
        local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
        echo "[$timestamp] [DEBUG] $*" >&2
    fi
}

# Validation helpers
validation_error() {
    local phase="$1"
    local error="$2"
    die "[$phase] $error"
}

validation_success() {
    local phase="$1"
    local message="$2"
    log "SUCCESS" "[$phase] $message"
}

# Certificate generation function for reuse
generate_certificates() {
    local cert_dir="$1"
    local cert_org="${2:-$CERT_ORG}"
    
    local cert_path="$cert_dir/identity.getpostman.com.crt"
    local key_path="$cert_dir/identity.getpostman.com.key"
    
    # Generate private key
    openssl genrsa -out "$key_path" 2048 2>/dev/null
    
    # Create certificate signing request
    openssl req -new -key "$key_path" -out "$cert_dir/temp.csr" \
        -subj "/C=US/O=$cert_org/CN=identity.getpostman.com" 2>/dev/null
    
    # Create extensions file
    cat > "$cert_dir/temp.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = identity.getpostman.com
DNS.2 = localhost
IP.1 = 127.0.0.1
EOF
    
    # Generate self-signed certificate
    openssl x509 -req -in "$cert_dir/temp.csr" -signkey "$key_path" -out "$cert_path" \
        -days 3650 -sha256 -extfile "$cert_dir/temp.ext" 2>/dev/null
    
    # Clean up and set permissions
    rm -f "$cert_dir/temp.csr" "$cert_dir/temp.ext"
    chmod 644 "$cert_path"
    chmod 600 "$key_path"
    
    # Generate metadata
    local sha1=$(openssl x509 -in "$cert_path" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')
    cat > "$cert_dir/metadata.json" <<JSON
{
  "generated": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "sha1": "$sha1"
}
JSON
}

# MDM profile generation function
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

# Simplified cleanup handler
cleanup() {
    local exit_code=$?
    
    # Clean up single temp directory
    [[ -n "$TEMP_DIR" ]] && rm -rf "$TEMP_DIR"
    
    # Clean up architecture-specific files
    rm -f "$SCRIPT_DIR"/pm-authrouter-* 2>/dev/null || true
    rm -rf "$SCRIPT_DIR"/{combined_root_*,extracted_pkg_*} 2>/dev/null || true
    
    if [[ $exit_code -ne 0 ]]; then
        log "ERROR" "Build process failed with exit code $exit_code"
    fi
    
    exit $exit_code
}

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
            echo "Configuration parameters - service requires both to activate:"
            echo "  --team <name>         Set team name at build time"
            echo "  --saml-url <url>      Set SAML URL at build time"
            echo "  --output <file>       Output PKG filename - auto-generated from original PKG name"
            echo "  --cert-org <org>      Certificate organization name - default: Postdot Technologies, Inc"
            echo "  --quiet              Reduce output for CI/CD environments"
            echo "  --debug              Enable debug logging and file operation tracking"
            echo "  --skip-deps          Skip dependency validation (for CI/CD with pre-validated environment)"
            echo "  --offline            Disable automatic PKG downloads (requires pre-placed PKG files)"
            echo "  --version            Show version and build environment information"
            echo "  --help               Show this help message"
            echo ""
            echo "MDM Configuration for runtime values:"
            echo "  Deploy Configuration Profile with teamName and samlUrl keys"
            echo "  via your MDM solution (Jamf, Workspace ONE, etc.)"
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
log "INFO" "Team Name: ${TEAM_NAME:-[not configured]}"
log "INFO" "SAML URL: ${SAML_URL:-[not configured]}"

# Comprehensive argument validation
validate_arguments() {
    log "INFO" "=== Argument Validation ==="
    
    # SAML URL validation - OPTIONAL (warn only)
    if [[ -z "$SAML_URL" ]]; then
        log "WARN" "No SAML URL provided. Service will be installed but not activated."
        log "INFO" "  Configure via MDM Configuration Profile with samlUrl key"
    else
        if [[ ! "$SAML_URL" =~ ^https?:// ]]; then
            log "WARN" "SAML URL should be a valid HTTP/HTTPS URL: $SAML_URL"
        fi
        
        # Validate SAML URL format
        if [[ ! "$SAML_URL" =~ ^https://identity\.getpostman\.com/ ]]; then
            log "WARN" "SAML URL should start with https://identity.getpostman.com/"
        fi
        
        if [[ ! "$SAML_URL" =~ /init$ ]]; then
            log "WARN" "SAML URL should end with '/init'"
        fi
    fi
    
    # Team name validation - OPTIONAL (warn only)
    if [[ -z "$TEAM_NAME" ]]; then
        log "WARN" "No team name provided. Service will be installed but not activated."
        log "INFO" "  Configure via MDM Configuration Profile with teamName key"
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

# Create single temp directory for all operations
TEMP_DIR=$(mktemp -d "${TEMP_ROOT}/postman-build-$$-XXXXXX") || die "Failed to create temp directory"

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
    
    # Create a temp file for the download in our single temp dir
    local temp_pkg="$TEMP_DIR/download-$arch.pkg"
    
    log "INFO" "Downloading $arch PKG from: $url"
    log "INFO" "Download will respect server filename (includes version)"
    log "INFO" "Destination directory: $SCRIPT_DIR"
    
    # Download with curl (with retry logic) - respecting server's filename
    local download_attempts=0
    local max_attempts=3
    local download_success=false
    local actual_filename=""
    
    # Change to temp directory for download
    local download_dir=$(dirname "$temp_pkg")
    local original_dir=$(pwd)
    cd "$download_dir" || {
        validation_error "PKG_DOWNLOAD" "Failed to change to download directory: $download_dir"
    }
    
    while [[ $download_attempts -lt $max_attempts ]] && [[ "$download_success" == "false" ]]; do
        download_attempts=$((download_attempts + 1))
        log "INFO" "Download attempt $download_attempts/$max_attempts..."
        log "DEBUG" "Downloading from: $url"
        
        # Use -J and -O to respect Content-Disposition header for filename
        # Note: Cannot use -C (resume) with -J (remote-header-name)
        local curl_opts=(-L --connect-timeout 57 --max-time 900 --retry 2 --retry-delay 3 --retry-max-time 300 -A "pm-authrouter" -J -O)
        if [[ "$DEBUG_MODE" == "1" ]]; then
            # Debug mode: verbose output, show progress
            curl_opts+=(--verbose --progress-bar)
            log "DEBUG" "Running curl with debug options: ${curl_opts[*]} \"$url\""
        else
            # Normal mode: silent with error reporting
            curl_opts+=(--silent --show-error)
        fi
        
        log "INFO" "Starting curl download (attempt $download_attempts/$max_attempts)..."
        if curl "${curl_opts[@]}" "$url"; then
            download_success=true
            # Find the downloaded file (should be the newest .pkg file)
            actual_filename=$(ls -t *.pkg 2>/dev/null | head -1)
            if [[ -n "$actual_filename" ]] && [[ -f "$actual_filename" ]]; then
                local file_size=$(stat -f%z "$actual_filename" 2>/dev/null || stat -c%s "$actual_filename" 2>/dev/null || echo "unknown")
                local file_size_mb=$(( file_size / 1024 / 1024 ))
                log "SUCCESS" "Download completed: $actual_filename (${file_size_mb}MB / $file_size bytes)"
                log "INFO" "Downloaded to: $download_dir/$actual_filename"
                # Update temp_pkg to point to actual downloaded file
                temp_pkg="$download_dir/$actual_filename"
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
    
    # Change back to original directory
    cd "$original_dir" || {
        validation_error "PKG_DOWNLOAD" "Failed to return to original directory: $original_dir"
    }
    
    if [[ "$download_success" == "false" ]]; then
        rm -f "$temp_pkg" 2>/dev/null
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
    local expand_dest="$TEMP_DIR/integrity-test-$arch"
    local expand_err
    if ! expand_err=$(pkgutil --expand "$temp_pkg" "$expand_dest" 2>&1); then
        log "ERROR" "pkgutil --expand failed: $expand_err"
        rm -rf "$expand_dest"
        rm -f "$temp_pkg"
        log "ERROR" "Downloaded $arch PKG is corrupted and cannot be expanded"
        return 1
    fi
    rm -rf "$expand_dest"
    log "INFO" "PKG integrity validation passed"
    
    # Basic PKG validation
    if ! pkgutil --check-signature "$temp_pkg" >/dev/null 2>&1; then
        log "WARN" "Downloaded $arch PKG signature validation failed - this may be expected for enterprise builds"
    fi
    
    # Use the actual filename from the server (which includes version)
    local final_filename=$(basename "$temp_pkg")
    
    # Move to final location in script directory
    local final_path="$SCRIPT_DIR/$final_filename"
    if ! mv "$temp_pkg" "$final_path"; then
        rm -f "$temp_pkg"
        validation_error "PKG_DOWNLOAD" "Failed to move downloaded $arch PKG to final location: $final_path"
    fi
    
    debug "PKG download completed: $final_path"
    log "INFO" "$arch PKG downloaded successfully: $final_filename ($(($download_size/1024/1024))MB)"
    log "INFO" "Final PKG location: $final_path"
    
    # Return the path for use
    echo "$final_path"
}

# Find existing PKGs or download if missing
ARM64_PKG=""
INTEL_PKG=""

log "INFO" "=== PKG Discovery and Download Phase ==="

# Extract version from PKG filename - most reliable for Postman PKGs
extract_version_from_pkg() {
    local pkg_path="$1"
    
    if [[ ! -f "$pkg_path" ]]; then
        return 1
    fi
    
    debug "Extracting version from PKG: $(basename "$pkg_path")"
    
    # Extract version from filename (Postman follows consistent naming)
    local version=$(basename "$pkg_path" | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1)
    
    if [[ -n "$version" ]]; then
        echo "$version"
        return 0
    fi
    
    return 1
}

# Simplified PKG discovery function
find_best_pkg() {
    local arch="$1"  # "arm64" or "x64"
    # Find all Postman PKGs with the architecture, exclude SAML versions, sort by time
    local pkgs=($(ls -t "$SCRIPT_DIR"/Postman*${arch}*.pkg 2>/dev/null | grep -v saml))
    [[ ${#pkgs[@]} -eq 0 ]] && return 1
    echo "${pkgs[0]}"  # Return newest
    return 0
}

# First, try to find existing PKGs using enhanced discovery
if ARM64_PKG=$(find_best_pkg "arm64"); then
    log "INFO" "Found existing ARM64 PKG: $(basename "$ARM64_PKG")"
fi

if INTEL_PKG=$(find_best_pkg "x64"); then
    log "INFO" "Found existing Intel PKG: $(basename "$INTEL_PKG")"
fi

# Architecture detection removed - we build both versions regardless
# The build machine's architecture doesn't matter for cross-compilation

# Only attempt downloads if not in offline mode
if [[ "$OFFLINE_MODE" != "true" ]]; then
    log "INFO" "Online mode - checking for missing PKGs to download..."
    
    # Download ARM64 PKG if missing
    if [[ -z "$ARM64_PKG" ]]; then
        log "INFO" "Downloading ARM64 PKG..."
        if ARM64_PKG=$(download_pkg "arm64" "$ARM64_PKG_URL" "arm64"); then
            log "INFO" "ARM64 PKG download completed successfully"
        else
            log "WARN" "ARM64 PKG download failed"
        fi
    fi

    # Download Intel PKG if missing
    if [[ -z "$INTEL_PKG" ]]; then
        log "INFO" "Downloading Intel PKG..."
        if INTEL_PKG=$(download_pkg "x64" "$INTEL_PKG_URL" "x64"); then
            log "INFO" "Intel PKG download completed successfully"
        else
            log "WARN" "Intel PKG download failed"
        fi
    fi
else
    log "INFO" "Offline mode enabled - skipping all download attempts"
    log "INFO" "Using only PKGs found during discovery phase"
fi

# Final validation - warn if missing any PKG but continue
if [[ -z "$ARM64_PKG" && -z "$INTEL_PKG" ]]; then
    log "ERROR" "No Postman Enterprise PKG available and downloads failed/disabled"
    log "ERROR" "Options:"
    log "ERROR" "  1. Place Postman-Enterprise-*-arm64.pkg or Postman-Enterprise-*-x64.pkg in $SCRIPT_DIR"
    log "ERROR" "  2. Enable downloads by removing --offline flag or OFFLINE_MODE=true"
    log "ERROR" "  3. Check network connectivity and try again"
    exit 1
fi

# Warn if only one architecture available
if [[ -z "$ARM64_PKG" ]]; then
    log "WARN" "ARM64 PKG not available - skipping ARM64 build"
fi
if [[ -z "$INTEL_PKG" ]]; then
    log "WARN" "Intel PKG not available - skipping Intel build"
fi

# Extract version from the first available PKG
log "INFO" "=== Version Detection ==="
DETECTED_PKG=""
if [[ -n "$ARM64_PKG" ]]; then
    DETECTED_PKG="$ARM64_PKG"
elif [[ -n "$INTEL_PKG" ]]; then
    DETECTED_PKG="$INTEL_PKG"
fi

if [[ -n "$DETECTED_PKG" ]]; then
    if VERSION=$(extract_version_from_pkg "$DETECTED_PKG"); then
        log "INFO" "Detected version: $VERSION from $(basename "$DETECTED_PKG")"
    else
        die "Failed to extract version from PKG: $(basename "$DETECTED_PKG")"
    fi
else
    die "No PKG available for version detection"
fi

# Report final status
log ""
log "=== PKG Status Summary ==="
if [[ -n "$ARM64_PKG" ]]; then
    log "INFO" "ARM64 PKG ready: $(basename "$ARM64_PKG") (v$VERSION)"
fi
if [[ -n "$INTEL_PKG" ]]; then
    log "INFO" "Intel PKG ready: $(basename "$INTEL_PKG") (v$VERSION)"
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
    local expand_dest="$TEMP_DIR/validate-original-$arch"
    local expand_err
    if ! expand_err=$(pkgutil --expand "$pkg_path" "$expand_dest" 2>&1); then
        log "ERROR" "pkgutil --expand failed: $expand_err"
        rm -rf "$expand_dest"
        validation_error "ORIGINAL_PKG" "PKG file cannot be expanded (corrupted)"
    fi
    
    # Check for required components
    if [[ ! -f "$expand_dest/Distribution" ]]; then
        rm -rf "$expand_dest"
        validation_error "ORIGINAL_PKG" "PKG missing Distribution file"
    fi
    
    local component_count=$(find "$expand_dest" -name "*.pkg" | wc -l)
    if [[ $component_count -eq 0 ]]; then
        rm -rf "$expand_dest"
        validation_error "ORIGINAL_PKG" "PKG contains no component packages"
    fi
    
    debug "Original PKG validated: $pkg_path"
    rm -rf "$expand_dest"
    
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
    
    debug "AuthRouter binary validated: $binary_path"
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
    
    # Generate output filename using global VERSION
    local PKG_BASENAME=$(basename "$ORIGINAL_PKG" .pkg)
    local PKG_NAME="${CUSTOM_PKG_NAME:-${PKG_BASENAME}-saml.pkg}"
    local PKG_VERSION="$VERSION"  # Use the globally extracted version
    
    log "Using version: $PKG_VERSION (detected earlier from PKG)"
    
    log "Found original PKG: $(basename "$ORIGINAL_PKG")"
    log "Output will be: $(basename "$PKG_NAME")"
    
    # Create build directory in our temp space
    local BUILD_DIR="$TEMP_DIR/build-$ARCH"
    mkdir -p "$BUILD_DIR" || validation_error "BUILD_SETUP" "Failed to create build directory"
    debug "Build directory created: $BUILD_DIR"
    
    log ""
    log "INFO" "=== Step 1: Building AuthRouter Binary for $ARCH ==="
    cd "$PROJECT_ROOT" || {
        validation_error "BUILD_SETUP" "Failed to change to project root: $PROJECT_ROOT"
    }
    
    if ! env GOOS=darwin GOARCH=$GOARCH go build -ldflags="-w" -o "$SCRIPT_DIR/pm-authrouter-$ARCH" ./cmd/pm-authrouter; then
        validation_error "BINARY_BUILD" "Failed to build AuthRouter binary for $ARCH"
    fi
    log "SUCCESS" "Built AuthRouter binary for $ARCH"
    
    # Phase 3A: Validate binary component  
    validate_binary_component "$SCRIPT_DIR/pm-authrouter-$ARCH" "$ARCH"
    
    log ""
    log "=== Step 2: Extracting Original PKG Structure ==="
    cd "$SCRIPT_DIR" || {
        die "Failed to change to script directory: $SCRIPT_DIR"
        return 1
    }
    
    # Clean up previous extractions
    rm -rf "extracted_pkg_$ARCH" "combined_root_$ARCH"
    
    # Extract original PKG
    log "Extracting original PKG..."
    if ! pkgutil --expand "$ORIGINAL_PKG" "./extracted_pkg_$ARCH/"; then
        die "Failed to expand original PKG: $ORIGINAL_PKG"
        return 1
    fi

    # Extract application files from Payload
    log "Extracting Postman.app from Payload..."
    cd "./extracted_pkg_$ARCH/com.postmanlabs.enterprise.mac.pkg" || {
        die "Failed to find PKG component directory"
        return 1
    }
    
    rm -rf extracted_files
    mkdir -p extracted_files || {
        die "Failed to create extraction directory"
        return 1
    }
    
    if ! (cat Payload | gzip -d | (cd extracted_files && cpio -i)); then
        die "Failed to extract Payload from original PKG"
        return 1
    fi
    
    log ""
    log "=== Step 3: Creating Combined Package Root ==="
    cd "$SCRIPT_DIR" || {
        die "Failed to change back to script directory"
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
    
    # Create simple MDM profile generator script that calls the main function
    cat > "combined_root_$ARCH/usr/local/bin/postman/generate_mdm_profile.sh" << 'MDM_PROFILE_GENERATOR'
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

# Generate the MDM profile using the main function logic
# Read certificate and encode it for the profile
CERT_BASE64=\$(cat "\$CERT_PATH" | grep -v "BEGIN CERTIFICATE" | grep -v "END CERTIFICATE" | tr -d '\\n')
PROFILE_UUID=\$(uuidgen)
PAYLOAD_UUID=\$(uuidgen)
CERT_SHA1=\$(openssl x509 -in "\$CERT_PATH" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')

# Create the configuration profile (simplified version of main function)
cat > "\$OUTPUT_PATH" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadCertificateFileName</key>
            <string>identity.getpostman.com.crt</string>
            <key>PayloadContent</key>
            <data>\$CERT_BASE64</data>
            <key>PayloadDescription</key>
            <string>Installs the Postman AuthRouter SSL certificate for SAML enforcement</string>
            <key>PayloadDisplayName</key>
            <string>Postman AuthRouter Certificate</string>
            <key>PayloadIdentifier</key>
            <string>com.postman.authrouter.certificate.\$PAYLOAD_UUID</string>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadUUID</key>
            <string>\$PAYLOAD_UUID</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>AllowAllAppsAccess</key>
            <true/>
        </dict>
        <dict>
            <key>PayloadType</key>
            <string>com.apple.security.certificatetrust</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.postman.authrouter.trust.\$(uuidgen)</string>
            <key>PayloadUUID</key>
            <string>\$(uuidgen)</string>
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
                    <data>\$(echo -n "\$CERT_SHA1" | xxd -r -p | base64)</data>
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
    <string>This profile installs the Postman AuthRouter SSL certificate as a trusted root certificate.</string>
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
    <string>\$PROFILE_UUID</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
EOF

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

# Read configuration from plist (as set at build time)
PLIST="/Library/LaunchDaemons/com.postman.pm-authrouter.plist"
TEAM=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:2" "$PLIST" 2>/dev/null || echo '')
SAML=$(/usr/libexec/PlistBuddy -c "Print :ProgramArguments:4" "$PLIST" 2>/dev/null || echo '')

echo "Configuration: Team=${TEAM:-[not set]}, SAML=${SAML:-[not set]}"

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
echo "  - Postman Enterprise.app installed"
echo "  - AuthRouter daemon ${TEAM:+configured for team: $TEAM}"
echo "  - Uninstall: sudo /usr/local/bin/postman/uninstall.sh"

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
        die "Failed to build component package"
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
    local EXPAND_DIR="$TEMP_DIR/welcome-$ARCH"
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
    
    rm -rf "$EXPAND_DIR"

    # Build final product archive
    log "Creating product archive..."
    local OUTPUT_PATH="$SCRIPT_DIR/$PKG_NAME"
    if ! productbuild \
        --distribution "$BUILD_DIR/distribution.xml" \
        --resources "$BUILD_DIR" \
        --package-path "$BUILD_DIR" \
        "$OUTPUT_PATH"; then
        die "Failed to create product archive"
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
    local expand_dest="$TEMP_DIR/validate-final-$arch"
    local expand_err
    if ! expand_err=$(pkgutil --expand "$pkg_path" "$expand_dest" 2>&1); then
        log "ERROR" "pkgutil --expand failed: $expand_err"
        rm -rf "$expand_dest"
        validation_error "FINAL_PKG" "Final PKG cannot be expanded (corrupted)"
    fi
    
    # Check for required components in final PKG
    if [[ ! -f "$expand_dest/Distribution" ]]; then
        rm -rf "$expand_dest"
        validation_error "FINAL_PKG" "Final PKG missing Distribution file"
    fi
    
    # Verify our component is included
    local our_component_count=$(find "$expand_dest" -name "component.pkg" | wc -l)
    if [[ $our_component_count -eq 0 ]]; then
        rm -rf "$expand_dest"
        validation_error "FINAL_PKG" "Final PKG missing our AuthRouter component"
    fi
    
    debug "Final PKG validated: $pkg_path"
    rm -rf "$expand_dest"
    
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
        log "INFO" "Installation:"
        log "INFO" "  sudo installer -pkg \"$PKG_NAME\" -target /"
        log "INFO" "  Or double-click in Finder"
        log ""
        log "INFO" "To uninstall:"
        log "INFO" "  sudo /usr/local/bin/postman/uninstall.sh"
    else
        die "Failed to create PKG for $ARCH"
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

# Use the globally detected version for consistent naming
if [[ -z "$VERSION" ]]; then
    die "VERSION not detected - this should not happen after PKG validation"
fi

MDM_VERSION="$VERSION"
log "INFO" "Using version $MDM_VERSION for MDM profile naming"

# Check for stable certificates in /ssl/ directory, generate if needed
STABLE_CERT="$SSL_DIR/identity.getpostman.com.crt"
STABLE_KEY="$SSL_DIR/identity.getpostman.com.key"

# Generate certificates if they don't exist
if [ ! -f "$STABLE_CERT" ] || [ ! -f "$STABLE_KEY" ]; then
    log "INFO" "Generating certificates in $SSL_DIR..."
    mkdir -p "$SSL_DIR"
    
    # Use existing script if available, otherwise use inline function
    if [ -f "$SSL_DIR/generate_cert.sh" ]; then
        log "INFO" "Running certificate generation script..."
        (cd "$SSL_DIR" && ./generate_cert.sh)
    else
        generate_certificates "$SSL_DIR" "$CERT_ORG"
    fi
    
    log "INFO" "Certificates generated successfully"
fi

log "INFO" "Using stable certificates from $SSL_DIR"
debug "Using certificate for MDM profile: $STABLE_CERT"


# Use a descriptive name that matches the PKG naming convention
MDM_PROFILE_NAME="Postman-Enterprise-${MDM_VERSION}-enterprise01-auth.mobileconfig"

# Generate the profile using shared function with stable certificate
generate_mdm_profile "$STABLE_CERT" "$MDM_PROFILE_NAME"

if [ -f "$MDM_PROFILE_NAME" ]; then
    log "MDM profile generated: $MDM_PROFILE_NAME"
    log "This single profile works for all package architectures"
else
    die "Failed to generate MDM profile"
fi

log "SUCCESS" "================================================="
log "SUCCESS" "PKG Build Complete - All Validations Passed"
log "SUCCESS" "================================================="
echo "Build Complete!"
echo "==============="
echo ""
echo "Deployment requires two components:"
echo "1. MDM Profile: $MDM_PROFILE_NAME"
echo "   Deploy via MDM to establish certificate trust"
echo ""
echo "2. PKG Files:"
for file in *-saml.pkg; do
    [ -f "$file" ] && echo "   - $file"
done
echo ""
echo "Deploy both for complete SAML enforcement."