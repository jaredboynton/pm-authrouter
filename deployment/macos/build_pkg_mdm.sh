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

# Constants for validation thresholds
readonly MIN_DOWNLOAD_SIZE_MB=10
readonly MIN_PKG_SIZE_KB=1000
readonly MAX_PKG_SIZE_MB=500
readonly MIN_BINARY_SIZE_KB=1000

# Configuration parameters
TEAM_NAME="${TEAM_NAME:-}"
SAML_URL="${SAML_URL:-}"
IDENTIFIER="${IDENTIFIER:-com.postman.enterprise.authrouter}"
VERSION=""
CERT_ORG="${CERT_ORG:-Postdot Technologies, Inc}"
QUIET="${QUIET:-false}"
DEBUG_MODE="${DEBUG_MODE:-0}"

# CI/CD behavior flags
SKIP_DEPS="${SKIP_DEPS:-false}"

# PKG Download URLs (configurable via environment)
ARM64_PKG_URL="${ARM64_PKG_URL:-https://dl-proxy.jared-boynton.workers.dev/https://dl.pstmn.io/download/latest/version/11/osx?channel=enterprise&filetype=pkg&arch=arm64}"
INTEL_PKG_URL="${INTEL_PKG_URL:-https://dl-proxy.jared-boynton.workers.dev/https://dl.pstmn.io/download/latest/version/11/osx?channel=enterprise&filetype=pkg&arch=x64}"

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
        echo "[DEBUG] $*" >&2
    fi
}

# File size helper - handles macOS/Linux stat differences
get_file_size() {
    local file="$1"
    stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0"
}

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
    
    openssl genrsa -out "$key_path" 2048 2>/dev/null
    openssl req -new -key "$key_path" -out "$cert_dir/temp.csr" \
        -subj "/C=US/O=$cert_org/CN=identity.getpostman.com" 2>/dev/null
    
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
    
    openssl x509 -req -in "$cert_dir/temp.csr" -signkey "$key_path" -out "$cert_path" \
        -days 3650 -sha256 -extfile "$cert_dir/temp.ext" 2>/dev/null
    
    rm -f "$cert_dir/temp.csr" "$cert_dir/temp.ext"
    chmod 644 "$cert_path"
    chmod 600 "$key_path"
    
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

# XML escaping function
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
    
    # curl is always required for potential downloads and version checking
    required_tools+=(curl)
    
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
    
    validation_success "DEPENDENCY_CHECK" "All required tools are available and functional"
}

log "INFO" "=== PKG Builder v$SCRIPT_VERSION - Enterprise Grade with Validation ==="
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
        if [[ ${#TEAM_NAME} -lt 2 ]]; then
            log "WARN" "Team name too short (minimum 2 characters recommended): $TEAM_NAME"
        fi
        
        if [[ ${#TEAM_NAME} -gt 100 ]]; then
            log "WARN" "Team name too long (maximum 100 characters recommended): $TEAM_NAME"
        fi
    fi
    
    # Output filename validation
    if [[ -n "$CUSTOM_PKG_NAME" ]]; then
        if [[ ! "$CUSTOM_PKG_NAME" =~ \.pkg$ ]]; then
            validation_error "ARGUMENT_VALIDATION" "Output filename must end with .pkg: $CUSTOM_PKG_NAME"
        fi
        
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
    # Redirect all output to stderr except the final path result
    {
    local arch="$1"
    local url="$2"
    local expected_filename_pattern="$3"
    
    log "INFO" "=== Downloading $arch PKG ==="
    
    # This function is only called when download is actually needed
    
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
        local curl_opts=(-L --tcp-nodelay --connect-timeout 10 --max-time 60 --retry 2 --retry-delay 3 --retry-max-time 300 -A "pm-authrouter" -J -O)
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
                local file_size=$(get_file_size "$actual_filename")
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
                local partial_size=$(get_file_size "$temp_pkg")
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
    
    # Validate downloaded file
    local download_size=$(get_file_size "$temp_pkg")
    local min_download_size=$((MIN_DOWNLOAD_SIZE_MB * 1024 * 1024))
    if [[ $download_size -lt $min_download_size ]]; then
        rm -f "$temp_pkg"
        log "ERROR" "Downloaded $arch PKG too small: $(($download_size/1024/1024))MB (minimum: ${MIN_DOWNLOAD_SIZE_MB}MB)"
        return 1
    fi
    
    log "INFO" "Downloaded PKG size validated: $(($download_size/1024/1024))MB"
    
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
    
    
    log "INFO" "$arch PKG downloaded successfully: $final_filename ($(($download_size/1024/1024))MB)"
    log "INFO" "Final PKG location: $final_path"
    
    } >&2  # End stderr redirection for all log output
    
    # Return ONLY the path to stdout (this is what gets captured)
    echo "$final_path"
}


# Find existing PKGs or download if missing
ARM64_PKG=""
INTEL_PKG=""

log "INFO" "=== PKG Discovery and Download Phase ==="

# Get version from server via HEAD request (fast, no download needed)
get_version_from_server() {
    local url="$1"
    
    
    # Get filename from Content-Disposition header without downloading
    local filename=$(curl -sI --connect-timeout 10 --max-time 30 "$url" 2>/dev/null | \
        grep -i content-disposition | \
        sed 's/.*filename=\([^;]*\).*/\1/' | \
        tr -d '\r"')
    
    if [[ -n "$filename" ]]; then
        # Extract version from filename (Postman follows consistent naming)
        local version=$(echo "$filename" | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1)
        
        if [[ -n "$version" ]]; then
            echo "$version"
            return 0
        fi
    fi
    
    return 1
}

# Extract version from PKG filename - fallback for existing files
extract_version_from_pkg() {
    local pkg_path="$1"
    
    if [[ ! -f "$pkg_path" ]]; then
        return 1
    fi
    
    
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

# Download missing PKGs if not found locally
log "INFO" "Checking for missing PKGs to download..."

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

# Final validation - warn if missing any PKG but continue
if [[ -z "$ARM64_PKG" && -z "$INTEL_PKG" ]]; then
    log "ERROR" "No Postman Enterprise PKG available and downloads failed"
    log "ERROR" "Options:"
    log "ERROR" "  1. Place Postman-Enterprise-*-arm64.pkg or Postman-Enterprise-*-x64.pkg in $SCRIPT_DIR"
    log "ERROR" "  2. Check network connectivity and try again"
    exit 1
fi

# Warn if only one architecture available
if [[ -z "$ARM64_PKG" ]]; then
    log "WARN" "ARM64 PKG not available - skipping ARM64 build"
fi
if [[ -z "$INTEL_PKG" ]]; then
    log "WARN" "Intel PKG not available - skipping Intel build"
fi

# Smart version detection: existing files first, then server HEAD request
log "INFO" "=== Version Detection ==="
VERSION=""

# First try to get version from existing files
if [[ -n "$ARM64_PKG" ]] && VERSION=$(extract_version_from_pkg "$ARM64_PKG"); then
    log "INFO" "Detected version: $VERSION from existing $(basename "$ARM64_PKG")"
elif [[ -n "$INTEL_PKG" ]] && VERSION=$(extract_version_from_pkg "$INTEL_PKG"); then
    log "INFO" "Detected version: $VERSION from existing $(basename "$INTEL_PKG")"
# Fallback to server HEAD request if no existing files
elif VERSION=$(get_version_from_server "$ARM64_PKG_URL"); then
    log "INFO" "Detected version: $VERSION from server (ARM64 URL)"
elif VERSION=$(get_version_from_server "$INTEL_PKG_URL"); then
    log "INFO" "Detected version: $VERSION from server (Intel URL)"
else
    die "Failed to detect version from existing files or server"
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

# Phase 2: Original PKG Validation (simplified - size check only)
validate_original_pkg() {
    local pkg_path="$1"
    local arch="$2"
    
    log "INFO" "=== Phase 2A: Original PKG Basic Validation ($arch) ==="
    
    # Basic PKG integrity check
    if [[ ! -f "$pkg_path" ]]; then
        validation_error "ORIGINAL_PKG" "PKG file not found: $pkg_path"
    fi
    
    local pkg_size=$(get_file_size "$pkg_path")
    local min_pkg_size=$((MIN_PKG_SIZE_KB * 1024))
    if [[ $pkg_size -lt $min_pkg_size ]]; then
        validation_error "ORIGINAL_PKG" "PKG file too small: $(($pkg_size/1024))KB (minimum: ${MIN_PKG_SIZE_KB}KB)"
    fi
    
    
    log "INFO" "Original PKG validated - Size: $(($pkg_size/1024/1024))MB"
    validation_success "ORIGINAL_PKG" "Original PKG size is valid"
}

# New consolidated validation function that works on already-extracted directories
validate_extracted_structure() {
    local extract_dir="$1"
    local arch="$2"
    
    log "INFO" "Validating extracted PKG structure..."
    
    # Check for required components
    if [[ ! -f "$extract_dir/Distribution" ]]; then
        validation_error "PKG_STRUCTURE" "PKG missing Distribution file"
    fi
    
    local component_count=$(find "$extract_dir" -name "*.pkg" | wc -l)
    if [[ $component_count -eq 0 ]]; then
        validation_error "PKG_STRUCTURE" "PKG contains no component packages"
    fi
    
    log "INFO" "Structure validated - Components: $component_count"
    validation_success "PKG_STRUCTURE" "PKG structure is valid and complete"
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
    local binary_size=$(get_file_size "$binary_path")
    local min_binary_size=$((MIN_BINARY_SIZE_KB * 1024))
    if [[ $binary_size -lt $min_binary_size ]]; then
        validation_error "SOURCE_COMPONENTS" "Binary too small: $(($binary_size/1024))KB (minimum: ${MIN_BINARY_SIZE_KB}KB - likely build failed)"
    fi
    
    log "INFO" "Binary validated - Architecture: $binary_arch, Size: $(($binary_size/1024/1024))MB"
    validation_success "SOURCE_COMPONENTS" "AuthRouter binary is valid and correctly compiled for $arch"
}

# Function to conditionally sign PKG files with Apple Developer ID certificates
sign_packages_if_available() {
    log "INFO" "=== Attempting PKG Code Signing ==="
    
    # Search for Apple Developer ID Installer certificates
    local signing_cert=$(security find-identity -v 2>/dev/null | grep "Developer ID Installer" | head -1 | sed 's/^[^"]*"//' | sed 's/"$//')
    
    if [[ -n "$signing_cert" ]]; then
        log "INFO" "Found signing certificate: $signing_cert"
        log "INFO" "Signing PKG files with Apple Developer ID certificate..."
        
        # Sign all SAML PKG files in the directory
        local signed_count=0
        local failed_count=0
        
        for pkg_file in "$SCRIPT_DIR"/*-saml.pkg; do
            if [[ -f "$pkg_file" ]]; then
                local pkg_name=$(basename "$pkg_file")
                local signed_pkg="${pkg_file%.pkg}-signed.pkg"
                
                log "INFO" "Signing $pkg_name..."
                if productsign --sign "$signing_cert" "$pkg_file" "$signed_pkg" 2>/dev/null; then
                    # Replace original with signed version
                    mv "$signed_pkg" "$pkg_file"
                    log "SUCCESS" "Signed: $pkg_name"
                    signed_count=$((signed_count + 1))
                else
                    log "WARN" "Failed to sign: $pkg_name"
                    failed_count=$((failed_count + 1))
                    # Clean up failed signed file if it exists
                    rm -f "$signed_pkg"
                fi
            fi
        done
        
        if [[ $signed_count -gt 0 ]]; then
            log "SUCCESS" "Successfully signed $signed_count PKG file(s)"
        fi
        
        if [[ $failed_count -gt 0 ]]; then
            log "WARN" "Failed to sign $failed_count PKG file(s) - they remain unsigned"
        fi
        
    else
        log "INFO" "No Apple Developer ID Installer certificate found in keychain"
        log "INFO" "PKG files will remain unsigned - enterprise deployments may require configuration"
        log "INFO" "For signed packages: import Apple Developer ID Installer certificate to keychain"
        log "INFO" "Note: Some MDM providers (Jamf, Intune) may require signed packages for deployment"
    fi
}

# Function to run parallel builds with error handling
run_parallel_builds() {
    log "INFO" "=== Starting Parallel Builds for ARM64 and Intel ==="
    
    # Create log files for each architecture
    local ARM64_LOG="$TEMP_DIR/build-arm64.log"
    local INTEL_LOG="$TEMP_DIR/build-intel.log"
    local ARM64_PID=""
    local INTEL_PID=""
    
    # Start ARM64 build in background
    if [[ -n "$ARM64_PKG" && -f "$ARM64_PKG" ]]; then
        log "INFO" "Starting ARM64 build (logging to $ARM64_LOG)..."
        (build_pkg_for_arch "$ARM64_PKG" "ARM64" "arm64") > "$ARM64_LOG" 2>&1 &
        ARM64_PID=$!
    else
        log "INFO" "Skipping ARM64 build - PKG not available"
    fi
    
    # Start Intel build in background
    if [[ -n "$INTEL_PKG" && -f "$INTEL_PKG" ]]; then
        log "INFO" "Starting Intel build (logging to $INTEL_LOG)..."
        (build_pkg_for_arch "$INTEL_PKG" "Intel" "amd64") > "$INTEL_LOG" 2>&1 &
        INTEL_PID=$!
    else
        log "INFO" "Skipping Intel build - PKG not available"
    fi
    
    # Wait for both builds and capture exit codes
    local ARM64_EXIT=0
    local INTEL_EXIT=0
    local BUILD_FAILED=false
    
    if [[ -n "$ARM64_PID" ]]; then
        log "INFO" "Waiting for ARM64 build to complete..."
        wait $ARM64_PID
        ARM64_EXIT=$?
    fi
    
    if [[ -n "$INTEL_PID" ]]; then
        log "INFO" "Waiting for Intel build to complete..."
        wait $INTEL_PID
        INTEL_EXIT=$?
    fi
    
    # Report results
    log "INFO" "=== Build Results ==="
    
    if [[ -n "$ARM64_PID" ]]; then
        if [[ $ARM64_EXIT -eq 0 ]]; then
            # Extract key information from log
            local arm64_size=$(grep "PKG size:" "$ARM64_LOG" | tail -1 | cut -d: -f2 | xargs)
            local arm64_pkg=$(grep "Combined PKG created:" "$ARM64_LOG" | tail -1 | cut -d: -f2 | xargs)
            log "SUCCESS" "ARM64 build completed"
            [[ -n "$arm64_pkg" ]] && log "INFO" "  Output: $arm64_pkg"
            [[ -n "$arm64_size" ]] && log "INFO" "  Size:$arm64_size"
        else
            log "ERROR" "ARM64 build failed (exit code: $ARM64_EXIT)"
            log "ERROR" "Last 20 lines of ARM64 build log:"
            tail -20 "$ARM64_LOG" | while IFS= read -r line; do
                log "ERROR" "  $line"
            done
            BUILD_FAILED=true
        fi
    fi
    
    if [[ -n "$INTEL_PID" ]]; then
        if [[ $INTEL_EXIT -eq 0 ]]; then
            # Extract key information from log
            local intel_size=$(grep "PKG size:" "$INTEL_LOG" | tail -1 | cut -d: -f2 | xargs)
            local intel_pkg=$(grep "Combined PKG created:" "$INTEL_LOG" | tail -1 | cut -d: -f2 | xargs)
            log "SUCCESS" "Intel build completed"
            [[ -n "$intel_pkg" ]] && log "INFO" "  Output: $intel_pkg"
            [[ -n "$intel_size" ]] && log "INFO" "  Size:$intel_size"
        else
            log "ERROR" "Intel build failed (exit code: $INTEL_EXIT)"
            log "ERROR" "Last 20 lines of Intel build log:"
            tail -20 "$INTEL_LOG" | while IFS= read -r line; do
                log "ERROR" "  $line"
            done
            BUILD_FAILED=true
        fi
    fi
    
    # Exit if any build failed
    if [[ "$BUILD_FAILED" == "true" ]]; then
        log "ERROR" "One or more builds failed. Full logs available at:"
        [[ $ARM64_EXIT -ne 0 ]] && [[ -n "$ARM64_PID" ]] && log "ERROR" "  ARM64: $ARM64_LOG"
        [[ $INTEL_EXIT -ne 0 ]] && [[ -n "$INTEL_PID" ]] && log "ERROR" "  Intel: $INTEL_LOG"
        exit 1
    fi
    
    log "SUCCESS" "All builds completed successfully"
    
    # Attempt to sign PKG files with Apple Developer ID certificates
    sign_packages_if_available
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
    
    log ""
    log "INFO" "=== Step 1: Building AuthRouter Binary for $ARCH ==="
    cd "$PROJECT_ROOT" || {
        validation_error "BUILD_SETUP" "Failed to change to project root: $PROJECT_ROOT"
    }
    
    if ! env GOOS=darwin GOARCH=$GOARCH go build -ldflags="-w -s" -o "$SCRIPT_DIR/pm-authrouter-$ARCH" ./cmd/pm-authrouter; then
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
    
    # Extract original PKG (only once!)
    log "Extracting original PKG..."
    if ! pkgutil --expand "$ORIGINAL_PKG" "./extracted_pkg_$ARCH/"; then
        die "Failed to expand original PKG: $ORIGINAL_PKG"
        return 1
    fi
    
    # Validate the structure of what we just extracted
    validate_extracted_structure "./extracted_pkg_$ARCH/" "$ARCH"

    # Extract application files from Payload (optimized)
    log "Extracting Postman.app from Payload (optimized)..."
    cd "./extracted_pkg_$ARCH/com.postmanlabs.enterprise.mac.pkg" || {
        die "Failed to find PKG component directory"
        return 1
    }
    
    rm -rf extracted_files
    mkdir -p extracted_files || {
        die "Failed to create extraction directory"
        return 1
    }
    
    # Optimized extraction using gunzip -c and cpio -im
    if ! gunzip -c Payload | (cd extracted_files && cpio -im 2>/dev/null); then
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
    
    # Copy Postman Enterprise.app from extracted files (optimized with ditto)
    # Using ditto for faster copying, skipping unnecessary metadata
    ditto --norsrc --noextattr --noacl \
        "extracted_pkg_$ARCH/com.postmanlabs.enterprise.mac.pkg/extracted_files/Applications/Postman Enterprise.app" \
        "combined_root_$ARCH/Applications/Postman Enterprise.app"
    
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

# Parse command line arguments
REMOVE_ALL=false

for arg in "$@"; do
    case $arg in
        --all|--complete)
            REMOVE_ALL=true
            ;;
        --help|-h)
            echo "Usage: sudo $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --all, --complete    Remove both AuthRouter service AND Postman Enterprise.app"
            echo "  --help, -h          Show this help message"
            echo ""
            echo "Default behavior: Removes only the AuthRouter service, preserves Postman app"
            exit 0
            ;;
    esac
done

# Show what will be removed
if [[ "$REMOVE_ALL" == "true" ]]; then
    echo "Running COMPLETE removal - both service and app will be removed..."
else
    echo "Running service-only removal - Postman app will be preserved..."
fi
echo "This will remove:"
echo "  - AuthRouter daemon"
echo "  - LaunchDaemon configuration" 
echo "  - SSL certificates from trust store"
echo "  - Generated certificate files"
echo "  - Hosts file modifications"
if [[ "$REMOVE_ALL" == "true" ]]; then
    echo "  - Postman Enterprise.app"
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

# Remove Postman Enterprise.app if --all flag was specified
if [[ "$REMOVE_ALL" == "true" ]]; then
    echo "Removing Postman Enterprise.app..."
    
    if [ -d "/Applications/Postman Enterprise.app" ]; then
        rm -rf "/Applications/Postman Enterprise.app"
        echo "   Postman Enterprise.app removed"
    else
        echo "  - Postman Enterprise.app not found"
    fi
fi

echo ""
if [[ "$REMOVE_ALL" == "true" ]]; then
    echo "Complete uninstall finished!"
    echo "Both AuthRouter service and Postman Enterprise.app have been removed."
else
    echo "Service uninstall complete!"
    echo ""
    echo "Note: Postman Enterprise.app was NOT removed."
    echo "To remove everything: sudo $0 --all"
fi
UNINSTALL_SCRIPT
    
    chmod +x "combined_root_$ARCH/usr/local/bin/postman/uninstall.sh"

    log ""
    log "=== Step 4: Creating LaunchDaemon Configuration ==="
    
    # Create LaunchDaemon plist with command-line arguments
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
echo "  - Uninstall service: sudo /usr/local/bin/postman/uninstall.sh"
echo "  - Uninstall everything: sudo /usr/local/bin/postman/uninstall.sh --all"

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

    # Reuse already-extracted PKG for welcome message
    if [ -f "extracted_pkg_$ARCH/Resources/welcome.txt" ]; then
        # Use original welcome message
        cp "extracted_pkg_$ARCH/Resources/welcome.txt" "$BUILD_DIR/welcome.txt"
        
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
    
# Phase 4: Final PKG Validation (simplified - size check only)
validate_final_pkg() {
    local pkg_path="$1"
    local arch="$2"
    
    log "INFO" "=== Phase 4A: Final PKG Size Validation ($arch) ==="
    
    if [[ ! -f "$pkg_path" ]]; then
        validation_error "FINAL_PKG" "Final PKG was not created: $pkg_path"
    fi
    
    # Basic size checks
    local pkg_size=$(get_file_size "$pkg_path")
    local min_pkg_size=$((MIN_PKG_SIZE_KB * 1024))
    if [[ $pkg_size -lt $min_pkg_size ]]; then
        validation_error "FINAL_PKG" "Final PKG too small: $(($pkg_size/1024))KB (minimum: ${MIN_PKG_SIZE_KB}KB)"
    fi
    
    # Size validation (PKG shouldn't be unreasonably large) 
    local max_size=$((MAX_PKG_SIZE_MB * 1024 * 1024))
    if [[ $pkg_size -gt $max_size ]]; then
        validation_error "FINAL_PKG" "Final PKG too large: $(($pkg_size/1024/1024))MB > ${MAX_PKG_SIZE_MB}MB"
    fi
    
    
    log "INFO" "Final PKG validated - Size: $(($pkg_size/1024/1024))MB"
    validation_success "FINAL_PKG" "Final PKG size is valid and reasonable"
}

    # Check final PKG size and validate
    if [ -f "$OUTPUT_PATH" ]; then
        # Phase 4A: Validate final PKG
        validate_final_pkg "$OUTPUT_PATH" "$ARCH"
        
        local PKG_SIZE=$(get_file_size "$OUTPUT_PATH")
        local BINARY_SIZE=$(get_file_size "$SCRIPT_DIR/pm-authrouter-$ARCH")
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
        log "INFO" "  sudo /usr/local/bin/postman/uninstall.sh      # Service only"
        log "INFO" "  sudo /usr/local/bin/postman/uninstall.sh --all # Everything"
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

# Build for both architectures in parallel
log "INFO" "=== Building Combined PKG Files ==="

# Run parallel builds
run_parallel_builds

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


# Use a descriptive name that matches the PKG naming convention
MDM_PROFILE_NAME="$SCRIPT_DIR/Postman-Enterprise-${MDM_VERSION}-enterprise01-auth.mobileconfig"

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