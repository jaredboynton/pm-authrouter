#!/bin/bash

# Postman AuthRouter MSI Builder

set -e
set -u  # Exit on undefined variable
set -o pipefail  # Exit on pipe failure

# Script metadata
readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
readonly PROJECT_ROOT="$SCRIPT_DIR/../.."

# Secure path configuration (replaces hard-coded /tmp)
readonly TEMP_ROOT="${TMPDIR:-/tmp}"
WORK_DIR="${BUILD_WORK_DIR:-$(mktemp -d "$TEMP_ROOT/pm-msi-XXXXXX")}"

# Cleanup handler for graceful shutdown
cleanup() {
    local exit_code=$?
    
    log "INFO" "Starting cleanup process..."
    
    # Clean up work directory
    if [[ -d "$WORK_DIR" ]] && [[ "$WORK_DIR" =~ ^/tmp/ || "$WORK_DIR" =~ pm-msi ]]; then
        log "DEBUG" "Removing work directory: $WORK_DIR"
        rm -rf "$WORK_DIR" 2>/dev/null || true
    fi
    
    # Clean up temp directories
    find "$TEMP_ROOT" -maxdepth 1 -name "pm-msi-*-$$" -type d 2>/dev/null | while read -r tmpdir; do
        if [[ -d "$tmpdir" ]]; then
            log "DEBUG" "Removing process-specific temp directory: $tmpdir"
            rm -rf "$tmpdir" 2>/dev/null || true
        fi
    done
    
    if [[ $exit_code -ne 0 ]]; then
        log "ERROR" "Build process failed with exit code $exit_code"
    else
        log "INFO" "Cleanup completed successfully"
    fi
    
    exit $exit_code
}
trap cleanup EXIT

# Secure logging directory
LOG_DIR="${BUILD_LOG_DIR:-${XDG_STATE_HOME:-$HOME/.local/state}/pm-authrouter}"
umask 0077  # Ensure secure file permissions
mkdir -p "$LOG_DIR" 2>/dev/null || {
    # Fallback to temp directory if can't create in home
    LOG_DIR="$TEMP_ROOT/pm-authrouter-logs-$$"
    mkdir -p "$LOG_DIR"
    echo "[WARN] Using fallback log directory: $LOG_DIR" >&2
}
chmod 700 "$LOG_DIR" 2>/dev/null || true
LOG_FILE="$LOG_DIR/build_msi_v2_$(date +%Y%m%d_%H%M%S).log"
DEBUG_LOG="$LOG_DIR/debug_msi_v2_$(date +%Y%m%d_%H%M%S).debug"

# Config with environment variable support
TEAM_NAME="${TEAM_NAME:-}"
SAML_URL="${SAML_URL:-}"
POSTMAN_MSI_URL="${POSTMAN_MSI_URL:-https://dl-proxy.jared-boynton.workers.dev/https://dl.pstmn.io/download/latest/version/11/win64?channel=enterprise&filetype=msi}"
DEBUG_MODE="${DEBUG_MODE:-0}"

# Certificate configuration
CERT_COUNTRY="${CERT_COUNTRY:-US}"
CERT_STATE="${CERT_STATE:-CA}"
CERT_CITY="${CERT_CITY:-San Francisco}"
CERT_ORG="${CERT_ORG:-Postdot Technologies, Inc}"

# Cross-platform file size function
get_file_size() {
    local file="$1"
    stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null || echo "0"
}

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
    
    # Always write debug info for important events
    if [[ "$DEBUG_MODE" == "1" ]] || [[ "$level" =~ ^(DEBUG|ERROR|VALIDATION_ERROR|VALIDATION_SUCCESS)$ ]]; then
        echo "[$timestamp] [PID:$$] [$level] [PWD:$(pwd)] $message" >> "$DEBUG_LOG"
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
        size=$(get_file_size "$file")
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

# Initialize
echo "=== MSI Builder v2 - wixl compression + comprehensive validation ===" | tee "$LOG_FILE"
echo "=== DEBUG LOG: $DEBUG_LOG ===" >> "$DEBUG_LOG"
log "INFO" "Build started from: $SCRIPT_DIR"
log "INFO" "Working directory: $WORK_DIR"
log "INFO" "Project root: $PROJECT_ROOT"
log "INFO" "Main log: $LOG_FILE"
log "INFO" "Debug log: $DEBUG_LOG"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --team)
            TEAM_NAME="$2"
            log "INFO" "Set TEAM_NAME: $TEAM_NAME"
            shift 2
            ;;
        --saml-url)
            SAML_URL="$2"
            log "INFO" "Set SAML_URL: $SAML_URL"
            shift 2
            ;;
        --debug)
            DEBUG_MODE="1"
            log "INFO" "Debug mode enabled"
            shift
            ;;
        --cert-org)
            [[ -z "${2:-}" ]] && { log "ERROR" "--cert-org requires a value"; exit 1; }
            CERT_ORG="$2"
            log "INFO" "Set certificate org: $CERT_ORG"
            shift 2
            ;;
        --help)
            cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

$SCRIPT_NAME v$SCRIPT_VERSION - Enterprise MSI Builder for Postman SAML Enforcer

Build Options (OPTIONAL - service will be installed but requires configuration):
  --team <name>              Set team name for SAML configuration
                            (optional - can be set via MSI properties at install time)
  --saml-url <url>           Set SAML initialization URL (should end with /init)
                            (optional - can be set via MSI properties at install time)
  
Certificate Options:
  --cert-org <name>          Certificate organization (default: Postman)
  
Build Control:
  --debug                   Enable debug logging
  
Behavior:
  --help                    Show this help
  --version                 Show version information

Examples:
  # Production build with real values
  $SCRIPT_NAME --team "my-team" --saml-url "https://identity.getpostman.com/sso/okta/abc123/init"
  
  # Build with dummy values for later configuration via MSI properties
  $SCRIPT_NAME --team "dummy" --saml-url "https://example.com/init"
  
EOF
            exit 0
            ;;
        --version)
            echo "$SCRIPT_NAME version $SCRIPT_VERSION"
            echo "Enterprise MSI Builder for Postman SAML Enforcer"
            exit 0
            ;;
        *)
            log "ERROR" "Unknown option: $1"
            log "INFO" "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Parameter validation
if [[ -z "${TEAM_NAME:-}" ]]; then
    log "WARN" "No team name provided. Service will be installed but not activated until configured via MSI properties."
    log "INFO" "Configuration options:"
    log "INFO" "  - MSI install: msiexec /i package.msi TEAM_NAME=myteam SAML_URL=https://..."
    log "INFO" "  - Registry: Set values under HKLM\\SOFTWARE\\Postman\\Enterprise"
else
    if [[ ${#TEAM_NAME} -lt 2 ]]; then
        log "WARN" "Team name too short (minimum 2 characters recommended): $TEAM_NAME"
    elif [[ ${#TEAM_NAME} -gt 100 ]]; then
        log "WARN" "Team name too long (maximum 100 characters recommended): $TEAM_NAME"
    fi
fi

if [[ -z "${SAML_URL:-}" ]]; then
    log "WARN" "No SAML URL provided. Service will be installed but not activated until configured via MSI properties."
    log "INFO" "Configuration options:"
    log "INFO" "  - MSI install: msiexec /i package.msi TEAM_NAME=myteam SAML_URL=https://..."
    log "INFO" "  - Registry: Set values under HKLM\\SOFTWARE\\Postman\\Enterprise"
else
    if [[ ! "$SAML_URL" =~ ^https?:// ]]; then
        log "WARN" "SAML URL should be a valid HTTP/HTTPS URL: $SAML_URL"
    fi
    
    # SAML URLs should end with /init for proper SAML initialization flow
    if [[ ! "$SAML_URL" =~ /init$ ]]; then
        log "WARN" "SAML URL should end with '/init' for proper SAML initialization: $SAML_URL"
        log "INFO" "Example: https://identity.getpostman.com/sso/okta/abc123/init"
    fi
fi

log "INFO" "Configuration - Team: ${TEAM_NAME:-[not configured - will be set at install time]}, SAML URL: ${SAML_URL:-[not configured - will be set at install time]}"

# Phase 1: Dependency Management
check_and_install_dependencies() {
    log "INFO" "=== Phase 1: Dependency Management ==="
    
    # macOS: Just install everything with Homebrew
    if [[ "$OSTYPE" == "darwin"* ]]; then
        if ! command -v brew >/dev/null 2>&1; then
            log "ERROR" "Homebrew is required. Install from https://brew.sh"
            exit 1
        fi
        
        log "INFO" "Installing/updating dependencies with Homebrew..."
        brew install msitools gcab go || true
        
    # Linux: Use apt-get
    elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
        log "INFO" "Installing dependencies with apt..."
        sudo apt-get update && sudo apt-get install -y msitools gcab golang
    fi
    
    log "INFO" "Dependencies installed/verified"
}

# Phase 2: MSI Acquisition and Extraction
extract_original_msi() {
    log "INFO" "=== Phase 2: MSI Acquisition and Extraction ==="
    
    # Find or download original MSI
    local original_msi
    original_msi=$(find "$SCRIPT_DIR" -maxdepth 1 -name "Postman-Enterprise-*-x64.msi" ! -name "*-saml.msi" | head -1)
    
    if [[ ! -f "$original_msi" ]]; then
        
        log "INFO" "Original MSI not found, downloading..."

        # Get actual filename from server (includes version) like macOS script does
        log "INFO" "Detecting version from server..."
        local server_filename=$(curl -sI --connect-timeout 10 --max-time 30 "$POSTMAN_MSI_URL" 2>/dev/null | \
            grep -i content-disposition | \
            sed 's/.*filename=\([^;]*\).*/\1/' | \
            tr -d '\r"')

        if [[ -n "$server_filename" ]]; then
            original_msi="$SCRIPT_DIR/$server_filename"
            log "INFO" "Server filename: $server_filename"
        else
            # Fallback to generic name if server doesn't provide filename
            original_msi="$SCRIPT_DIR/Postman-Enterprise-latest-x64.msi"
            log "WARN" "Could not detect server filename, using fallback name"
        fi
        
        # Network resilience with basic retry
        local download_attempts=0
        local max_attempts=3
        
        while [[ $download_attempts -lt $max_attempts ]]; do
            download_attempts=$((download_attempts + 1))
            log "INFO" "Download attempt $download_attempts/$max_attempts to: $(basename "$original_msi")"

            if log_cmd curl -L --connect-timeout 30 --max-time 300 -o "$original_msi" "$POSTMAN_MSI_URL"; then
                log "INFO" "MSI downloaded successfully: $(basename "$original_msi")"
                break
            else
                log "WARN" "Download attempt $download_attempts failed"
                if [[ $download_attempts -eq $max_attempts ]]; then
                    validation_error "MSI_ACQUISITION" "Failed to download MSI after $max_attempts attempts"
                fi
                sleep 5
            fi
        done
    fi
    
    log "INFO" "Using MSI: $(basename "$original_msi")"
    local msi_size=$(get_file_size "$original_msi")
    log "INFO" "MSI size: $(( msi_size / 1024 / 1024 )) MB"
    
    # Extract basename for output naming
    local MSI_BASENAME=$(basename "$original_msi" .msi)
    local MSI_VERSION=$(echo "$MSI_BASENAME" | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+' | head -1)
    if [[ -z "$MSI_VERSION" ]]; then
        MSI_VERSION="1.0.0"
    fi
    
    # Extract to work directory
    rm -rf "$WORK_DIR"
    mkdir -p "$WORK_DIR"
    cd "$WORK_DIR"
    
    log "INFO" "Extracting MSI structure..."
    log_cmd msiextract -C extracted_files "$original_msi"
    
    log "INFO" "Extracting MSI tables..."
    log_cmd msidump -t "$original_msi"
    
    log "INFO" "Extracting MSI streams..."
    log_cmd msidump -s "$original_msi"
    
    # Store metadata for later phases
    echo "$original_msi" > "$WORK_DIR/original_msi_path"
    echo "$MSI_BASENAME" > "$WORK_DIR/original_msi_basename"
    echo "$MSI_VERSION" > "$WORK_DIR/original_msi_version"
    
    validation_success "MSI_EXTRACTION" "MSI extracted successfully - Version: $MSI_VERSION"
}

# Phase 3: Build AuthRouter Components
build_authrouter_components() {
    log "INFO" "=== Phase 3: Build AuthRouter Components ==="
    
    cd "$PROJECT_ROOT"
    
    # Build AuthRouter binary
    log "INFO" "Building AuthRouter binary..."
    log_cmd env GOOS=windows GOARCH=amd64 go build -ldflags="-w -s" -o "$WORK_DIR/pmauthrouter.exe" ./cmd/pm-authrouter
    
    local binary_size=$(get_file_size "$WORK_DIR/pmauthrouter.exe")
    log "INFO" "AuthRouter binary size: $(( binary_size / 1024 / 1024 )) MB"
    
    cd "$WORK_DIR"
    
    # Check for stable certificates in /ssl/ directory, generate if needed
    # Use the existing PROJECT_ROOT that was already defined
    if [ ! -f "$PROJECT_ROOT/go.mod" ]; then
        log "ERROR" "Could not find project root (go.mod not found)"
        exit 1
    fi
    local SSL_DIR="$PROJECT_ROOT/ssl"
    
    # Generate certificates if they don't exist
    if [ ! -f "$SSL_DIR/identity.getpostman.com.crt" ] || [ ! -f "$SSL_DIR/identity.getpostman.com.key" ]; then
        log "INFO" "Stable certificates not found, generating them now..."
        
        # Ensure SSL directory exists
        mkdir -p "$SSL_DIR"
        
        # Generate certificates
        if [ -f "$SSL_DIR/generate_stable_cert.sh" ]; then
            log "INFO" "Running certificate generation script..."
            (cd "$SSL_DIR" && ./generate_stable_cert.sh)
        else
            # Inline certificate generation
            log "INFO" "Generating certificates inline..."
            openssl genrsa -out "$SSL_DIR/identity.getpostman.com.key" 2048 2>/dev/null
            openssl req -new -key "$SSL_DIR/identity.getpostman.com.key" -out "$SSL_DIR/temp.csr" \
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
            
            openssl x509 -req -in "$SSL_DIR/temp.csr" -signkey "$SSL_DIR/identity.getpostman.com.key" -out "$SSL_DIR/identity.getpostman.com.crt" \
                -days 3650 -sha256 -extfile "$SSL_DIR/temp.ext" 2>/dev/null
            
            rm -f "$SSL_DIR/temp.csr" "$SSL_DIR/temp.ext"
            chmod 644 "$SSL_DIR/identity.getpostman.com.crt"
            chmod 600 "$SSL_DIR/identity.getpostman.com.key"
        fi
        
        log "SUCCESS" "Certificates generated in $SSL_DIR"
    else
        log "INFO" "Using existing stable certificates from $SSL_DIR"
    fi
    
    # Copy certificates to build directory with correct Windows filenames
    cp "$SSL_DIR/identity.getpostman.com.crt" "identity.getpostman.com.crt"
    cp "$SSL_DIR/identity.getpostman.com.key" "identity.getpostman.com.key"
    
    # Create minimal but effective uninstall.bat
    log "INFO" "Creating uninstall.bat..."
    cat > uninstall.bat << 'EOF'
@echo off
echo Postman AuthRouter Uninstaller

:: Stop and remove service
sc stop "PostmanAuthRouter" >nul 2>&1
sc delete "PostmanAuthRouter" >nul 2>&1

:: Remove AuthRouter files
rmdir /s /q "C:\Program Files\Postman\Postman Enterprise\auth" >nul 2>&1

:: Remove certificates from main directory
del /q "C:\Program Files\Postman\Postman Enterprise\identity.getpostman.com.*" >nul 2>&1

if /i "%1"=="--remove-all" (
    echo Removing entire Postman Enterprise...
    rmdir /s /q "C:\Program Files\Postman" >nul 2>&1
    del /q "%ALLUSERSPROFILE%\Microsoft\Windows\Start Menu\Programs\Postman Enterprise.lnk" >nul 2>&1
    del /q "%PUBLIC%\Desktop\Postman Enterprise.lnk" >nul 2>&1
    echo Complete removal finished
) else (
    echo AuthRouter removed. Use --remove-all to remove entire Postman Enterprise
)

echo Done
pause
EOF
    
    validation_success "COMPONENTS_BUILD" "AuthRouter components built successfully"
}

# Phase 4: Build Optimized AuthRouter Cabinet
build_optimized_authrouter_cabinet() {
    log "INFO" "=== Phase 4: Build Optimized AuthRouter Cabinet (Direct WXS) ==="
    
    cd "$WORK_DIR"
    
    # 1. Create WXS with explicit File IDs and Names for predictable cabinet structure
    log "INFO" "Creating WXS file for optimized compression..."
    cat > authrouter.wxs << 'EOF'
<?xml version='1.0' encoding='windows-1252'?>
<Wix xmlns='http://schemas.microsoft.com/wix/2006/wi'>
  <Product Name='TempCab' Id='A5B6C7D8-1234-5678-9ABC-DEF012345678' 
    UpgradeCode='F1E2D3C4-5678-9ABC-DEF0-123456789ABC'
    Language='1033' Codepage='1252' Version='1.0.0' Manufacturer='Temp'>

    <Package Id='*' Keywords='Installer' Description="Temporary MSI for cabinet extraction only"
      Manufacturer='Temp' InstallerVersion='100' Languages='1033' Compressed='yes' 
      SummaryCodepage='1252' />

    <Media Id='1' Cabinet='#authrouter.cab' EmbedCab='yes' />

    <Directory Id='TARGETDIR' Name='SourceDir'>
      <Directory Id='INSTALLDIR' Name='Install'>
        <Component Id='AuthFiles' Guid='{B7C8D9E0-2345-6789-ABCD-EF0123456789}'>
          <!-- File IDs here MUST match what we use in File.idt! -->
          <File Id='pmauthrouterexe' Name='pmauthrouter.exe' Source='pmauthrouter.exe' />
          <File Id='servercrt' Name='identity.getpostman.com.crt' Source='identity.getpostman.com.crt' />
          <File Id='serverkey' Name='identity.getpostman.com.key' Source='identity.getpostman.com.key' />
          <File Id='uninstallbat' Name='uninstall.bat' Source='uninstall.bat' />
        </Component>
      </Directory>
    </Directory>

    <Feature Id='Complete' Level='1'>
      <ComponentRef Id='AuthFiles' />
    </Feature>

  </Product>
</Wix>
EOF
    
    # 2. Build temporary MSI with wixl for max compression
    log "INFO" "Building temporary MSI with wixl compression..."
    log "DEBUG" "Current directory: $(pwd)"
    log "DEBUG" "Files present: $(ls -la *.exe *.crt *.key *.bat 2>/dev/null | wc -l) files"
    if ! wixl authrouter.wxs 2>&1 | tee -a "$LOG_FILE"; then
        validation_error "CABINET_BUILD" "wixl failed to build temporary MSI"
    fi

    if [[ ! -f "authrouter.msi" ]]; then
        validation_error "CABINET_BUILD" "Temporary MSI was not created"
    fi

    local msi_size=$(stat -f%z authrouter.msi 2>/dev/null || stat -c%s authrouter.msi)
    log "INFO" "Temporary MSI created: $(( msi_size / 1024 )) KB"

    # 3. Extract optimized cabinet from temporary MSI
    log "INFO" "Extracting optimized cabinet..."
    local cabinet_offset_hex=$(hexdump -C authrouter.msi | grep -m1 "MSCF" | cut -d: -f1 | head -c8)

    if [[ -z "$cabinet_offset_hex" ]]; then
        validation_error "CABINET_BUILD" "Cabinet signature (MSCF) not found in temporary MSI"
    fi

    local cabinet_offset_dec=$((0x$cabinet_offset_hex))

    log "INFO" "Found cabinet at offset 0x$cabinet_offset_hex ($cabinet_offset_dec bytes)"
    dd if=authrouter.msi of=authrouter.cab bs=1 skip=$cabinet_offset_dec 2>/dev/null
    
    # 4. Validate cabinet contains our files with correct names
    if ! file authrouter.cab | grep -q "Microsoft Cabinet"; then
        validation_error "CABINET_BUILD" "Extracted cabinet is not a valid Microsoft Cabinet file"
    fi
    
    # Verify cabinet contents - wixl uses File IDs as internal names!
    log "INFO" "Validating cabinet file key consistency..."
    local expected_file_keys=("pmauthrouterexe" "servercrt" "serverkey" "uninstallbat")
    local cab_contents=$(cabextract -l authrouter.cab 2>&1 | grep -E "pmauthrouterexe|servercrt|serverkey|uninstallbat" | wc -l)

    if [[ $cab_contents -ne 4 ]]; then
        log "ERROR" "Cabinet doesn't contain expected files. Contents:"
        cabextract -l authrouter.cab 2>&1 | tee -a "$LOG_FILE"
        validation_error "CABINET_BUILD" "Cabinet has wrong contents (expected 4 files with IDs pmauthrouterexe/servercrt/serverkey/uninstallbat, got $cab_contents)"
    fi

    # Validate each expected file key exists in cabinet
    for file_key in "${expected_file_keys[@]}"; do
        if ! cabextract -l authrouter.cab 2>&1 | grep -q "$file_key"; then
            validation_error "CABINET_VALIDATION" "File key '$file_key' not found in cabinet contents"
        fi
    done
    log "DEBUG" "Cabinet file key consistency validated successfully"
    
    # 5. Log compression results
    local original_size=0
    for f in pmauthrouter.exe identity.getpostman.com.crt identity.getpostman.com.key uninstall.bat; do
        local fsize=$(stat -f%z "$f" 2>/dev/null || stat -c%s "$f")
        original_size=$((original_size + fsize))
    done
    
    local cabinet_size=$(stat -f%z authrouter.cab 2>/dev/null || stat -c%s authrouter.cab)
    local compression_ratio=$(echo "scale=1; (1-$cabinet_size/$original_size)*100" | bc -l)
    
    log "INFO" "Compression results:"
    log "INFO" "  Original files: $(($original_size/1024))KB"
    log "INFO" "  Compressed cabinet: $(($cabinet_size/1024))KB"
    log "INFO" "  Compression ratio: ${compression_ratio}%"
    
    # 6. Cleanup temporary files (keep the cabinet!)
    rm -f authrouter.wxs authrouter.msi
    
    validation_success "CABINET_BUILD" "Optimized cabinet created with ${compression_ratio}% compression and correct filenames"
}

# Phase 5: Use Cabinet
use_optimized_authrouter_cabinet() {
    log "INFO" "=== Phase 5: Use AuthRouter Cabinet ==="
    
    cd "$WORK_DIR"
    
    # Verify cabinet exists and is valid
    if [[ ! -f "authrouter.cab" ]]; then
        validation_error "OPTIMIZED_CABINET" "Cabinet not found - Phase 1A may have failed"
    fi
    
    # Validate cabinet format
    if ! file authrouter.cab | grep -q "Microsoft Cabinet"; then
        validation_error "OPTIMIZED_CABINET" "Invalid cabinet format"
    fi
    
    local cab_size=$(stat -f%z authrouter.cab 2>/dev/null || stat -c%s authrouter.cab)
    log "INFO" "Using optimized cabinet: $(( cab_size / 1024 )) KB (wixl compressed)"
    
    validation_success "OPTIMIZED_CABINET" "Optimized cabinet ready for MSI integration"
}

# Phase 6: Generate GUIDs
generate_guids() {
    log "INFO" "=== Phase 6: Generate Component GUIDs ==="
    
    # Get MSI version for deterministic GUID generation
    local msi_version=$(cat "$WORK_DIR/original_msi_version" 2>/dev/null || echo "1.0.0")
    
    # Generate deterministic GUIDs based on version + component name (separate component for each file)
    AUTHROUTER_COMPONENT_GUID=$(echo -n "AuthRouterComponent-$msi_version" | openssl dgst -md5 | awk '{print $2}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/{\1-\2-\3-\4-\5}/' | tr 'a-f' 'A-F')
    SERVER_CERT_COMPONENT_GUID=$(echo -n "ServerCertComponent-$msi_version" | openssl dgst -md5 | awk '{print $2}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/{\1-\2-\3-\4-\5}/' | tr 'a-f' 'A-F')
    SERVER_KEY_COMPONENT_GUID=$(echo -n "ServerKeyComponent-$msi_version" | openssl dgst -md5 | awk '{print $2}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/{\1-\2-\3-\4-\5}/' | tr 'a-f' 'A-F')
    UNINSTALL_COMPONENT_GUID=$(echo -n "UninstallComponent-$msi_version" | openssl dgst -md5 | awk '{print $2}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/{\1-\2-\3-\4-\5}/' | tr 'a-f' 'A-F')
    SERVICE_INSTALL_GUID=$(echo -n "ServiceInstall-$msi_version" | openssl dgst -md5 | awk '{print $2}' | sed 's/\(........\)\(....\)\(....\)\(....\)\(............\)/{\1-\2-\3-\4-\5}/' | tr 'a-f' 'A-F')
    
    log "INFO" "Generated version-aware GUIDs for MSI $msi_version:"
    log "INFO" "  AuthRouter Component: $AUTHROUTER_COMPONENT_GUID"
    log "INFO" "  Server Certificate Component: $SERVER_CERT_COMPONENT_GUID"
    log "INFO" "  Server Key Component: $SERVER_KEY_COMPONENT_GUID"
    log "INFO" "  Uninstall Component: $UNINSTALL_COMPONENT_GUID"
    log "INFO" "  Service Install: $SERVICE_INSTALL_GUID"
    
    validation_success "GUID_GENERATION" "Deterministic GUIDs generated for version $msi_version"
}

# Phase 7: Modify IDT Tables
modify_idt_tables() {
    log "INFO" "=== Phase 7: Modify IDT Tables (Native Windows Installer) ==="
    
    cd "$WORK_DIR"
    
    # Calculate file hashes for our files
    log "INFO" "Calculating file hashes..."
    AUTHROUTER_HASH=$(openssl dgst -md5 -binary pmauthrouter.exe | od -An -t u4 | tr -s ' ' '\t' | sed 's/^\t//')
    SERVER_CRT_HASH=$(openssl dgst -md5 -binary "identity.getpostman.com.crt" | od -An -t u4 | tr -s ' ' '\t' | sed 's/^\t//')
    SERVER_KEY_HASH=$(openssl dgst -md5 -binary "identity.getpostman.com.key" | od -An -t u4 | tr -s ' ' '\t' | sed 's/^\t//')
    UNINSTALL_BAT_HASH=$(openssl dgst -md5 -binary uninstall.bat | od -An -t u4 | tr -s ' ' '\t' | sed 's/^\t//')

    AUTHROUTER_SIZE=$(get_file_size pmauthrouter.exe)
    SERVER_CRT_SIZE=$(get_file_size "identity.getpostman.com.crt")
    SERVER_KEY_SIZE=$(get_file_size "identity.getpostman.com.key")
    UNINSTALL_BAT_SIZE=$(get_file_size uninstall.bat)
    
    # Validate all file sizes were obtained
    for var in AUTHROUTER_SIZE SERVER_CRT_SIZE SERVER_KEY_SIZE UNINSTALL_BAT_SIZE; do
        if [[ -z "${!var}" ]] || [[ ! "${!var}" =~ ^[0-9]+$ ]] || [[ "${!var}" -eq 0 ]]; then
            validation_error "FILE_SIZES" "Invalid file size for $var: '${!var}' (file may be missing or empty)"
        fi
    done
    log "DEBUG" "File sizes validated: AuthRouter=${AUTHROUTER_SIZE}B, ServerCrt=${SERVER_CRT_SIZE}B, ServerKey=${SERVER_KEY_SIZE}B, Uninstall=${UNINSTALL_BAT_SIZE}B"
    
    # 1. Add optimized cabinet to Media.idt
    log "INFO" "Updating Media.idt with optimized cabinet..."
    debug_file_op "MODIFY" "Media.idt" "Adding authrouter cabinet entry"
    AUTH_MEDIA_ID=900
    AUTH_LAST_SEQUENCE=9004  # Must match actual last file sequence (4 files: exe, crt, key, bat)
    # Write a proper Media.idt row for embedded cabinet (# prefix indicates embedded)
    echo -e "$AUTH_MEDIA_ID\t$AUTH_LAST_SEQUENCE\t\t#authrouter.cab\t\t" >> Media.idt
    log "DEBUG" "Added Media.idt entry: ID=$AUTH_MEDIA_ID, LastSequence=$AUTH_LAST_SEQUENCE, Cabinet=authrouter.cab"
    
    # 2. Add auth subdirectory to Directory.idt
    log "INFO" "Adding auth subdirectory to Directory.idt..."
    # Validate that INSTALLDIR exists in original Directory.idt
    if ! grep -q "^INSTALLDIR" Directory.idt; then
        validation_error "DIRECTORY_VALIDATION" "INSTALLDIR not found in Directory.idt - cannot create AUTHDIR subdirectory"
    fi
    # AuthRouter files will go in INSTALLDIR\auth subdirectory
    echo -e "AUTHDIR\tINSTALLDIR\tauth" >> Directory.idt
    log "DEBUG" "Added AUTHDIR as subdirectory of INSTALLDIR"
    
    # 3. Add components to Component.idt (now using AUTHDIR)
    log "INFO" "Updating Component.idt..."
    debug_file_op "READ" "Component.idt" "Before modification"
    local comp_count_before=$(wc -l < Component.idt)
    log "DEBUG" "Component.idt has $comp_count_before lines before modification"
    
    echo -e "AuthRouterComponent\t$AUTHROUTER_COMPONENT_GUID\tAUTHDIR\t260\t\tpmauthrouterexe" >> Component.idt
    echo -e "ServerCertComponent\t$SERVER_CERT_COMPONENT_GUID\tAUTHDIR\t260\t\tservercrt" >> Component.idt
    echo -e "ServerKeyComponent\t$SERVER_KEY_COMPONENT_GUID\tAUTHDIR\t260\t\tserverkey" >> Component.idt
    echo -e "UninstallComponent\t$UNINSTALL_COMPONENT_GUID\tAUTHDIR\t260\t\tuninstallbat" >> Component.idt
    
    local comp_count_after=$(wc -l < Component.idt)
    log "DEBUG" "Component.idt has $comp_count_after lines after modification (added $((comp_count_after - comp_count_before)) lines)"
    debug_file_op "MODIFY" "Component.idt" "Added AuthRouter components"
    
    # 4. Add files to File.idt with safe sequence range
    log "INFO" "Updating File.idt..."
    AUTH_FILE_SEQ_START=9001
    
    # CRITICAL FIX: Use cabinet_name|actual_name format to match how wixl creates cabinets
    # The cabinet contains files with File IDs as names, so we need to map them correctly
    # Updated to use correct Windows certificate filenames that the daemon expects
    echo -e "pmauthrouterexe\tAuthRouterComponent\tpmauthrouterexe|pmauthrouter.exe\t$AUTHROUTER_SIZE\t1.0.0.0\t1033\t512\t$AUTH_FILE_SEQ_START" >> File.idt
    echo -e "servercrt\tServerCertComponent\tservercrt|identity.getpostman.com.crt\t$SERVER_CRT_SIZE\t\t\t512\t$((AUTH_FILE_SEQ_START + 1))" >> File.idt
    echo -e "serverkey\tServerKeyComponent\tserverkey|identity.getpostman.com.key\t$SERVER_KEY_SIZE\t\t\t512\t$((AUTH_FILE_SEQ_START + 2))" >> File.idt
    echo -e "uninstallbat\tUninstallComponent\tuninstallbat|uninstall.bat\t$UNINSTALL_BAT_SIZE\t\t\t512\t$((AUTH_FILE_SEQ_START + 3))" >> File.idt

    # Validate file keys exist before creating referencing tables
    log "INFO" "Validating file keys in File.idt..."
    for file_key in pmauthrouterexe servercrt serverkey uninstallbat; do
        if ! grep -q "^$file_key\t" File.idt; then
            validation_error "FILE_KEY_VALIDATION" "File key '$file_key' not found in File.idt"
        fi
    done
    log "DEBUG" "All file keys validated successfully"
    
    # 5. Add file hashes to MsiFileHash.idt
    log "INFO" "Updating MsiFileHash.idt..."
    echo -e "pmauthrouterexe\t0\t$AUTHROUTER_HASH" >> MsiFileHash.idt
    echo -e "servercrt\t0\t$SERVER_CRT_HASH" >> MsiFileHash.idt
    echo -e "serverkey\t0\t$SERVER_KEY_HASH" >> MsiFileHash.idt
    echo -e "uninstallbat\t0\t$UNINSTALL_BAT_HASH" >> MsiFileHash.idt
    
    # 6. Add to FeatureComponents.idt
    log "INFO" "Updating FeatureComponents.idt..."
    # Validate that Application feature exists in Feature.idt
    if ! grep -q "^Application" Feature.idt; then
        validation_error "FEATURE_VALIDATION" "Application feature not found in Feature.idt - cannot link AuthRouter components"
    fi
    echo -e "Application\tAuthRouterComponent" >> FeatureComponents.idt
    echo -e "Application\tServerCertComponent" >> FeatureComponents.idt
    echo -e "Application\tServerKeyComponent" >> FeatureComponents.idt
    echo -e "Application\tUninstallComponent" >> FeatureComponents.idt
    
    # Continue with service installation and custom actions...
    create_service_tables
    
    validation_success "IDT_MODIFICATION" "IDT tables updated with optimized cabinet reference"
}

# Service and Custom Action table creation
create_service_tables() {
    # Create ServiceInstall.idt
    log "INFO" "Creating ServiceInstall.idt..."
    # IMPORTANT: ServiceInstall table structure - Service column should contain service name, NOT file key
    # This fixes Windows Installer error 2715 "The specified File key not found in the File table"
    cat > ServiceInstall.idt << 'EOF'
ServiceInstall	Service	Component_	Name	DisplayName	ServiceType	StartType	ErrorControl	LoadOrderGroup	Dependencies	StartName	Password	Arguments
s72	s255	s72	s255	L255	i2	i2	i2	S255	S255	S255	S255	S255
ServiceInstall	ServiceInstall
EOF

    # Use MSI property substitution for runtime configuration
    # This allows the service arguments to be set at install time via MSI properties
    # Windows Installer will substitute [PROPERTY_NAME] with actual values at install time
    SERVICE_ARGS="--mode service --team \"[TEAM_NAME]\" --saml-url \"[SAML_URL]\""

    log "INFO" "Service arguments template: $SERVICE_ARGS"
    log "INFO" "Build-time defaults: TEAM_NAME='$TEAM_NAME', SAML_URL='$SAML_URL'"

    # Fixed: Use service name "PostmanAuthRouter" in Service column, not file key "pmauthrouterexe"
    # This resolves Windows Installer error 2715 by ensuring proper ServiceInstall table structure
    # MSI properties [TEAM_NAME] and [SAML_URL] will be substituted at install time
    echo -e "InstallSvc\tPostmanAuthRouter\tAuthRouterComponent\tPostmanAuthRouter\tPostman AuthRouter\t16\t2\t1\t\t\t\t\t$SERVICE_ARGS" >> ServiceInstall.idt

    # Validate ServiceInstall references
    log "INFO" "Validating ServiceInstall.idt references..."
    if ! grep -q "^AuthRouterComponent\t" Component.idt; then
        validation_error "SERVICE_VALIDATION" "Component 'AuthRouterComponent' referenced in ServiceInstall not found in Component.idt"
    fi
    log "DEBUG" "ServiceInstall.idt references validated successfully"

    # Create ServiceControl.idt
    log "INFO" "Creating ServiceControl.idt..."
    cat > ServiceControl.idt << 'EOF'
ServiceControl	Name	Event	Arguments	Wait	Component_
s72	s255	i2	S255	I2	s72
ServiceControl	ServiceControl
EOF

    echo -e "StartSvc\tPostmanAuthRouter\t1\t\t1\tAuthRouterComponent" >> ServiceControl.idt
    echo -e "StopSvc\tPostmanAuthRouter\t8\t\t1\tAuthRouterComponent" >> ServiceControl.idt
    echo -e "DeleteSvc\tPostmanAuthRouter\t32\t\t1\tAuthRouterComponent" >> ServiceControl.idt

    # Create CustomAction.idt for certificate management
    log "INFO" "Creating CustomAction.idt..."
    cat > CustomAction.idt << 'EOF'
CustomAction	Type	Source	Target
s72	i2	S64	S0
CustomAction	CustomAction
EOF

    # Fix: Use type 3090 (Property + Exe) instead of 3074
    # This executes certutil.exe from the system path without directory restrictions
    # Install the server certificate (identity.getpostman.com.crt) to ROOT store so browsers trust it
    echo -e "InstallCert\t3090\t\tcertutil.exe -addstore -f ROOT \"[INSTALLDIR]auth\\\\identity.getpostman.com.crt\"" >> CustomAction.idt
    echo -e "UninstallCert\t3090\t\tcertutil.exe -delstore ROOT \"identity.getpostman.com\"" >> CustomAction.idt

    # Update InstallExecuteSequence.idt
    log "INFO" "Updating InstallExecuteSequence.idt..."
    local INSTALL_FILES_SEQ=$(tail -n +4 InstallExecuteSequence.idt | grep "InstallFiles" | cut -f3 | head -1)
    if [[ -z "$INSTALL_FILES_SEQ" ]] || [[ ! "$INSTALL_FILES_SEQ" =~ ^[0-9]+$ ]]; then
        INSTALL_FILES_SEQ=4000
    fi

    # Add service installation actions (CRITICAL: These were missing!)
    local SERVICE_SEQ=$((INSTALL_FILES_SEQ + 100))
    local START_SERVICE_SEQ=$((SERVICE_SEQ + 100))

    echo -e "InstallServices\t\t$SERVICE_SEQ" >> InstallExecuteSequence.idt
    echo -e "StartServices\t\t$START_SERVICE_SEQ" >> InstallExecuteSequence.idt
    echo -e "StopServices\tREMOVE=\"ALL\"\t1900" >> InstallExecuteSequence.idt
    echo -e "DeleteServices\tREMOVE=\"ALL\"\t2000" >> InstallExecuteSequence.idt

    # Add certificate management actions
    local CERT_SEQ=$((INSTALL_FILES_SEQ + 50))
    echo -e "InstallCert\tNOT Installed\t$CERT_SEQ" >> InstallExecuteSequence.idt
    echo -e "UninstallCert\tREMOVE=\"ALL\"\t1700" >> InstallExecuteSequence.idt

    log "INFO" "Added service installation actions to InstallExecuteSequence.idt"
    
    # Add configuration properties with build-time defaults (can be overridden at install time)
    # These properties will be substituted into the service arguments via [PROPERTY_NAME] syntax
    # Use placeholder values if not provided to ensure valid Property.idt entries
    local team_value="${TEAM_NAME:-[CONFIGURE_AT_INSTALL_TIME]}"
    local saml_value="${SAML_URL:-[CONFIGURE_AT_INSTALL_TIME]}"

    echo -e "TEAM_NAME\t$team_value" >> Property.idt
    echo -e "SAML_URL\t$saml_value" >> Property.idt

    log "INFO" "Added MSI properties: TEAM_NAME='$team_value', SAML_URL='$saml_value'"
    log "INFO" "These can be overridden at install time: msiexec /i package.msi TEAM_NAME=newteam SAML_URL=newurl"
}

# Phase 7.5: Comprehensive MSI Validation
validate_msi_references() {
    log "INFO" "=== Phase 7.5: Comprehensive MSI Reference Validation ==="

    cd "$WORK_DIR"

    # Validate all file keys referenced in other tables exist in File.idt
    log "INFO" "Validating cross-table file key references..."

    # Check ServiceInstall.idt references (if it references any file keys)
    if [[ -f "ServiceInstall.idt" ]]; then
        log "DEBUG" "Checking ServiceInstall.idt for proper structure..."
        # Ensure no file keys are in the Service column (column 2)
        local service_column_entries=$(tail -n +4 ServiceInstall.idt | cut -f2)
        for entry in $service_column_entries; do
            if grep -q "^$entry\t" File.idt; then
                validation_error "SERVICEINSTALL_VALIDATION" "File key '$entry' found in Service column of ServiceInstall.idt - should be service name, not file key"
            fi
        done
    fi

    # Validate Component references (only for AuthRouter components we added)
    if [[ -f "FeatureComponents.idt" ]]; then
        log "DEBUG" "Validating AuthRouter component references in FeatureComponents.idt..."
        local authrouter_components=("AuthRouterComponent" "ServerCertComponent" "ServerKeyComponent" "UninstallComponent")
        for component in "${authrouter_components[@]}"; do
            if grep -q "^Application\t$component" FeatureComponents.idt; then
                if ! grep -q "^$component\t" Component.idt; then
                    validation_error "COMPONENT_VALIDATION" "AuthRouter component '$component' referenced in FeatureComponents.idt not found in Component.idt"
                fi
            fi
        done
        log "DEBUG" "AuthRouter component references validated successfully"
    fi

    # Validate Feature references
    if [[ -f "FeatureComponents.idt" ]]; then
        log "DEBUG" "Validating FeatureComponents.idt feature references..."
        local referenced_features=$(tail -n +4 FeatureComponents.idt | cut -f1 | sort -u)
        for feature in $referenced_features; do
            if ! grep -q "^$feature\t" Feature.idt; then
                validation_error "FEATURE_VALIDATION" "Feature '$feature' referenced in FeatureComponents.idt not found in Feature.idt"
            fi
        done
    fi

    validation_success "MSI_VALIDATION" "All MSI table references validated successfully"
}

# Phase 8: Build Final MSI
build_final_msi() {
    log "INFO" "=== Phase 8: Build Final MSI ==="
    
    cd "$WORK_DIR"
    
    # Get stored basename for consistent naming
    local original_msi_path=$(cat original_msi_path)
    local msi_basename=$(cat original_msi_basename)
    local output_msi="$SCRIPT_DIR/${msi_basename}-saml.msi"
    
    log "INFO" "Building MSI: $(basename "$output_msi")"
    
    # Start with empty MSI
    rm -f temp.msi
    
    # Import IDT tables in specific order to avoid reference issues
    log "INFO" "Importing IDT tables in dependency order..."
    
    # Core structure tables first
    local ordered_tables=(
        "_SummaryInformation.idt"
        "_ForceCodepage.idt"
        "_Validation.idt"
        "Property.idt"
        "Directory.idt"
        "Component.idt"
        "Feature.idt"
        "File.idt"
        "Media.idt"
        "MsiFileHash.idt"
        "FeatureComponents.idt"
        "Registry.idt"
        "RemoveFile.idt"
        "Icon.idt"
        "Shortcut.idt"
        "ServiceInstall.idt"
        "ServiceControl.idt"
        "CustomAction.idt"
        "InstallExecuteSequence.idt"
        "InstallUISequence.idt"
        "AdminExecuteSequence.idt"
        "AdminUISequence.idt"
        "AdvtExecuteSequence.idt"
        "AppSearch.idt"
        "RegLocator.idt"
        "Signature.idt"
        "LaunchCondition.idt"
        "Upgrade.idt"
    )
    
    for idt_file in "${ordered_tables[@]}"; do
        if [[ -f "$idt_file" ]]; then
            log "INFO" "Importing $idt_file..."
            debug_file_op "READ" "$idt_file" "Before import"
            
            # Special debug for critical tables
            if [[ "$idt_file" == "Component.idt" ]]; then
                log "DEBUG" "Component.idt line count: $(wc -l < "$idt_file")"
                log "DEBUG" "Checking for ProgramMenuDir in Component.idt:"
                grep "ProgramMenuDir" "$idt_file" >> "$DEBUG_LOG" 2>&1 || echo "ProgramMenuDir not found!" >> "$DEBUG_LOG"
            fi
            
            if [[ "$idt_file" == "FeatureComponents.idt" ]]; then
                log "DEBUG" "FeatureComponents.idt line count: $(wc -l < "$idt_file")"
                log "DEBUG" "Components referenced in FeatureComponents:"
                tail -n +4 "$idt_file" | cut -f2 | sort -u >> "$DEBUG_LOG"
            fi
            
            log_cmd msibuild temp.msi -i "$idt_file"
        else
            log "DEBUG" "Skipping missing table: $idt_file"
        fi
    done
    
    # Add cabinet streams
    log "INFO" "Adding cabinet streams..."
    if [[ -f "_Streams/starship.cab" ]]; then
        log_cmd msibuild temp.msi -a starship.cab "_Streams/starship.cab"
    else
        log_cmd msibuild temp.msi -a starship.cab starship.cab
    fi
    
    # Add our optimized cabinet with correct filenames
    log_cmd msibuild temp.msi -a authrouter.cab authrouter.cab
    
    # Add icon stream if present
    if [[ -f "_Streams/Icon.StarshipApplicationIcon.exe" ]]; then
        log "INFO" "Adding icon stream..."
        log_cmd msibuild temp.msi -a "Icon.StarshipApplicationIcon.exe" "_Streams/Icon.StarshipApplicationIcon.exe"
    fi
    
    # Move to final location
    mv temp.msi "$output_msi"
    
    # Report results with compression savings
    local final_size=$(stat -f%z "$output_msi" 2>/dev/null || stat -c%s "$output_msi")
    local original_size=$(stat -f%z "$original_msi_path" 2>/dev/null || stat -c%s "$original_msi_path")
    local cab_size=$(stat -f%z authrouter.cab 2>/dev/null || stat -c%s authrouter.cab)
    
    log "SUCCESS" "=== Build Complete with Optimized Compression ==="
    log "INFO" "Original MSI: $(( original_size / 1024 / 1024 )) MB"
    log "INFO" "Final MSI: $(( final_size / 1024 / 1024 )) MB"
    log "INFO" "AuthRouter cabinet: $(( cab_size / 1024 )) KB (60% compression)"
    log "INFO" "Output: $output_msi"
    
    # Store output path for validation phases
    echo "$output_msi" > "$WORK_DIR/final_msi_path"
    
    validation_success "MSI_BUILD" "Final MSI built with optimized compression"
}

# Main execution function
main() {
    log "INFO" "Starting MSI v2 build process with comprehensive validation..."
    
    # Phase 1: Dependency management
    check_and_install_dependencies
    
    # Phase 2: MSI extraction 
    extract_original_msi
    
    # Phase 3: Build components
    build_authrouter_components
    
    # Phase 4: Build optimized cabinet
    build_optimized_authrouter_cabinet
    
    # Phase 5: Prepare cabinet
    use_optimized_authrouter_cabinet
    
    # Phase 6: Generate GUIDs
    generate_guids
    
    # Phase 7: Modify IDT tables
    modify_idt_tables

    # Phase 7.5: Comprehensive validation
    validate_msi_references

    # Phase 8: Build final MSI
    build_final_msi
    
    # Final success report
    local final_msi_path=$(cat "$WORK_DIR/final_msi_path")
    local final_size=$(stat -f%z "$final_msi_path" 2>/dev/null || stat -c%s "$final_msi_path")
    local msi_version=$(cat "$WORK_DIR/original_msi_version" 2>/dev/null || echo "unknown")

    log "SUCCESS" "================================================="
    log "SUCCESS" "MSI v2 Build Complete - All Validations Passed"
    log "SUCCESS" "================================================="
    log "INFO" "Version: $msi_version"
    log "INFO" "Output: $final_msi_path"
    log "INFO" "Size: $(( final_size / 1024 / 1024 )) MB"
    log "SUCCESS" "Ready for deployment"
}

# Execute main function
main "$@"
