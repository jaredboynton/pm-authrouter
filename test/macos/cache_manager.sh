#!/bin/bash

# cache_manager.sh - Artifact caching system for macOS tests
# Provides intelligent caching of Go binaries, PKG files, and certificates

set -e

# Cache configuration
CACHE_DIR="$HOME/.postman_test_cache"
CACHE_CONFIG_FILE="$CACHE_DIR/cache.json"
PROJECT_ROOT="$(dirname "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")")"

# Source dependency tracker for intelligent invalidation
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/dependency_tracker.sh" ]]; then
    source "$SCRIPT_DIR/dependency_tracker.sh"
    export CACHE_DIR  # Share cache directory with dependency tracker
fi

# Cache categories - using individual variables for compatibility
CACHE_PATH_go_binary="$CACHE_DIR/binaries"
CACHE_PATH_pkg_files="$CACHE_DIR/packages" 
CACHE_PATH_certificates="$CACHE_DIR/certificates"
CACHE_PATH_test_data="$CACHE_DIR/test_data"

# Initialize cache directory structure
init_cache() {
    mkdir -p "$CACHE_DIR"
    mkdir -p "$CACHE_PATH_go_binary"
    mkdir -p "$CACHE_PATH_pkg_files"
    mkdir -p "$CACHE_PATH_certificates" 
    mkdir -p "$CACHE_PATH_test_data"
    
    # Create cache config if it doesn't exist
    if [ ! -f "$CACHE_CONFIG_FILE" ]; then
        echo '{"version": "1.0", "entries": {}}' > "$CACHE_CONFIG_FILE"
    fi
}

# Calculate file hash
get_file_hash() {
    local file="$1"
    if [ -f "$file" ]; then
        shasum -a 256 "$file" | cut -d' ' -f1
    else
        echo ""
    fi
}

# Calculate directory hash (for source changes)
get_directory_hash() {
    local dir="$1"
    find "$dir" -type f \( -name "*.go" -o -name "go.mod" -o -name "go.sum" \) -exec shasum -a 256 {} \; | sort | shasum -a 256 | cut -d' ' -f1
}

# Get Go source hash
get_go_source_hash() {
    # Use dependency tracker if available
    if command -v track_go_sources >/dev/null 2>&1; then
        # Get hash from dependency tracker which tracks all Go source patterns
        local hash_file="$HASH_CACHE_DIR/go_binary.hash"
        if [[ -f "$hash_file" ]]; then
            cat "$hash_file"
        else
            # Generate initial hash
            cd "$PROJECT_ROOT"
            track_go_sources >/dev/null 2>&1
            if [[ -f "$hash_file" ]]; then
                cat "$hash_file"
            else
                get_directory_hash "$PROJECT_ROOT/cmd"
            fi
        fi
    else
        # Fallback to original method
        get_directory_hash "$PROJECT_ROOT/cmd"
    fi
}

# Check if cached artifact is valid
is_cache_valid() {
    local cache_type="$1"
    local source_hash="$2"
    local cache_file="$3"
    
    if [ ! -f "$cache_file" ]; then
        return 1
    fi
    
    local cached_hash=$(jq -r ".entries.\"$cache_type\".source_hash // empty" "$CACHE_CONFIG_FILE" 2>/dev/null)
    
    if [ "$cached_hash" = "$source_hash" ]; then
        return 0
    else
        return 1
    fi
}

# Update cache metadata
update_cache_metadata() {
    local cache_type="$1"
    local source_hash="$2"
    local cache_file="$3"
    local build_time="$4"
    
    local temp_config=$(mktemp)
    jq ".entries.\"$cache_type\" = {\"source_hash\": \"$source_hash\", \"cache_file\": \"$cache_file\", \"build_time\": $build_time, \"created\": \"$(date -Iseconds)\"}" "$CACHE_CONFIG_FILE" > "$temp_config"
    mv "$temp_config" "$CACHE_CONFIG_FILE"
}

# Cache Go binary
cache_go_binary() {
    local arch="${1:-$(uname -m)}"
    
    # Check if rebuild is needed using dependency tracker
    if command -v check_rebuild_needed >/dev/null 2>&1; then
        if ! check_rebuild_needed "go_binary"; then
            # Sources unchanged, use existing cache
            local cache_file=$(find "$CACHE_PATH_go_binary" -name "pm-authrouter-$arch-*" -type f -mtime -1 | head -1)
            if [[ -n "$cache_file" && -f "$cache_file" ]]; then
                echo "Using cached Go binary (sources unchanged): $cache_file"
                return 0
            fi
        fi
    fi
    
    local source_hash=$(get_go_source_hash)
    local cache_file="$CACHE_PATH_go_binary/pm-authrouter-$arch-$source_hash"
    
    if is_cache_valid "go_binary_$arch" "$source_hash" "$cache_file"; then
        echo "Using cached Go binary: $cache_file"
        return 0
    fi
    
    echo "Building Go binary for $arch (sources changed)..."
    local start_time=$(date +%s)
    
    cd "$PROJECT_ROOT"
    GOOS=darwin GOARCH="$([[ "$arch" == "arm64" ]] && echo "arm64" || echo "amd64")" go build -o "$cache_file" ./cmd/pm-authrouter
    
    local end_time=$(date +%s)
    local build_time=$((end_time - start_time))
    
    update_cache_metadata "go_binary_$arch" "$source_hash" "$cache_file" "$build_time"
    echo "Go binary cached in ${build_time}s: $cache_file"
}

# Get cached Go binary path
get_cached_go_binary() {
    local arch="${1:-$(uname -m)}"
    local source_hash=$(get_go_source_hash)
    local cache_file="$CACHE_PATH_go_binary/pm-authrouter-$arch-$source_hash"
    
    if is_cache_valid "go_binary_$arch" "$source_hash" "$cache_file"; then
        echo "$cache_file"
        return 0
    else
        return 1
    fi
}

# Get cached MDM profile path
get_cached_mdm_profile() {
    local original_pkg="$1"
    local team="$2"
    local saml_url="$3"
    
    local original_hash=$(get_file_hash "$original_pkg")
    local config_hash=$(echo "$team:$saml_url" | shasum -a 256 | cut -d' ' -f1)
    local combined_hash=$(echo "$original_hash:$config_hash" | shasum -a 256 | cut -d' ' -f1)
    local cache_mdm_profile="$CACHE_PATH_pkg_files/saml-pkg-$combined_hash.mobileconfig"
    
    if [ -f "$cache_mdm_profile" ]; then
        echo "$cache_mdm_profile"
        return 0
    else
        return 1
    fi
}

# Cache PKG file
cache_pkg_file() {
    local original_pkg="$1"
    local team="$2"
    local saml_url="$3"
    
    if [ ! -f "$original_pkg" ]; then
        echo "Error: Original PKG not found: $original_pkg"
        return 1
    fi
    
    local original_hash=$(get_file_hash "$original_pkg")
    local config_hash=$(echo "$team:$saml_url" | shasum -a 256 | cut -d' ' -f1)
    local combined_hash=$(echo "$original_hash:$config_hash" | shasum -a 256 | cut -d' ' -f1)
    local cache_file="$CACHE_PATH_pkg_files/saml-pkg-$combined_hash.pkg"
    local cache_mdm_profile="$CACHE_PATH_pkg_files/saml-pkg-$combined_hash.mobileconfig"
    
    if is_cache_valid "pkg_saml" "$combined_hash" "$cache_file"; then
        echo "Using cached PKG: $cache_file"
        # Check if MDM profile also exists in cache
        if [ -f "$cache_mdm_profile" ]; then
            echo "Using cached MDM profile: $cache_mdm_profile"
        fi
        echo "$cache_file"
        return 0
    fi
    
    echo "Building SAML PKG..."
    local start_time=$(date +%s)
    
    # Build PKG with configuration
    cd "$(dirname "$original_pkg")"
    if ./build_pkg_mdm.sh --team "$team" --saml-url "$saml_url" --output "$cache_file"; then
        local end_time=$(date +%s)
        local build_time=$((end_time - start_time))
        
        # Check if MDM profile was generated and cache it too
        local mdm_profile_pattern="Postman-Enterprise-*-enterprise01-auth.mobileconfig"
        local generated_mdm=$(ls $mdm_profile_pattern 2>/dev/null | head -1)
        if [ -f "$generated_mdm" ]; then
            cp "$generated_mdm" "$cache_mdm_profile"
            echo "MDM profile cached: $cache_mdm_profile"
        fi
        
        update_cache_metadata "pkg_saml" "$combined_hash" "$cache_file" "$build_time"
        echo "PKG cached in ${build_time}s: $cache_file"
        echo "$cache_file"
    else
        echo "Error: PKG build failed"
        return 1
    fi
}

# Cache test certificates
cache_test_certificates() {
    local cert_hash=$(echo "test-cert-$(date +%Y%m%d)" | shasum -a 256 | cut -d' ' -f1)
    local cert_dir="$CACHE_PATH_certificates/test-certs-$cert_hash"
    
    if [ -d "$cert_dir" ] && [ -f "$cert_dir/cert.pem" ] && [ -f "$cert_dir/key.pem" ]; then
        if is_cache_valid "test_certificates" "$cert_hash" "$cert_dir"; then
            echo "Using cached test certificates: $cert_dir"
            echo "$cert_dir"
            return 0
        fi
    fi
    
    echo "Generating test certificates..."
    mkdir -p "$cert_dir"
    
    # Generate test certificate
    openssl genrsa -out "$cert_dir/key.pem" 2048 2>/dev/null
    openssl req -new -x509 \
        -key "$cert_dir/key.pem" \
        -out "$cert_dir/cert.pem" \
        -days 365 \
        -subj "/C=US/O=Test/CN=identity.getpostman.com" \
        2>/dev/null
    
    update_cache_metadata "test_certificates" "$cert_hash" "$cert_dir" "5"
    echo "Test certificates cached: $cert_dir"
    echo "$cert_dir"
}

# Clean expired cache entries
clean_cache() {
    local max_age_days="${1:-30}"
    local cutoff_date=$(date -d "$max_age_days days ago" +%s 2>/dev/null || date -v-"${max_age_days}d" +%s)
    
    echo "Cleaning cache entries older than $max_age_days days..."
    
    # Clean each cache directory
    for cache_path in "$CACHE_PATH_go_binary" "$CACHE_PATH_pkg_files" "$CACHE_PATH_certificates" "$CACHE_PATH_test_data"; do
        if [ -d "$cache_path" ]; then
            find "$cache_path" -type f -mtime +$max_age_days -delete
        fi
    done
    
    echo "Cache cleanup completed"
}

# Show cache statistics
show_cache_stats() {
    echo "Cache Statistics:"
    echo "=================="
    echo "Cache directory: $CACHE_DIR"
    
    local total_size=0
    
    # Show stats for each cache directory
    if [ -d "$CACHE_PATH_go_binary" ]; then
        local size=$(du -sh "$CACHE_PATH_go_binary" | cut -f1)
        local count=$(find "$CACHE_PATH_go_binary" -type f | wc -l)
        echo "go_binary: $count files, $size"
    fi
    
    if [ -d "$CACHE_PATH_pkg_files" ]; then
        local size=$(du -sh "$CACHE_PATH_pkg_files" | cut -f1)
        local count=$(find "$CACHE_PATH_pkg_files" -type f | wc -l)
        echo "pkg_files: $count files, $size"
    fi
    
    if [ -d "$CACHE_PATH_certificates" ]; then
        local size=$(du -sh "$CACHE_PATH_certificates" | cut -f1)
        local count=$(find "$CACHE_PATH_certificates" -type f | wc -l)
        echo "certificates: $count files, $size"
    fi
    
    if [ -d "$CACHE_PATH_test_data" ]; then
        local size=$(du -sh "$CACHE_PATH_test_data" | cut -f1)
        local count=$(find "$CACHE_PATH_test_data" -type f | wc -l)
        echo "test_data: $count files, $size"
    fi
    
    if [ -f "$CACHE_CONFIG_FILE" ]; then
        local total_entries=$(jq '.entries | length' "$CACHE_CONFIG_FILE")
        echo "Total cached entries: $total_entries"
    fi
}

# Main command dispatcher
main() {
    local command="$1"
    shift
    
    case "$command" in
        "init")
            init_cache
            ;;
        "cache-binary")
            init_cache
            cache_go_binary "$@"
            ;;
        "get-binary")
            init_cache
            get_cached_go_binary "$@"
            ;;
        "cache-pkg")
            init_cache
            cache_pkg_file "$@"
            ;;
        "get-mdm")
            init_cache
            get_cached_mdm_profile "$@"
            ;;
        "cache-certs")
            init_cache
            cache_test_certificates
            ;;
        "clean")
            clean_cache "$@"
            ;;
        "stats")
            show_cache_stats
            # Also show dependency tracking stats if available
            if command -v show_cache_stats >/dev/null 2>&1; then
                echo ""
                $SCRIPT_DIR/dependency_tracker.sh stats
            fi
            ;;
        "check-rebuild")
            # Check if rebuild is needed for an artifact
            if [[ -f "$SCRIPT_DIR/dependency_tracker.sh" ]]; then
                $SCRIPT_DIR/dependency_tracker.sh check "$@"
            else
                echo "Dependency tracker not available"
                exit 1
            fi
            ;;
        "dep-graph")
            # Generate dependency graph
            if [[ -f "$SCRIPT_DIR/dependency_tracker.sh" ]]; then
                $SCRIPT_DIR/dependency_tracker.sh graph
            else
                echo "Dependency tracker not available"
                exit 1
            fi
            ;;
        *)
            echo "Usage: $0 {init|cache-binary|get-binary|cache-pkg|get-mdm|cache-certs|clean|stats|check-rebuild|dep-graph}"
            echo ""
            echo "Commands:"
            echo "  init                    Initialize cache directory structure"
            echo "  cache-binary [arch]     Cache Go binary for architecture"
            echo "  get-binary [arch]       Get path to cached Go binary"
            echo "  cache-pkg PKG TEAM URL  Cache PKG with SAML configuration (also caches MDM profile)"
            echo "  get-mdm PKG TEAM URL    Get path to cached MDM profile"
            echo "  cache-certs             Cache test certificates"
            echo "  clean [days]            Clean cache entries older than days (default: 30)"
            echo "  stats                   Show cache statistics"
            echo "  check-rebuild TYPE      Check if rebuild is needed for artifact type"
            echo "  dep-graph               Generate dependency graph"
            exit 1
            ;;
    esac
}

if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi