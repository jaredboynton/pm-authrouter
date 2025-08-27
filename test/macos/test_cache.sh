#!/bin/bash
# test_cache.sh - Unified caching system for macOS test infrastructure
# Consolidates artifact caching, dependency tracking, and fixture management

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Cache configuration
CACHE_VERSION="1.0.0"
CACHE_BASE_DIR="${CACHE_BASE_DIR:-/tmp/pm-authrouter-cache}"
CACHE_ARTIFACTS_DIR="$CACHE_BASE_DIR/artifacts"
CACHE_FIXTURES_DIR="$CACHE_BASE_DIR/fixtures"
CACHE_DEPS_DIR="$CACHE_BASE_DIR/deps"
CACHE_METADATA_FILE="$CACHE_BASE_DIR/metadata.json"
CACHE_MAX_AGE_DAYS=7

# Source patterns for dependency tracking
SOURCE_PATTERNS=(
    "cmd/**/*.go"
    "internal/**/*.go"
    "go.mod"
    "go.sum"
)

# Initialize cache directories
init_cache() {
    mkdir -p "$CACHE_ARTIFACTS_DIR"
    mkdir -p "$CACHE_FIXTURES_DIR"
    mkdir -p "$CACHE_DEPS_DIR"
    
    # Initialize metadata if not exists
    if [ ! -f "$CACHE_METADATA_FILE" ]; then
        echo "{\"version\": \"$CACHE_VERSION\", \"created\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" > "$CACHE_METADATA_FILE"
    fi
}

# ========================================
# Artifact Caching Functions
# ========================================

# Cache a build artifact
cache_artifact() {
    local artifact_path="$1"
    local cache_key="$2"
    local artifact_type="${3:-binary}"
    
    if [ ! -f "$artifact_path" ]; then
        echo -e "${RED}Artifact not found: $artifact_path${NC}"
        return 1
    fi
    
    local cache_path="$CACHE_ARTIFACTS_DIR/${cache_key}_${artifact_type}"
    local hash_file="${cache_path}.sha256"
    
    # Calculate hash
    local artifact_hash
    artifact_hash=$(shasum -a 256 "$artifact_path" | cut -d' ' -f1)
    
    # Check if already cached
    if [ -f "$cache_path" ] && [ -f "$hash_file" ]; then
        local cached_hash
        cached_hash=$(cat "$hash_file")
        if [ "$artifact_hash" = "$cached_hash" ]; then
            echo -e "${GREEN}${NC} Artifact already cached: $cache_key"
            return 0
        fi
    fi
    
    # Cache the artifact
    cp "$artifact_path" "$cache_path"
    echo "$artifact_hash" > "$hash_file"
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${cache_path}.timestamp"
    
    echo -e "${GREEN}${NC} Cached artifact: $cache_key (${artifact_type})"
    return 0
}

# Retrieve cached artifact
get_cached_artifact() {
    local cache_key="$1"
    local destination="$2"
    local artifact_type="${3:-binary}"
    
    local cache_path="$CACHE_ARTIFACTS_DIR/${cache_key}_${artifact_type}"
    
    if [ ! -f "$cache_path" ]; then
        echo -e "${YELLOW}Cache miss: $cache_key${NC}"
        return 1
    fi
    
    # Check age
    if is_cache_expired "$cache_path"; then
        echo -e "${YELLOW}Cache expired: $cache_key${NC}"
        rm -f "$cache_path" "${cache_path}.sha256" "${cache_path}.timestamp"
        return 1
    fi
    
    # Copy from cache
    cp "$cache_path" "$destination"
    echo -e "${GREEN}${NC} Retrieved from cache: $cache_key"
    return 0
}

# ========================================
# Dependency Tracking Functions
# ========================================

# Calculate hash for source files
calculate_source_hash() {
    local pattern="$1"
    local hash_file="$CACHE_DEPS_DIR/$(echo "$pattern" | sed 's/\//_/g').hash"
    
    # Find all matching files and calculate combined hash
    local combined_hash=""
    while IFS= read -r file; do
        if [ -f "$file" ]; then
            combined_hash="${combined_hash}$(shasum -a 256 "$file" | cut -d' ' -f1)"
        fi
    done < <(find . -path "./$pattern" -type f 2>/dev/null)
    
    if [ -n "$combined_hash" ]; then
        echo "$combined_hash" | shasum -a 256 | cut -d' ' -f1
    else
        echo "empty"
    fi
}

# Check if dependencies have changed
check_dependencies_changed() {
    local cache_key="$1"
    local deps_file="$CACHE_DEPS_DIR/${cache_key}.deps"
    
    # Calculate current hashes
    local current_hashes=""
    for pattern in "${SOURCE_PATTERNS[@]}"; do
        local hash
        hash=$(calculate_source_hash "$pattern")
        current_hashes="${current_hashes}${hash}:"
    done
    
    # Compare with cached hashes
    if [ -f "$deps_file" ]; then
        local cached_hashes
        cached_hashes=$(cat "$deps_file")
        if [ "$current_hashes" = "$cached_hashes" ]; then
            echo -e "${GREEN}${NC} Dependencies unchanged for: $cache_key"
            return 1  # No changes
        fi
    fi
    
    # Save new hashes
    echo "$current_hashes" > "$deps_file"
    echo -e "${YELLOW}Dependencies changed for: $cache_key${NC}"
    return 0  # Changes detected
}

# Track build dependencies
track_dependencies() {
    local target="$1"
    local deps_file="$CACHE_DEPS_DIR/${target}.deps"
    
    echo -e "${CYAN}Tracking dependencies for: $target${NC}"
    
    # Track Go module dependencies
    if [ -f "go.mod" ]; then
        go list -m all 2>/dev/null > "${deps_file}.modules"
    fi
    
    # Track source file changes
    for pattern in "${SOURCE_PATTERNS[@]}"; do
        local hash
        hash=$(calculate_source_hash "$pattern")
        echo "$pattern:$hash" >> "${deps_file}.sources"
    done
    
    echo -e "${GREEN}${NC} Dependencies tracked for: $target"
}

# ========================================
# Fixture Caching Functions
# ========================================

# Cache test fixtures
cache_fixture() {
    local fixture_name="$1"
    local fixture_data="$2"
    
    local fixture_path="$CACHE_FIXTURES_DIR/${fixture_name}"
    echo "$fixture_data" > "$fixture_path"
    echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "${fixture_path}.timestamp"
    
    echo -e "${GREEN}${NC} Cached fixture: $fixture_name"
}

# Get cached fixture
get_cached_fixture() {
    local fixture_name="$1"
    local fixture_path="$CACHE_FIXTURES_DIR/${fixture_name}"
    
    if [ ! -f "$fixture_path" ]; then
        return 1
    fi
    
    cat "$fixture_path"
    return 0
}

# Cache certificate pair
cache_certificates() {
    local cert_name="$1"
    local cert_path="$2"
    local key_path="$3"
    
    if [ ! -f "$cert_path" ] || [ ! -f "$key_path" ]; then
        echo -e "${RED}Certificate files not found${NC}"
        return 1
    fi
    
    local cache_cert="$CACHE_FIXTURES_DIR/${cert_name}.crt"
    local cache_key="$CACHE_FIXTURES_DIR/${cert_name}.key"
    
    cp "$cert_path" "$cache_cert"
    cp "$key_path" "$cache_key"
    
    echo -e "${GREEN}${NC} Cached certificates: $cert_name"
    return 0
}

# ========================================
# Cache Management Functions
# ========================================

# Check if cache entry is expired
is_cache_expired() {
    local cache_path="$1"
    local timestamp_file="${cache_path}.timestamp"
    
    if [ ! -f "$timestamp_file" ]; then
        return 0  # Consider expired if no timestamp
    fi
    
    local timestamp
    timestamp=$(cat "$timestamp_file")
    local timestamp_epoch
    timestamp_epoch=$(date -j -f "%Y-%m-%dT%H:%M:%SZ" "$timestamp" "+%s" 2>/dev/null || echo "0")
    local current_epoch
    current_epoch=$(date "+%s")
    local age_days=$(( (current_epoch - timestamp_epoch) / 86400 ))
    
    if [ "$age_days" -gt "$CACHE_MAX_AGE_DAYS" ]; then
        return 0  # Expired
    fi
    
    return 1  # Not expired
}

# Clean expired cache entries
clean_expired_cache() {
    echo -e "${YELLOW}Cleaning expired cache entries...${NC}"
    
    local cleaned=0
    for cache_file in "$CACHE_ARTIFACTS_DIR"/* "$CACHE_FIXTURES_DIR"/*; do
        if [ -f "$cache_file" ] && [[ ! "$cache_file" =~ \.(sha256|timestamp|deps)$ ]]; then
            if is_cache_expired "$cache_file"; then
                rm -f "$cache_file" "${cache_file}.sha256" "${cache_file}.timestamp"
                echo -e "${YELLOW}Removed expired: $(basename "$cache_file")${NC}"
                ((cleaned++))
            fi
        fi
    done
    
    echo -e "${GREEN}${NC} Cleaned $cleaned expired entries"
}

# Clear entire cache
clear_cache() {
    local category="${1:-all}"
    
    case "$category" in
        artifacts)
            rm -rf "$CACHE_ARTIFACTS_DIR"/*
            echo -e "${GREEN}${NC} Cleared artifact cache"
            ;;
        fixtures)
            rm -rf "$CACHE_FIXTURES_DIR"/*
            echo -e "${GREEN}${NC} Cleared fixture cache"
            ;;
        deps)
            rm -rf "$CACHE_DEPS_DIR"/*
            echo -e "${GREEN}${NC} Cleared dependency cache"
            ;;
        all)
            rm -rf "$CACHE_BASE_DIR"/*
            init_cache
            echo -e "${GREEN}${NC} Cleared all caches"
            ;;
        *)
            echo -e "${RED}Unknown category: $category${NC}"
            return 1
            ;;
    esac
}

# Get cache statistics
cache_stats() {
    echo -e "${CYAN}=== Cache Statistics ===${NC}"
    
    # Count entries
    local artifact_count
    artifact_count=$(find "$CACHE_ARTIFACTS_DIR" -type f ! -name "*.sha256" ! -name "*.timestamp" | wc -l)
    local fixture_count
    fixture_count=$(find "$CACHE_FIXTURES_DIR" -type f ! -name "*.timestamp" | wc -l)
    local deps_count
    deps_count=$(find "$CACHE_DEPS_DIR" -type f | wc -l)
    
    # Calculate size
    local cache_size
    cache_size=$(du -sh "$CACHE_BASE_DIR" 2>/dev/null | cut -f1)
    
    echo "Location: $CACHE_BASE_DIR"
    echo "Total size: $cache_size"
    echo "Artifacts: $artifact_count"
    echo "Fixtures: $fixture_count"
    echo "Dependencies: $deps_count"
    echo "Max age: $CACHE_MAX_AGE_DAYS days"
    
    # Show oldest and newest
    local oldest
    oldest=$(find "$CACHE_BASE_DIR" -name "*.timestamp" -exec cat {} \; | sort | head -1)
    local newest
    newest=$(find "$CACHE_BASE_DIR" -name "*.timestamp" -exec cat {} \; | sort | tail -1)
    
    if [ -n "$oldest" ]; then
        echo "Oldest entry: $oldest"
    fi
    if [ -n "$newest" ]; then
        echo "Newest entry: $newest"
    fi
}

# ========================================
# Test Functions
# ========================================

# Test artifact caching
test_artifact_caching() {
    echo -e "\n${YELLOW}Testing artifact caching...${NC}"
    
    # Create test artifact
    local test_file="/tmp/test_artifact_$$"
    echo "test content" > "$test_file"
    
    # Cache it
    if cache_artifact "$test_file" "test_artifact" "binary"; then
        echo -e "${GREEN}${NC} Artifact cached successfully"
    else
        echo -e "${RED}${NC} Failed to cache artifact"
        return 1
    fi
    
    # Retrieve it
    local retrieved="/tmp/retrieved_$$"
    if get_cached_artifact "test_artifact" "$retrieved" "binary"; then
        if diff "$test_file" "$retrieved" >/dev/null 2>&1; then
            echo -e "${GREEN}${NC} Artifact retrieved correctly"
        else
            echo -e "${RED}${NC} Retrieved artifact differs"
        fi
    else
        echo -e "${RED}${NC} Failed to retrieve artifact"
    fi
    
    # Cleanup
    rm -f "$test_file" "$retrieved"
}

# Test dependency tracking
test_dependency_tracking() {
    echo -e "\n${YELLOW}Testing dependency tracking...${NC}"
    
    # Track dependencies
    track_dependencies "test_target"
    
    # Check if detected as unchanged
    if ! check_dependencies_changed "test_target"; then
        echo -e "${GREEN}${NC} Dependencies correctly detected as unchanged"
    else
        echo -e "${RED}${NC} Dependencies incorrectly detected as changed"
    fi
    
    # Modify a tracked file
    if [ -f "go.mod" ]; then
        touch "go.mod"
        if check_dependencies_changed "test_target"; then
            echo -e "${GREEN}${NC} Change detection working"
        else
            echo -e "${RED}${NC} Failed to detect changes"
        fi
    fi
}

# Test fixture caching
test_fixture_caching() {
    echo -e "\n${YELLOW}Testing fixture caching...${NC}"
    
    # Cache a fixture
    cache_fixture "test_fixture" "test fixture data"
    
    # Retrieve it
    local retrieved
    retrieved=$(get_cached_fixture "test_fixture")
    if [ "$retrieved" = "test fixture data" ]; then
        echo -e "${GREEN}${NC} Fixture caching working"
    else
        echo -e "${RED}${NC} Fixture caching failed"
    fi
}

# ========================================
# Main Function
# ========================================

main() {
    local command="${1:-help}"
    shift || true
    
    # Initialize cache
    init_cache
    
    case "$command" in
        cache)
            cache_artifact "$@"
            ;;
        get)
            get_cached_artifact "$@"
            ;;
        track)
            track_dependencies "$@"
            ;;
        check)
            check_dependencies_changed "$@"
            ;;
        fixture)
            cache_fixture "$@"
            ;;
        certs)
            cache_certificates "$@"
            ;;
        clean)
            clean_expired_cache
            ;;
        clear)
            clear_cache "$@"
            ;;
        stats)
            cache_stats
            ;;
        test)
            echo "Running cache system tests..."
            test_artifact_caching
            test_dependency_tracking
            test_fixture_caching
            echo -e "\n${GREEN}All cache tests completed${NC}"
            ;;
        help|*)
            echo "Usage: $0 <command> [arguments]"
            echo ""
            echo "Commands:"
            echo "  cache <file> <key> [type]  - Cache an artifact"
            echo "  get <key> <dest> [type]     - Get cached artifact"
            echo "  track <target>              - Track dependencies"
            echo "  check <target>              - Check if dependencies changed"
            echo "  fixture <name> <data>       - Cache test fixture"
            echo "  certs <name> <cert> <key>   - Cache certificate pair"
            echo "  clean                       - Clean expired entries"
            echo "  clear [category]            - Clear cache (all/artifacts/fixtures/deps)"
            echo "  stats                       - Show cache statistics"
            echo "  test                        - Run cache system tests"
            echo "  help                        - Show this help"
            ;;
    esac
}

# Run main function
main "$@"