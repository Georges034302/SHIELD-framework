#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step4_directory_listing"

# Common directories to check for listing
DIRECTORIES=(
    "uploads"
    "uploads/"
    "assets"
    "assets/"
    "images"
    "images/"
    "static"
    "static/"
    "files"
    "files/"
    "media"
    "media/"
    "public"
    "public/"
    "downloads"
    "downloads/"
)

# Check for directory listing enabled
check_directory_listing() {
    local target="$1"
    local base_url="${target%/}"
    
    local listed=()
    local checked=0
    
    for dir in "${DIRECTORIES[@]}"; do
        local url="$base_url/$dir"
        local response=$(curl -sS --max-time 5 "$url" 2>/dev/null || echo "")
        checked=$((checked + 1))
        
        # Look for common directory listing patterns
        if echo "$response" | grep -qiE "(Index of|Directory listing|Parent Directory|\[DIR\]|<title>Index of)" || true; then
            listed+=("/$dir")
        fi
    done
    
    if [[ ${#listed[@]} -eq 0 ]]; then
        echo "PASS|No directory listing detected (checked $checked paths)|Directory listing disabled|INFO|"
    elif [[ ${#listed[@]} -eq 1 ]]; then
        echo "WARN|Directory listing enabled: ${listed[0]}|Directory listing disabled|MEDIUM|SEC-DIRLISTING-001"
    else
        local listed_str=$(IFS=", "; echo "${listed[*]}")
        echo "WARN|${#listed[@]} directories with listing enabled: $listed_str|Directory listing disabled|HIGH|SEC-DIRLISTING-002"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking directory listing for $TARGET"
    
    OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/directory_listing.json"
    
    # Run check
    result=$(check_directory_listing "$TARGET")
    
    # Parse result
    IFS='|' read -r status found expected severity remediation_id <<< "$result"
    
    # Escape for JSON
    status_esc=$(json_escape "$status")
    found_esc=$(json_escape "$found")
    expected_esc=$(json_escape "$expected")
    severity_esc=$(json_escape "$severity")
    remediation_id_esc=$(json_escape "$remediation_id")
    
    {
        echo "{"
        echo "  \"step\": \"$STEP_NAME\","
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"target\": \"$TARGET\","
        echo "  \"checks\": ["
        echo "    {\"name\":\"Directory Listing\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "Directory listing check complete"
done
