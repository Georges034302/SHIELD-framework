#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step4_admin_paths"

# Common admin/sensitive paths
ADMIN_PATHS=(
    "admin"
    "admin/"
    "administrator"
    "wp-admin"
    "wp-admin/"
    "phpmyadmin"
    "phpMyAdmin"
    "server-status"
    "server-info"
    "status"
    "actuator"
    "actuator/health"
    "debug"
    "_profiler"
    "elmah.axd"
    "trace.axd"
)

# Check for publicly accessible admin paths
check_admin_paths() {
    local target="$1"
    local base_url="${target%/}"
    
    local accessible=()
    local checked=0
    
    for path in "${ADMIN_PATHS[@]}"; do
        local url="$base_url/$path"
        local response=$(curl -sS -I --max-time 5 "$url" 2>/dev/null || echo "")
        local status_code=$(echo "$response" | grep -i "HTTP/" | head -1 | awk '{print $2}' || echo "000")
        checked=$((checked + 1))
        
        # 200 = accessible, 401/403 = exists but protected (good), 404 = doesn't exist (good)
        if [[ "$status_code" == "200" ]]; then
            accessible+=("/$path (HTTP $status_code)")
        fi
    done
    
    if [[ ${#accessible[@]} -eq 0 ]]; then
        echo "PASS|No admin paths publicly accessible (checked $checked paths)|Admin paths protected|INFO|"
    elif [[ ${#accessible[@]} -eq 1 ]]; then
        echo "FAIL|Publicly accessible: ${accessible[0]}|Admin paths protected|HIGH|SEC-ADMIN-001"
    else
        local accessible_str=$(IFS=", "; echo "${accessible[*]}")
        echo "FAIL|${#accessible[@]} admin paths accessible: $accessible_str|Admin paths protected|CRITICAL|SEC-ADMIN-002"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking admin path protection for $TARGET"
    
    OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/admin_paths.json"
    
    # Run check
    result=$(check_admin_paths "$TARGET")
    
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
        echo "    {\"name\":\"Admin Path Protection\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "Admin paths check complete"
done
