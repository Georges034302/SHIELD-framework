#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step4_api_auth"

# Common API endpoints
API_ENDPOINTS=(
    "api"
    "api/"
    "api/v1"
    "api/v1/"
    "api/v2"
    "api/v2/"
    "api/users"
    "api/data"
    "api/config"
    "graphql"
    "graphql/"
)

# Check API authentication posture
check_api_auth() {
    local target="$1"
    local base_url="${target%/}"
    
    local open_endpoints=()
    local checked=0
    
    for endpoint in "${API_ENDPOINTS[@]}"; do
        local url="$base_url/$endpoint"
        local response=$(curl -sS -I --max-time 5 "$url" 2>/dev/null || echo "")
        local status_code=$(echo "$response" | grep -i "HTTP/" | head -1 | awk '{print $2}' || echo "000")
        checked=$((checked + 1))
        
        # 200 = open, 401/403 = protected (good), 404 = doesn't exist
        if [[ "$status_code" == "200" ]]; then
            # Check if it returns JSON (likely API)
            local content_type=$(echo "$response" | grep -i "^Content-Type:" | grep -qi "json" && echo "json" || echo "")
            if [[ -n "$content_type" ]] || [[ "$endpoint" =~ graphql ]]; then
                open_endpoints+=("/$endpoint (HTTP $status_code)")
            fi
        fi
    done
    
    if [[ ${#open_endpoints[@]} -eq 0 ]]; then
        echo "PASS|No open API endpoints detected (checked $checked paths)|API endpoints require authentication|INFO|"
    elif [[ ${#open_endpoints[@]} -eq 1 ]]; then
        echo "WARN|Open API endpoint: ${open_endpoints[0]}|API endpoints require authentication|MEDIUM|SEC-API-001"
    else
        local open_str=$(IFS=", "; echo "${open_endpoints[*]}")
        echo "WARN|${#open_endpoints[@]} open API endpoints: $open_str|API endpoints require authentication|HIGH|SEC-API-002"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking API authentication for $TARGET"
    
    OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/api_auth.json"
    
    # Run check
    result=$(check_api_auth "$TARGET")
    
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
        echo "    {\"name\":\"API Authentication\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "API authentication check complete"
done
