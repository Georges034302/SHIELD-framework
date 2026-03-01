#!/usr/bin/env bash
# Step 2: Information Exposure via Headers
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"
source "$SCRIPT_DIR/lib/http.sh"

STEP_NAME="step2_exposure"

json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/}"
    echo -n "$str"
}

check_info_exposure() {
    local target="$1"
    local headers=$(fetch_headers "$target")
    
    if [[ -z "$headers" ]]; then
        echo "SKIP|Could not fetch headers|Headers hidden|INFO|"
        return
    fi
    
    local exposures=()
    
    # Check for technology exposure
    echo "$headers" | grep -qi "^X-Powered-By:" && exposures+=("X-Powered-By")
    echo "$headers" | grep -qi "^X-AspNet-Version:" && exposures+=("X-AspNet-Version")
    echo "$headers" | grep -qi "^X-AspNetMvc-Version:" && exposures+=("X-AspNetMvc-Version")
    echo "$headers" | grep -qi "^X-Generator:" && exposures+=("X-Generator")
    echo "$headers" | grep -qi "^X-Drupal-Cache:" && exposures+=("X-Drupal-Cache")
    echo "$headers" | grep -qi "^X-Pingback:" && exposures+=("X-Pingback")
    
    # Check Server header with version details
    local server_header=$(echo "$headers" | grep -i "^Server:" | head -1 | cut -d' ' -f2- | tr -d '\r')
    if [[ -n "$server_header" ]] && echo "$server_header" | grep -qE '[0-9]+\.[0-9]+'; then
        exposures+=("Server version: $server_header")
    fi
    
    if [[ ${#exposures[@]} -eq 0 ]]; then
        echo "PASS|No technology headers exposed|Headers minimized|INFO|"
    elif [[ ${#exposures[@]} -le 2 ]]; then
        local exp_str=$(IFS=", "; echo "${exposures[*]}")
        echo "WARN|Exposed headers: $exp_str|Suppress technology headers|LOW|SEC-EXPOSE-001"
    else
        local exp_str=$(IFS=", "; echo "${exposures[*]}")
        echo "WARN|Multiple technology headers exposed: $exp_str|Suppress technology headers|MEDIUM|SEC-EXPOSE-001"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking information exposure for $TARGET"
    
    OUTPUT_DIR="$OUT/step2"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/exposure.json"
    
    # Run check
    result=$(check_info_exposure "$TARGET" || echo "SKIP|Check failed|Headers minimized|INFO|")
    IFS='|' read -r status found expected severity remediation_id <<< "$result"
    
    # Escape for JSON
    status_esc=$(json_escape "$status")
    found_esc=$(json_escape "$found")
    expected_esc=$(json_escape "$expected")
    severity_esc=$(json_escape "$severity")
    remediation_id_esc=$(json_escape "$remediation_id")
    
    # Write JSON
    {
        echo "{"
        echo "  \"step\": \"$STEP_NAME\","
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"target\": \"$TARGET\","
        echo "  \"checks\": ["
        echo "    {\"name\":\"Technology Header Exposure\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "Exposure: $found"
    print_status "INFO" "Report written to $OUTPUT_FILE"
done
