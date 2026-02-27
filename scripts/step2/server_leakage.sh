#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"
source "$SCRIPT_DIR/lib/http.sh"

STEP_NAME="step2_server_leakage"

# Check for server information leakage
check_server_leakage() {
    local target="$1"
    local headers=$(fetch_headers "$target")
    
    local findings=()
    local severity="INFO"
    
    # Check Server header
    local server_header=$(get_header "$headers" "Server")
    if [[ -n "$server_header" ]]; then
        # Check if it contains version info
        if echo "$server_header" | grep -qE "[0-9]+\.[0-9]+" || true; then
            findings+=("Server: $server_header (version exposed)")
            severity="MEDIUM"
        else
            findings+=("Server: $server_header")
            [[ "$severity" == "INFO" ]] && severity="LOW"
        fi
    fi
    
    # Check X-Powered-By
    local powered_by=$(get_header "$headers" "X-Powered-By")
    if [[ -n "$powered_by" ]]; then
        findings+=("X-Powered-By: $powered_by")
        [[ "$severity" == "INFO" ]] && severity="LOW"
    fi
    
    # Check X-AspNet-Version
    local aspnet=$(get_header "$headers" "X-AspNet-Version")
    if [[ -n "$aspnet" ]]; then
        findings+=("X-AspNet-Version: $aspnet")
        severity="MEDIUM"
    fi
    
    # Check X-AspNetMvc-Version
    local aspnetmvc=$(get_header "$headers" "X-AspNetMvc-Version")
    if [[ -n "$aspnetmvc" ]]; then
        findings+=("X-AspNetMvc-Version: $aspnetmvc")
        severity="MEDIUM"
    fi
    
    # Check X-Generator
    local generator=$(get_header "$headers" "X-Generator")
    if [[ -n "$generator" ]]; then
        findings+=("X-Generator: $generator")
        [[ "$severity" == "INFO" ]] && severity="LOW"
    fi
    
    if [[ ${#findings[@]} -eq 0 ]]; then
        echo "PASS|No server/framework info leaked|Headers stripped|INFO|"
    else
        local findings_str=$(IFS=", "; echo "${findings[*]}")
        echo "WARN|${#findings[@]} info disclosure header(s): $findings_str|Headers stripped|$severity|SEC-INFO-001"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking server information leakage for $TARGET"
    
    OUTPUT_DIR="$OUT/step2"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/server_leakage.json"
    
    # Run check
    result=$(check_server_leakage "$TARGET")
    
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
        echo "    {\"name\":\"Server Information Leakage\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "Server leakage check complete"
done
