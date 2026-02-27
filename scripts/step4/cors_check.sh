#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"
source "$SCRIPT_DIR/lib/http.sh"

STEP_NAME="step4_cors_check"

# Check for CORS misconfigurations
check_cors() {
    local target="$1"
    
    # Test with a malicious origin
    local response=$(curl -sS -I -H "Origin: https://evil.com" --max-time 5 "$target" 2>/dev/null || echo "")
    
    local acao=$(echo "$response" | grep -i "^Access-Control-Allow-Origin:" | awk '{print $2}' | tr -d '\r' || echo "")
    local acac=$(echo "$response" | grep -i "^Access-Control-Allow-Credentials:" | awk '{print $2}' | tr -d '\r' || echo "")
    
    local issues=()
    local severity="INFO"
    
    # Check for wildcard with credentials (dangerous)
    if [[ "$acao" == "*" ]] && [[ "$acac" == "true" ]]; then
        echo "FAIL|CORS allows any origin (*) with credentials|Restricted CORS policy|CRITICAL|SEC-CORS-001"
        return
    fi
    
    # Check for wildcard alone
    if [[ "$acao" == "*" ]]; then
        issues+=("Access-Control-Allow-Origin: * (overly permissive)")
        severity="MEDIUM"
    fi
    
    # Check if evil origin is reflected
    if [[ "$acao" == "https://evil.com" ]]; then
        issues+=("Origin reflected without validation")
        severity="HIGH"
    fi
    
    # Check for credentials without proper origin restriction
    if [[ "$acac" == "true" ]] && [[ -n "$acao" ]] && [[ "$acao" != "null" ]]; then
        if [[ "$acao" == "*" ]] || [[ "$acao" == "https://evil.com" ]]; then
            issues+=("Credentials enabled with weak origin policy")
            [[ "$severity" == "INFO" ]] && severity="HIGH"
        fi
    fi
    
    if [[ ${#issues[@]} -eq 0 ]]; then
        if [[ -z "$acao" ]]; then
            echo "PASS|CORS not configured (or properly restricted)|Restricted CORS policy|INFO|"
        else
            echo "PASS|CORS properly configured|Restricted CORS policy|INFO|"
        fi
    else
        local issues_str=$(IFS=", "; echo "${issues[*]}")
        echo "FAIL|$issues_str|Restricted CORS policy|$severity|SEC-CORS-002"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking CORS configuration for $TARGET"
    
    OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/cors_check.json"
    
    # Run check
    result=$(check_cors "$TARGET")
    
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
        echo "    {\"name\":\"CORS Configuration\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "CORS check complete"
done
