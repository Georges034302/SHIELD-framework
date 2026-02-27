#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step2_tls_ciphers"

# Check TLS protocol versions and cipher strength
check_tls_protocols() {
    local target="$1"
    
    # Extract hostname and port
    local hostname=$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##' | sed 's/:.*$//')
    local port="443"
    
    local issues=()
    local severity="INFO"
    
    # Check TLS 1.0 (deprecated)
    if timeout 5 openssl s_client -connect "$hostname:$port" -tls1 </dev/null 2>&1 | grep -q "Cipher is" || true; then
        issues+=("TLS 1.0 enabled (deprecated)")
        severity="HIGH"
    fi
    
    # Check TLS 1.1 (deprecated)
    if timeout 5 openssl s_client -connect "$hostname:$port" -tls1_1 </dev/null 2>&1 | grep -q "Cipher is" || true; then
        issues+=("TLS 1.1 enabled (deprecated)")
        [[ "$severity" == "INFO" ]] && severity="HIGH"
    fi
    
    # Check TLS 1.2 support
    local tls12_supported=false
    if timeout 5 openssl s_client -connect "$hostname:$port" -tls1_2 </dev/null 2>&1 | grep -q "Cipher is" || true; then
        tls12_supported=true
    fi
    
    # Check TLS 1.3 support (preferred)
    local tls13_supported=false
    if timeout 5 openssl s_client -connect "$hostname:$port" -tls1_3 </dev/null 2>&1 | grep -q "Cipher is" || true; then
        tls13_supported=true
    fi
    
    # Evaluate findings
    if [[ ${#issues[@]} -gt 0 ]]; then
        local issues_str=$(IFS=", "; echo "${issues[*]}")
        echo "FAIL|Legacy TLS protocols enabled: $issues_str|TLS 1.2+ only|HIGH|SEC-TLS-001"
    elif [[ "$tls13_supported" == true ]]; then
        echo "PASS|TLS 1.3 and 1.2 supported, no legacy protocols|TLS 1.2+ only|INFO|"
    elif [[ "$tls12_supported" == true ]]; then
        echo "WARN|TLS 1.2 only (TLS 1.3 recommended)|TLS 1.2+ with 1.3 preferred|LOW|SEC-TLS-002"
    else
        echo "FAIL|Could not verify TLS configuration|TLS 1.2+ only|MEDIUM|SEC-TLS-003"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking TLS protocol configuration for $TARGET"
    
    OUTPUT_DIR="$OUT/step2"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/tls_ciphers.json"
    
    # Run check
    result=$(check_tls_protocols "$TARGET")
    
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
        echo "    {\"name\":\"TLS Protocol Configuration\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "TLS protocol check complete"
done
