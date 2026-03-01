#!/usr/bin/env bash
# Step 2: TLS Version Check
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step2_tls"

json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/}"
    echo -n "$str"
}

check_tls_version() {
    local target="$1"
    local host port
    
    # Extract hostname and port
    host=$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##' | cut -d: -f1)
    port=$(echo "$target" | grep -oE ':[0-9]+' | cut -d: -f2)
    [[ -z "$port" ]] && port=443
    
    # Test TLS versions
    local tls13_support=$(timeout 5 bash -c "echo | openssl s_client -connect '$host:$port' -tls1_3 -servername '$host' 2>&1" | grep -c "Protocol.*TLSv1.3" || echo "0")
    local tls12_support=$(timeout 5 bash -c "echo | openssl s_client -connect '$host:$port' -tls1_2 -servername '$host' 2>&1" | grep -c "Protocol.*TLSv1.2" || echo "0")
    local tls11_support=$(timeout 5 bash -c "echo | openssl s_client -connect '$host:$port' -tls1_1 -servername '$host' 2>&1" | grep -c "Protocol.*TLSv1.1" || echo "0")
    local tls10_support=$(timeout 5 bash -c "echo | openssl s_client -connect '$host:$port' -tls1 -servername '$host' 2>&1" | grep -c "Protocol.*TLSv1" || echo "0")
    
    local versions=()
    [[ "$tls13_support" -gt 0 ]] && versions+=("TLS 1.3")
    [[ "$tls12_support" -gt 0 ]] && versions+=("TLS 1.2")
    [[ "$tls11_support" -gt 0 ]] && versions+=("TLS 1.1")
    [[ "$tls10_support" -gt 0 ]] && versions+=("TLS 1.0")
    
    local versions_str=$(IFS=", "; echo "${versions[*]}")
    
    if [[ "$tls11_support" -gt 0 ]] || [[ "$tls10_support" -gt 0 ]]; then
        echo "FAIL|Vulnerable TLS versions enabled: $versions_str|TLS 1.2+ only|HIGH|SEC-TLS-001"
    elif [[ "$tls12_support" -gt 0 ]] || [[ "$tls13_support" -gt 0 ]]; then
        echo "PASS|Secure TLS: $versions_str|TLS 1.2+|INFO|"
    else
        echo "FAIL|Could not determine TLS version|TLS 1.2+|MEDIUM|SEC-TLS-001"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking TLS version for $TARGET"
    
    OUTPUT_DIR="$OUT/step2"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/tls.json"
    
    # Run check
    result=$(check_tls_version "$TARGET" 2>/dev/null || echo "FAIL|Connection failed|TLS 1.2+|MEDIUM|SEC-TLS-001")
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
        echo "    {\"name\":\"TLS Version Support\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "TLS check: $found"
    print_status "INFO" "Report written to $OUTPUT_FILE"
done
