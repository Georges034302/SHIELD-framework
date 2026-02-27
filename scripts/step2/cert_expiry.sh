#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step2_cert_expiry"

# Check certificate expiry
check_cert_expiry() {
    local target="$1"
    
    # Extract hostname and port
    local hostname=$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##' | sed 's/:.*$//')
    local port="443"
    
    # Get certificate expiry date
    local cert_info=$(echo | openssl s_client -servername "$hostname" -connect "$hostname:$port" 2>/dev/null | openssl x509 -noout -dates 2>/dev/null || true)
    
    if [[ -z "$cert_info" ]]; then
        echo "FAIL|Could not retrieve certificate|Valid certificate|HIGH|SEC-CERT-001"
        return
    fi
    
    # Extract notAfter date
    local expiry_str=$(echo "$cert_info" | grep "notAfter=" | sed 's/notAfter=//' || echo "")
    
    if [[ -z "$expiry_str" ]]; then
        echo "FAIL|Could not parse certificate expiry|Valid certificate|MEDIUM|SEC-CERT-002"
        return
    fi
    
    # Convert to epoch time
    local expiry_epoch=$(date -d "$expiry_str" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$expiry_str" +%s 2>/dev/null || echo "0")
    local current_epoch=$(date +%s)
    
    if [[ "$expiry_epoch" -eq 0 ]]; then
        echo "WARN|Could not parse date: $expiry_str|Valid certificate|LOW|SEC-CERT-003"
        return
    fi
    
    local days_until_expiry=$(( (expiry_epoch - current_epoch) / 86400 ))
    
    if [[ $days_until_expiry -lt 0 ]]; then
        echo "FAIL|Certificate expired ${days_until_expiry#-} days ago|Valid certificate|CRITICAL|SEC-CERT-004"
    elif [[ $days_until_expiry -lt 7 ]]; then
        echo "FAIL|Certificate expires in $days_until_expiry days|Valid certificate (30+ days)|HIGH|SEC-CERT-005"
    elif [[ $days_until_expiry -lt 30 ]]; then
        echo "WARN|Certificate expires in $days_until_expiry days|Valid certificate (30+ days)|MEDIUM|SEC-CERT-006"
    else
        echo "PASS|Certificate valid for $days_until_expiry days|Valid certificate|INFO|"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking certificate expiry for $TARGET"
    
    OUTPUT_DIR="$OUT/step2"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/cert_expiry.json"
    
    # Run check
    result=$(check_cert_expiry "$TARGET")
    
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
        echo "    {\"name\":\"Certificate Expiry\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "Certificate expiry check complete"
done
