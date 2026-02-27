#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step6_subdomain_enum"

# Passive subdomain enumeration via certificate transparency logs (crt.sh)
check_subdomain_enum() {
    local target="$1"
    local hostname
    hostname=$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##' | sed 's/:.*$//')

    local issues=()
    local severity="INFO"

    # Query crt.sh for subdomains (certificate transparency logs)
    local crt_response
    crt_response=$(curl -sS --max-time "${TIMEOUT:-10}" \
        "https://crt.sh/?q=%25.$hostname&output=json" 2>/dev/null || echo "")

    if [[ -z "$crt_response" ]] || [[ "$crt_response" == "[]" ]]; then
        echo "INFO|No subdomains found in certificate transparency logs|Subdomain exposure reviewed|INFO|"
        return
    fi

    # Extract unique subdomain names
    local subdomains
    subdomains=$(echo "$crt_response" | grep -oP '"name_value":"[^"]*"' | \
        sed 's/"name_value":"//;s/"//' | \
        grep -v '^\*\.' | \
        sort -u 2>/dev/null || echo "")

    local count
    count=$(echo "$subdomains" | grep -c . || echo "0")

    # Check for sensitive-looking subdomains
    local sensitive
    sensitive=$(echo "$subdomains" | grep -iE "admin|dev|staging|test|internal|vpn|api|beta|uat|qa|preprod|old|backup|legacy" || echo "")
    local sensitive_count
    sensitive_count=$(echo "$sensitive" | grep -c . || echo "0")

    if [[ "$sensitive_count" -gt 0 ]]; then
        local sensitive_list
        sensitive_list=$(echo "$sensitive" | head -5 | tr '\n' ', ' | sed 's/,$//')
        issues+=("$sensitive_count sensitive subdomains found: $sensitive_list")
        severity="MEDIUM"
    fi

    if [[ "$count" -gt 50 ]]; then
        issues+=("Large attack surface: $count subdomains exposed in CT logs")
        [[ "$severity" == "INFO" ]] && severity="LOW"
    fi

    if [[ ${#issues[@]} -eq 0 ]]; then
        echo "PASS|$count subdomains in CT logs, none appear sensitive|Sensitive subdomains hardened or removed|INFO|"
        return
    fi

    local issues_str
    issues_str=$(IFS="; "; printf '%s' "${issues[*]}")
    echo "WARN|$issues_str|Secure or remove sensitive subdomains; review CT log exposure|$severity|SEC-SUBDOMAIN-001"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Enumerating subdomains for $TARGET"

    OUTPUT_DIR="$OUT/step6"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/subdomain_enum.json"

    result=$(check_subdomain_enum "$TARGET")

    IFS='|' read -r status found expected severity remediation_id <<< "$result"

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
        echo "    {\"name\":\"Subdomain Enumeration\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "Subdomain enumeration complete"
done
