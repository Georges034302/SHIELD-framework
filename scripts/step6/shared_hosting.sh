#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step6_shared_hosting"

check_shared_hosting() {
    local target="$1"
    local hostname
    hostname=$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##' | sed 's/:.*$//')

    local issues=()
    local severity="INFO"
    local hosting_signals=()

    # --- Resolve IP + reverse DNS ---
    local ip
    ip=$(dig +short "$hostname" A 2>/dev/null | tail -1 || echo "")

    if [[ -z "$ip" ]]; then
        echo "WARN|Could not resolve IP for $hostname|N/A|LOW|SEC-SHARED-001"
        return
    fi

    local reverse_dns
    reverse_dns=$(dig +short -x "$ip" 2>/dev/null | head -1 | sed 's/\.$//' || echo "")

    # --- Shared hosting indicators ---
    # Reverse DNS patterns common to shared hosts
    if echo "$reverse_dns" | grep -qiE "cpanel|plesk|server[0-9]+\.|shared|host[0-9]+\.|siteground|hostgator|bluehost|godaddy|namecheap|dreamhost|inmotionhosting|wpengine|kinsta|cloudways|liquidweb"; then
        hosting_signals+=("Reverse DNS suggests shared/managed hosting: $reverse_dns")
        severity="MEDIUM"
    fi

    # Check cPanel/Plesk exposure
    local response_headers
    response_headers=$(curl -sS -I --max-time "${TIMEOUT:-10}" "$target" 2>/dev/null || echo "")

    if echo "$response_headers" | grep -qi "x-cpanel\|cpanel\|whm\|x-plesk\|plesk"; then
        hosting_signals+=("cPanel/Plesk control panel headers detected")
        issues+=("Control panel headers expose hosting platform identity")
        [[ "$severity" == "INFO" ]] && severity="MEDIUM"
    fi

    # Check if multiple domains resolve to same IP (shared IP indicator)
    local reverse_ptr
    reverse_ptr=$(host "$ip" 2>/dev/null | grep "domain name pointer" | head -3 | awk '{print $NF}' || echo "")

    if [[ -n "$reverse_ptr" ]] && [[ "$reverse_ptr" != "$hostname." ]]; then
        hosting_signals+=("IP $ip reverse-resolves to $reverse_ptr (different from $hostname — shared IP)")
        [[ "$severity" == "INFO" ]] && severity="LOW"
    fi

    # Check cPanel/WHM/Plesk default ports
    local mgmt_ports=("2082:cPanel HTTP" "2083:cPanel HTTPS" "2086:WHM HTTP" "2087:WHM HTTPS" "8443:Plesk HTTPS" "8880:Plesk HTTP")
    for port_info in "${mgmt_ports[@]}"; do
        local port="${port_info%%:*}"
        local name="${port_info#*:}"
        local port_check
        port_check=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 "http://$hostname:$port/" 2>/dev/null || echo "000")
        if [[ "$port_check" != "000" ]] && [[ "$port_check" != "400" ]]; then
            issues+=("$name panel accessible on port $port (HTTP $port_check)")
            severity="HIGH"
        fi
    done

    # Cross-site contamination risk assessment
    local contamination_risk=""
    if [[ ${#hosting_signals[@]} -gt 0 ]] && [[ ${#issues[@]} -eq 0 ]]; then
        contamination_risk="Shared hosting detected — cross-site contamination possible if another tenant is compromised"
        [[ "$severity" == "INFO" ]] && severity="MEDIUM"
        issues+=("$contamination_risk")
    fi

    if [[ ${#issues[@]} -eq 0 ]] && [[ ${#hosting_signals[@]} -eq 0 ]]; then
        echo "PASS|No shared hosting indicators detected; appears to be dedicated/cloud infrastructure|N/A|INFO|"
        return
    fi

    if [[ ${#issues[@]} -eq 0 ]]; then
        local signals_str
        signals_str=$(IFS="; "; printf '%s' "${hosting_signals[*]}")
        echo "INFO|Shared hosting signals: $signals_str|Consider isolated hosting for sensitive sites|$severity|SEC-SHARED-001"
        return
    fi

    local issues_str
    issues_str=$(IFS="; "; printf '%s' "${issues[*]}")
    local signals_str
    signals_str=$(IFS=", "; printf '%s' "${hosting_signals[*]}")
    [[ -n "$signals_str" ]] && issues_str="$issues_str (signals: $signals_str)"

    echo "WARN|$issues_str|Restrict control panel access by IP; use dedicated hosting for critical sites|$severity|SEC-SHARED-002"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking shared hosting indicators for $TARGET"

    OUTPUT_DIR="$OUT/step6"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/shared_hosting.json"

    result=$(check_shared_hosting "$TARGET")
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
        echo "    {\"name\":\"Shared Hosting Indicators\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "Shared hosting check complete"
done
