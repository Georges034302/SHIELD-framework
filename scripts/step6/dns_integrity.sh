#!/usr/bin/env bash
# Phase 5 - DNS Integrity Check
# Validates SPF, DMARC, MX records for hijack/misconfiguration.
# Checks for wildcard DNS, unexpected TXT records, and DNS anomalies.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step6_dns_integrity"

check_dns_integrity() {
    local target="$1"
    local hostname
    hostname=$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##' | sed 's/:.*$//')
    # Strip subdomain to get base domain for SPF/DMARC
    local base_domain
    base_domain=$(echo "$hostname" | awk -F. 'NF>=2{print $(NF-1)"."$NF}')

    local checks=()

    # ── 1. SPF Record ─────────────────────────────────────────────────────────
    local spf
    spf=$(dig +short TXT "$base_domain" 2>/dev/null | grep -i 'v=spf1' | head -1 | tr -d '"' || echo "")

    if [[ -z "$spf" ]]; then
        checks+=("FAIL|No SPF record found for $base_domain|v=spf1 ... -all record required|MEDIUM|SEC-DNS-001")
    elif echo "$spf" | grep -q '\+all'; then
        checks+=("FAIL|SPF record allows ALL senders (+all): $spf|End with -all (hard fail)|HIGH|SEC-DNS-001")
    elif echo "$spf" | grep -q '~all'; then
        checks+=("WARN|SPF uses softfail (~all) instead of hardfail (-all): $spf|Change ~all to -all|MEDIUM|SEC-DNS-001")
    elif echo "$spf" | grep -q '\-all'; then
        checks+=("PASS|SPF record configured with -all (hard fail): $spf|N/A|INFO|")
    else
        checks+=("INFO|SPF record present but review recommended: $spf|Ensure -all is set|LOW|SEC-DNS-001")
    fi

    # ── 2. DMARC Record ───────────────────────────────────────────────────────
    local dmarc
    dmarc=$(dig +short TXT "_dmarc.$base_domain" 2>/dev/null | grep -i 'v=DMARC1' | head -1 | tr -d '"' || echo "")

    if [[ -z "$dmarc" ]]; then
        checks+=("FAIL|No DMARC record found for _dmarc.$base_domain|v=DMARC1; p=reject required|HIGH|SEC-DNS-002")
    elif echo "$dmarc" | grep -qi 'p=none'; then
        checks+=("WARN|DMARC policy is p=none (monitor only, no enforcement): $dmarc|Change to p=quarantine or p=reject|MEDIUM|SEC-DNS-002")
    elif echo "$dmarc" | grep -qi 'p=quarantine'; then
        checks+=("WARN|DMARC policy is p=quarantine (not full rejection): $dmarc|Upgrade to p=reject|LOW|SEC-DNS-002")
    elif echo "$dmarc" | grep -qi 'p=reject'; then
        checks+=("PASS|DMARC policy is p=reject (full enforcement): $dmarc|N/A|INFO|")
    else
        checks+=("INFO|DMARC record present but policy unclear: $dmarc|Verify p=reject is set|LOW|SEC-DNS-002")
    fi

    # ── 3. MX Record Validation ───────────────────────────────────────────────
    local mx_records
    mx_records=$(dig +short MX "$base_domain" 2>/dev/null | sort || echo "")

    if [[ -z "$mx_records" ]]; then
        checks+=("INFO|No MX records found for $base_domain — domain does not accept email|N/A|INFO|")
    else
        local suspicious_mx=()
        while IFS= read -r mx; do
            local mx_host; mx_host=$(echo "$mx" | awk '{print $NF}' | sed 's/\.$//')
            # Check if MX host resolves correctly
            local mx_ip; mx_ip=$(dig +short "$mx_host" A 2>/dev/null | head -1 || echo "")
            if [[ -z "$mx_ip" ]]; then
                suspicious_mx+=("MX $mx_host does not resolve — possible hijacked/orphaned MX")
            fi
            # Check for suspicious MX domains
            echo "$mx_host" | grep -qiE 'spam|phish|abuse|malware|bullet' && \
                suspicious_mx+=("Suspicious MX hostname: $mx_host")
        done <<< "$mx_records"

        if [[ ${#suspicious_mx[@]} -gt 0 ]]; then
            local mxs_str; mxs_str=$(IFS="; "; printf '%s' "${suspicious_mx[*]}")
            checks+=("FAIL|MX anomalies detected: $mxs_str|Valid, resolving MX records pointing to legitimate mail servers|HIGH|SEC-DNS-003")
        else
            local mx_count; mx_count=$(echo "$mx_records" | wc -l | tr -d ' ')
            checks+=("PASS|$mx_count MX record(s) present and resolving correctly|N/A|INFO|")
        fi
    fi

    # ── 4. Wildcard DNS ───────────────────────────────────────────────────────
    local random_sub="xyzrandom${RANDOM}${RANDOM}"
    local wildcard_result
    wildcard_result=$(dig +short "${random_sub}.${base_domain}" A 2>/dev/null | head -1 || echo "")

    if [[ -n "$wildcard_result" ]]; then
        checks+=("WARN|Wildcard DNS active: ${random_sub}.${base_domain} resolves to $wildcard_result — all subdomains resolve|Wildcard DNS disabled unless required for service|MEDIUM|SEC-DNS-004")
    else
        checks+=("PASS|No wildcard DNS detected for ${base_domain}|N/A|INFO|")
    fi

    # ── 5. TXT Record Anomaly Scan ────────────────────────────────────────────
    local txt_records
    txt_records=$(dig +short TXT "$base_domain" 2>/dev/null | tr -d '"' || echo "")

    local sus_txt=()
    while IFS= read -r txt; do
        [[ -z "$txt" ]] && continue
        # Skip known legitimate patterns
        echo "$txt" | grep -qiE '^(v=spf1|v=DMARC1|google-site-verification|MS=ms|docusign|atlassian|stripe-verification|apple-domain-verification|facebook-domain-verification|_dmarc)' && continue
        # Flag unusual patterns
        if echo "$txt" | grep -qiE 'eval\(|base64|cmd=|exec\(|/bin/sh|/etc/passwd|<script'; then
            sus_txt+=("INJECTED TXT: $txt")
        elif echo "$txt" | grep -qiE '^[A-Za-z0-9+/]{40,}={0,2}$'; then
            sus_txt+=("Possible base64 payload in TXT: ${txt:0:40}...")
        fi
    done <<< "$txt_records"

    if [[ ${#sus_txt[@]} -gt 0 ]]; then
        local txt_str; txt_str=$(IFS="; "; printf '%s' "${sus_txt[*]}")
        checks+=("FAIL|Suspicious TXT records detected: $txt_str|Only legitimate service verification TXT records|HIGH|SEC-DNS-005")
    else
        local txt_count; txt_count=$(echo "$txt_records" | grep -c '\S' || echo "0")
        checks+=("PASS|$txt_count TXT record(s) — no anomalies detected|N/A|INFO|")
    fi

    # ── 6. DNS over HTTPS — recent IP changes (Cloudflare DoH) ──────────────
    local doh_ip
    doh_ip=$(curl -sS -H "accept: application/dns-json" \
        "https://cloudflare-dns.com/dns-query?name=$hostname&type=A" \
        --max-time "${TIMEOUT:-8}" 2>/dev/null | \
        grep -o '"data":"[0-9.]*"' | head -1 | cut -d'"' -f4 || echo "")

    local local_ip
    local_ip=$(dig +short "$hostname" A 2>/dev/null | tail -1 || echo "")

    if [[ -n "$doh_ip" && -n "$local_ip" && "$doh_ip" != "$local_ip" ]]; then
        checks+=("WARN|Cloudflare DoH resolves $hostname to $doh_ip but local DNS resolves to $local_ip — possible split-DNS or recent change|Consistent resolution across DNS resolvers|MEDIUM|SEC-DNS-004")
    elif [[ -n "$doh_ip" ]]; then
        checks+=("PASS|DNS resolution consistent between local and Cloudflare DoH ($doh_ip)|N/A|INFO|")
    else
        checks+=("INFO|Could not verify DNS via Cloudflare DoH|N/A|LOW|")
    fi

    local OUTPUT_DIR="$OUT/step6"
    mkdir -p "$OUTPUT_DIR"
    local OUTPUT_FILE="$OUTPUT_DIR/dns_integrity.json"

    local check_names=("SPF Record" "DMARC Record" "MX Records" "Wildcard DNS" "TXT Record Anomaly" "DNS Consistency (DoH)")
    {
        echo "{"
        echo "  \"step\": \"$STEP_NAME\","
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"target\": \"$target\","
        echo "  \"checks\": ["
        local first=true
        local i=0
        for check in "${checks[@]}"; do
            IFS='|' read -r st fd ex sv rm <<< "$check"
            local st_e fd_e ex_e sv_e rm_e name_e
            st_e=$(json_escape "$st"); fd_e=$(json_escape "$fd")
            ex_e=$(json_escape "$ex"); sv_e=$(json_escape "$sv"); rm_e=$(json_escape "$rm")
            name_e=$(json_escape "${check_names[$i]:-DNS Check}")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"$name_e\",\"status\":\"$st_e\",\"found\":\"$fd_e\",\"expected\":\"$ex_e\",\"severity\":\"$sv_e\",\"remediation_id\":\"$rm_e\"}"
            (( i++ )) || true
        done
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    # Determine overall worst status
    local has_fail=false has_warn=false
    for c in "${checks[@]}"; do
        [[ "$c" == FAIL* ]] && has_fail=true
        [[ "$c" == WARN* ]] && has_warn=true
    done
    $has_fail && print_status "FAIL" "DNS integrity: failures found" && return
    $has_warn && print_status "WARN" "DNS integrity: warnings found" && return
    print_status "PASS" "DNS integrity: all checks passed"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking DNS integrity: $TARGET"
    check_dns_integrity "$TARGET"
done
