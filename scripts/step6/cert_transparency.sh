#!/usr/bin/env bash
# Phase 5 - Certificate Transparency & TLS Validation
# Queries crt.sh for unexpected SANs/subdomains.
# Checks self-signed cert, cert issuer anomaly, expiry, and SANs scope.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step6_cert_transparency"

# Known trusted CA root names (partial match)
TRUSTED_CAS="Let's Encrypt|DigiCert|Comodo|Sectigo|GlobalSign|GeoTrust|RapidSSL|Thawte|Entrust|Amazon|Microsoft|Google Trust|ISRG|Certum|GoDaddy|Network Solutions|VeriSign|Symantec|IdenTrust"

check_cert_transparency() {
    local target="$1"
    local hostname
    hostname=$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##' | sed 's/:.*$//')
    local base_domain
    base_domain=$(echo "$hostname" | awk -F. 'NF>=2{print $(NF-1)"."$NF}')

    local checks=()

    # ── 1. Live TLS Certificate Details ──────────────────────────────────────
    local cert_info
    cert_info=$(echo | timeout "${TIMEOUT:-10}" openssl s_client \
        -connect "$hostname:443" \
        -servername "$hostname" 2>/dev/null | openssl x509 -noout \
        -subject -issuer -dates -ext subjectAltName 2>/dev/null || echo "")

    if [[ -z "$cert_info" ]]; then
        checks+=("WARN|Could not retrieve TLS certificate for $hostname (no HTTPS or connection refused)|Valid TLS certificate required|HIGH|SEC-TLS-001")
    else
        # Self-signed detection
        local subject issuer
        subject=$(echo "$cert_info" | grep "^subject=" | sed 's/subject=//')
        issuer=$(echo "$cert_info"  | grep "^issuer="  | sed 's/issuer=//')

        if [[ "$subject" == "$issuer" ]]; then
            checks+=("FAIL|Self-signed certificate: issuer equals subject ($issuer)|Certificate from trusted CA|CRITICAL|SEC-TLS-002")
        elif ! echo "$issuer" | grep -qiE "$TRUSTED_CAS"; then
            checks+=("WARN|Certificate issued by unknown/untrusted CA: $issuer|Certificate from known trusted CA|HIGH|SEC-TLS-002")
        else
            checks+=("PASS|Certificate issued by trusted CA: $issuer|N/A|INFO|")
        fi

        # Expiry check
        local not_after
        not_after=$(echo "$cert_info" | grep "notAfter=" | sed 's/notAfter=//')
        if [[ -n "$not_after" ]]; then
            local expiry_epoch
            expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null || date -jf "%b %d %T %Y %Z" "$not_after" +%s 2>/dev/null || echo "0")
            local now_epoch; now_epoch=$(date +%s)
            local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

            if [[ $days_left -lt 0 ]]; then
                checks+=("FAIL|TLS certificate EXPIRED $((- days_left)) days ago ($not_after)|Valid, non-expired certificate|CRITICAL|SEC-TLS-001")
            elif [[ $days_left -lt 14 ]]; then
                checks+=("FAIL|TLS certificate expires in $days_left days ($not_after) — URGENT renewal needed|Certificate valid >30 days|HIGH|SEC-TLS-001")
            elif [[ $days_left -lt 30 ]]; then
                checks+=("WARN|TLS certificate expires in $days_left days ($not_after) — renew soon|Certificate valid >30 days|MEDIUM|SEC-TLS-001")
            else
                checks+=("PASS|TLS certificate valid for $days_left more days (expires $not_after)|N/A|INFO|")
            fi
        fi

        # SAN scope — detect overly broad SANs (wildcard + many unrelated domains)
        local sans
        sans=$(echo "$cert_info" | grep -A5 "subjectAltName" | grep "DNS:" | tr ',' '\n' | sed 's/.*DNS://;s/^ *//' | grep -v '^$' || echo "")
        local san_count; san_count=$(echo "$sans" | grep -c '\S' || echo "0")
        local wildcard_sans; wildcard_sans=$(echo "$sans" | grep '^\*\.' || echo "")
        local unrelated_sans=()

        while IFS= read -r san; do
            [[ -z "$san" ]] && continue
            local san_clean="${san#\*.}"
            if ! echo "$san_clean" | grep -qi "$base_domain"; then
                unrelated_sans+=("$san")
            fi
        done <<< "$sans"

        if [[ ${#unrelated_sans[@]} -gt 0 ]]; then
            local ur_str; ur_str=$(IFS=", "; printf '%s' "${unrelated_sans[*]}")
            checks+=("WARN|Certificate covers unrelated domains in SANs: $ur_str (${san_count} total SANs)|Certificate should only cover your domains|MEDIUM|SEC-TLS-003")
        elif [[ -n "$wildcard_sans" ]]; then
            checks+=("INFO|Wildcard SAN present: $wildcard_sans (covers all subdomains of $base_domain)|Acceptable if intentional|LOW|")
        else
            checks+=("PASS|Certificate SANs ($san_count) all relate to $base_domain|N/A|INFO|")
        fi
    fi

    # ── 2. Certificate Transparency Log (crt.sh) ─────────────────────────────
    local crtsh_resp
    crtsh_resp=$(curl -sS "https://crt.sh/?q=%25.$base_domain&output=json" \
        --max-time "${TIMEOUT:-15}" 2>/dev/null || echo "[]")

    if [[ "$crtsh_resp" == "[]" || -z "$crtsh_resp" ]]; then
        checks+=("INFO|No Certificate Transparency records found for $base_domain on crt.sh|N/A|LOW|")
    else
        # Count unique issuers in CT logs
        local unique_issuers
        unique_issuers=$(echo "$crtsh_resp" | grep -o '"issuer_name":"[^"]*"' | sort -u | wc -l | tr -d ' ')

        # Find unexpected subdomains from CT logs
        local ct_domains
        ct_domains=$(echo "$crtsh_resp" | grep -o '"common_name":"[^"]*"' | cut -d'"' -f4 | \
            sort -u | grep -v "^$" | head -50 || echo "")

        local ct_count; ct_count=$(echo "$ct_domains" | grep -c '\S' || echo "0")

        # Detect suspicious subdomains in CT
        local suspicious_ct=()
        while IFS= read -r domain; do
            [[ -z "$domain" ]] && continue
            echo "$domain" | grep -qiE 'admin\.|portal\.|secure\.|login\.|vpn\.|internal\.|corp\.|api\.' && \
                suspicious_ct+=("$domain")
        done <<< "$ct_domains"

        if [[ ${#suspicious_ct[@]} -gt 0 ]]; then
            local sc_str; sc_str=$(IFS=", "; printf '%s' "${suspicious_ct[@]:0:10}")
            checks+=("INFO|CT logs reveal ${ct_count} subdomains; sensitive-looking names: $sc_str|N/A|LOW|")
        else
            checks+=("PASS|CT logs show $ct_count subdomains, $unique_issuers unique issuer(s) — no anomalies|N/A|INFO|")
        fi

        # Detect very recent cert issuance (possible attacker obtaining cert for subdomain)
        local recent_certs
        recent_certs=$(echo "$crtsh_resp" | grep -o '"not_before":"2[0-9][0-9][0-9]-[01][0-9]-[0-3][0-9]' | \
            grep -v "$(date +%Y-%m)" | head -3 || echo "")
        # Check for certs issued in last 7 days
        local cutoff; cutoff=$(date -d "7 days ago" +%Y-%m-%d 2>/dev/null || date -v-7d +%Y-%m-%d 2>/dev/null || echo "")
        if [[ -n "$cutoff" ]]; then
            local very_recent
            very_recent=$(echo "$crtsh_resp" | python3 -c "
import sys, json, datetime
try:
    data = json.load(sys.stdin)
    cutoff = datetime.datetime.strptime('$cutoff', '%Y-%m-%d')
    recent = [e.get('common_name','') for e in data
              if e.get('not_before','') >= '$cutoff'][:5]
    print('; '.join(set(recent)))
except: pass
" 2>/dev/null || echo "")

            if [[ -n "$very_recent" ]]; then
                checks+=("WARN|Very recently issued certificates (last 7 days): $very_recent — verify these are authorised|Only your team issues certificates for this domain|MEDIUM|SEC-TLS-003")
            fi
        fi
    fi

    # ── 3. HSTS Check ─────────────────────────────────────────────────────────
    local hsts_header
    hsts_header=$(curl -sS -I --max-time "${TIMEOUT:-8}" "https://$hostname/" 2>/dev/null | \
        grep -i "strict-transport-security" | head -1 | tr -d '\r' || echo "")

    if [[ -z "$hsts_header" ]]; then
        checks+=("WARN|HSTS (Strict-Transport-Security) header not set — browsers can be MITM'd on first visit|HSTS with max-age>=31536000|MEDIUM|SEC-TLS-004")
    elif echo "$hsts_header" | grep -qi "max-age=0"; then
        checks+=("FAIL|HSTS header present but max-age=0 (effectively disabled)|max-age>=31536000|MEDIUM|SEC-TLS-004")
    else
        checks+=("PASS|HSTS header present: $(echo "$hsts_header" | sed 's/strict-transport-security: //i')|N/A|INFO|")
    fi

    local OUTPUT_DIR="$OUT/step6"
    mkdir -p "$OUTPUT_DIR"
    local OUTPUT_FILE="$OUTPUT_DIR/cert_transparency.json"

    local check_names=("Live Certificate (Issuer)" "Certificate Expiry" "Certificate SANs" "CT Log Subdomains" "Recent Cert Issuance" "HSTS Header")
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
            name_e=$(json_escape "${check_names[$i]:-Cert Check}")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"$name_e\",\"status\":\"$st_e\",\"found\":\"$fd_e\",\"expected\":\"$ex_e\",\"severity\":\"$sv_e\",\"remediation_id\":\"$rm_e\"}"
            (( i++ )) || true
        done
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    local has_fail=false
    for c in "${checks[@]}"; do [[ "$c" == FAIL* ]] && has_fail=true; done
    $has_fail && print_status "FAIL" "Cert transparency: failures found" && return
    print_status "PASS" "Cert transparency: checks complete"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking certificate transparency: $TARGET"
    check_cert_transparency "$TARGET"
done
