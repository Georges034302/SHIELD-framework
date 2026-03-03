#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

# Phase 5 - Threat Intelligence Lookup
# Checks IP reputation via Spamhaus DNS BL, AbuseIPDB, and Google Safe Browsing.
# No API keys required for Spamhaus (DNS-based). Optional keys for GSB/AbuseIPDB.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step5_threat_intel"

# Optional API keys — set as env vars before running:
# export GSB_API_KEY="your-google-safe-browsing-api-key"
# export ABUSEIPDB_API_KEY="your-abuseipdb-api-key"

check_threat_intel() {
    local target="$1"
    local hostname
    hostname=$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##' | sed 's/:.*$//')

    local checks=()
    local overall="PASS"

    # ── 1. Resolve IP ─────────────────────────────────────────────────────────
    local ip
    ip=$(dig +short "$hostname" A 2>/dev/null | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | tail -1 || echo "")
    if [[ -z "$ip" ]]; then
        checks+=("WARN|Could not resolve IP for $hostname — threat intel checks skipped|N/A|LOW|")
        overall="WARN"
    else
        # ── 2. Spamhaus ZEN DNS Blocklist ─────────────────────────────────────
        # Reverse the IP for DNS lookup: 1.2.3.4 → 4.3.2.1.zen.spamhaus.org
        local rev_ip
        rev_ip=$(echo "$ip" | awk -F. '{print $4"."$3"."$2"."$1}')
        local spamhaus_result
        spamhaus_result=$(dig +short "${rev_ip}.zen.spamhaus.org" A 2>/dev/null | head -5 || echo "")

        if [[ -n "$spamhaus_result" ]]; then
            # Decode return codes
            local bl_categories=()
            echo "$spamhaus_result" | grep -q "127.0.0.2" && bl_categories+=("SBL (Spamhaus Block List — spam source/operation)")
            echo "$spamhaus_result" | grep -q "127.0.0.3" && bl_categories+=("CSS (Snowshoe spam)")
            echo "$spamhaus_result" | grep -qE "127.0.0.[45]" && bl_categories+=("XBL (Exploits Block List — compromised/botnet)")
            echo "$spamhaus_result" | grep -q "127.0.0.9" && bl_categories+=("DROP (Do Not Route — netblock allocated to criminals)")
            echo "$spamhaus_result" | grep -qE "127.0.1\." && bl_categories+=("PBL (Policy Block List — dynamic/end-user IP)")
            [[ ${#bl_categories[@]} -eq 0 ]] && bl_categories+=("Listed (return: $spamhaus_result)")

            local bl_str; bl_str=$(IFS="; "; printf '%s' "${bl_categories[*]}")
            checks+=("FAIL|IP $ip is listed on Spamhaus ZEN: $bl_str|IP not on any blocklist|HIGH|SEC-THREAT-001")
            overall="FAIL"
        else
            checks+=("PASS|IP $ip is not listed on Spamhaus ZEN blocklist|N/A|INFO|")
        fi

        # ── 3. Spamhaus DBL (Domain Block List) ───────────────────────────────
        local dbl_result
        dbl_result=$(dig +short "${hostname}.dbl.spamhaus.org" A 2>/dev/null | head -3 || echo "")
        if [[ -n "$dbl_result" ]] && ! echo "$dbl_result" | grep -qE 'NXDOMAIN|SERVFAIL|^$'; then
            local dbl_types=()
            echo "$dbl_result" | grep -q "127.0.1.2" && dbl_types+=("Spam domain")
            echo "$dbl_result" | grep -q "127.0.1.3" && dbl_types+=("Phishing domain")
            echo "$dbl_result" | grep -q "127.0.1.4" && dbl_types+=("Malware domain")
            echo "$dbl_result" | grep -q "127.0.1.5" && dbl_types+=("Botnet C&C domain")
            [[ ${#dbl_types[@]} -eq 0 ]] && dbl_types+=("Listed on DBL (return: $dbl_result)")
            local dbl_str; dbl_str=$(IFS="; "; printf '%s' "${dbl_types[*]}")
            checks+=("FAIL|Domain $hostname is on Spamhaus DBL: $dbl_str|Domain not on domain blocklist|CRITICAL|SEC-THREAT-001")
            overall="FAIL"
        else
            checks+=("PASS|Domain $hostname not listed on Spamhaus DBL|N/A|INFO|")
        fi

        # ── 4. Reverse DNS mismatch (bulletproof hosting indicator) ──────────
        local rdns
        rdns=$(dig +short -x "$ip" 2>/dev/null | sed 's/\.$//' | head -1 || echo "")
        if [[ -n "$rdns" ]]; then
            local rdns_domain
            rdns_domain=$(echo "$rdns" | awk -F. '{print $(NF-1)"."$NF}')
            local target_domain
            target_domain=$(echo "$hostname" | awk -F. '{print $(NF-1)"."$NF}')
            if [[ "$rdns_domain" != "$target_domain" ]]; then
                # Check if rdns looks suspicious
                if echo "$rdns" | grep -qiE 'bulletproof|spammy|abuse|malware|phish|bot|spam'; then
                    checks+=("FAIL|IP $ip reverse-resolves to suspicious host: $rdns (domain: $hostname)|Clean reverse DNS|HIGH|SEC-THREAT-002")
                    [[ "$overall" != "FAIL" ]] && overall="WARN"
                else
                    checks+=("INFO|IP $ip reverse-resolves to $rdns (different from $hostname) — shared/CDN hosting or mismatch|N/A|LOW|")
                fi
            else
                checks+=("PASS|Reverse DNS for $ip matches domain ($rdns)|N/A|INFO|")
            fi
        else
            checks+=("INFO|No reverse DNS (PTR) record for $ip|N/A|LOW|")
        fi

        # ── 5. AbuseIPDB (requires API key) ──────────────────────────────────
        if [[ -n "${ABUSEIPDB_API_KEY:-}" ]]; then
            local abuse_resp
            abuse_resp=$(curl -sS -G "https://api.abuseipdb.com/api/v2/check" \
                --data-urlencode "ipAddress=$ip" \
                -d "maxAgeInDays=90" \
                -d "verbose" \
                -H "Key: $ABUSEIPDB_API_KEY" \
                -H "Accept: application/json" \
                --max-time "${TIMEOUT:-10}" 2>/dev/null || echo "{}")

            local abuse_score
            abuse_score=$(echo "$abuse_resp" | grep -o '"abuseConfidenceScore":[0-9]*' | grep -o '[0-9]*' || echo "0")
            local abuse_reports
            abuse_reports=$(echo "$abuse_resp" | grep -o '"totalReports":[0-9]*' | grep -o '[0-9]*' || echo "0")

            if [[ "${abuse_score:-0}" -gt 50 ]]; then
                checks+=("FAIL|AbuseIPDB: $ip has confidence score ${abuse_score}% (${abuse_reports} reports in 90 days)|Score <25%|HIGH|SEC-THREAT-001")
                overall="FAIL"
            elif [[ "${abuse_score:-0}" -gt 25 ]]; then
                checks+=("WARN|AbuseIPDB: $ip has confidence score ${abuse_score}% (${abuse_reports} reports) — moderate abuse activity|Score <25%|MEDIUM|SEC-THREAT-001")
                [[ "$overall" == "PASS" ]] && overall="WARN"
            else
                checks+=("PASS|AbuseIPDB: $ip score ${abuse_score}% (${abuse_reports} reports) — clean|N/A|INFO|")
            fi
        else
            checks+=("INFO|AbuseIPDB check skipped — set ABUSEIPDB_API_KEY env var to enable|N/A|LOW|")
        fi

        # ── 6. Google Safe Browsing (requires API key) ────────────────────────
        if [[ -n "${GSB_API_KEY:-}" ]]; then
            local gsb_resp
            gsb_resp=$(curl -sS -X POST \
                "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=$GSB_API_KEY" \
                -H "Content-Type: application/json" \
                -d "{\"client\":{\"clientId\":\"shield-framework\",\"clientVersion\":\"5.0\"},\"threatInfo\":{\"threatTypes\":[\"MALWARE\",\"SOCIAL_ENGINEERING\",\"UNWANTED_SOFTWARE\",\"POTENTIALLY_HARMFUL_APPLICATION\"],\"platformTypes\":[\"ANY_PLATFORM\"],\"threatEntryTypes\":[\"URL\"],\"threatEntries\":[{\"url\":\"$target\"}]}}" \
                --max-time "${TIMEOUT:-10}" 2>/dev/null || echo "{}")

            if echo "$gsb_resp" | grep -q '"matches"'; then
                local threat_type
                threat_type=$(echo "$gsb_resp" | grep -o '"threatType":"[^"]*"' | head -1 | cut -d'"' -f4)
                checks+=("FAIL|Google Safe Browsing: $target flagged as $threat_type|Not flagged by Google|CRITICAL|SEC-THREAT-003")
                overall="FAIL"
            else
                checks+=("PASS|Google Safe Browsing: $target not flagged|N/A|INFO|")
            fi
        else
            checks+=("INFO|Google Safe Browsing check skipped — set GSB_API_KEY env var to enable|N/A|LOW|")
        fi
    fi

    local OUTPUT_DIR="$OUT/step5"
    mkdir -p "$OUTPUT_DIR"
    local OUTPUT_FILE="$OUTPUT_DIR/threat_intel.json"

    local check_names=("IP Resolution" "Spamhaus ZEN (IP)" "Spamhaus DBL (Domain)" "Reverse DNS" "AbuseIPDB" "Google Safe Browsing")
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
            name_e=$(json_escape "${check_names[$i]:-Threat Intel}")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"$name_e\",\"status\":\"$st_e\",\"found\":\"$fd_e\",\"expected\":\"$ex_e\",\"severity\":\"$sv_e\",\"remediation_id\":\"$rm_e\"}"
            (( i++ )) || true
        done
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$overall" "Threat intel check complete (overall: $overall)"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Running threat intel lookups: $TARGET"
    check_threat_intel "$TARGET"
done
