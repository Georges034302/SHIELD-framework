#!/usr/bin/env bash
# Phase 5 - Cloaking Detection
# Detects content served differently based on User-Agent, Referer, or IP (cloaking).
# Compares: normal browser UA vs Googlebot UA vs Google-referred visitor.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step5_cloaking_check"

SITE_DOMAIN=""

check_cloaking() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')
    SITE_DOMAIN=$(echo "$base_url" | sed -E 's#https?://([^/]+).*#\1#' | sed 's/^www\.//')

    local checks=()
    local overall="PASS"

    # ── Fetch three views ─────────────────────────────────────────────────────
    local ua_normal="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36"
    local ua_googlebot="Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    local ua_bingbot="Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"

    local body_normal
    body_normal=$(curl -sS -L --max-time "${TIMEOUT:-15}" \
        -H "User-Agent: $ua_normal" \
        "$base_url/" 2>/dev/null | head -c 200000 || echo "")

    local body_googlebot
    body_googlebot=$(curl -sS -L --max-time "${TIMEOUT:-15}" \
        -H "User-Agent: $ua_googlebot" \
        "$base_url/" 2>/dev/null | head -c 200000 || echo "")

    local body_referer
    body_referer=$(curl -sS -L --max-time "${TIMEOUT:-15}" \
        -H "User-Agent: $ua_normal" \
        -H "Referer: https://www.google.com/search?q=site:$SITE_DOMAIN" \
        "$base_url/" 2>/dev/null | head -c 200000 || echo "")

    local body_bingbot
    body_bingbot=$(curl -sS -L --max-time "${TIMEOUT:-15}" \
        -H "User-Agent: $ua_bingbot" \
        "$base_url/" 2>/dev/null | head -c 200000 || echo "")

    local len_normal=${#body_normal}
    local len_bot=${#body_googlebot}
    local len_referer=${#body_referer}
    local len_bing=${#body_bingbot}

    # helper: percentage difference
    pct_diff() {
        local a=$1 b=$2
        [[ $a -eq 0 ]] && echo 0 && return
        local d=$(( (b - a) * 100 / a ))
        [[ $d -lt 0 ]] && d=$(( -d ))
        echo "$d"
    }

    # ── 1. UA Cloaking: normal vs Googlebot ──────────────────────────────────
    local diff_bot; diff_bot=$(pct_diff "$len_normal" "$len_bot")
    if [[ $diff_bot -gt 40 ]]; then
        checks+=("FAIL|Googlebot response is ~${diff_bot}% different in size vs normal UA (normal: ${len_normal}B, bot: ${len_bot}B) — strong cloaking indicator|Consistent content for all UAs|CRITICAL|SEC-CLOAK-001")
        overall="CRITICAL"
    elif [[ $diff_bot -gt 20 ]]; then
        checks+=("WARN|Googlebot response differs ~${diff_bot}% from normal UA — possible cloaking (normal: ${len_normal}B, bot: ${len_bot}B)|Consistent content for all UAs|MEDIUM|SEC-CLOAK-001")
        [[ "$overall" == "PASS" || "$overall" == "INFO" ]] && overall="WARN"
    else
        checks+=("PASS|Googlebot UA response consistent with normal UA (~${diff_bot}% size diff)|N/A|INFO|")
    fi

    # ── 2. Referer Cloaking: Google search referer ───────────────────────────
    local diff_ref; diff_ref=$(pct_diff "$len_normal" "$len_referer")
    if [[ $diff_ref -gt 40 ]]; then
        checks+=("FAIL|Google-referer response is ~${diff_ref}% different in size vs no-referer — referer-based cloaking detected|Consistent content regardless of Referer|CRITICAL|SEC-CLOAK-001")
        overall="CRITICAL"
    elif [[ $diff_ref -gt 20 ]]; then
        checks+=("WARN|Google-referer response differs ~${diff_ref}% from no-referer — possible referer cloaking|Consistent content regardless of Referer|MEDIUM|SEC-CLOAK-001")
        [[ "$overall" == "PASS" || "$overall" == "INFO" ]] && overall="WARN"
    else
        checks+=("PASS|Google-referer response consistent with normal request (~${diff_ref}% diff)|N/A|INFO|")
    fi

    # ── 3. Pharma/Spam keywords in bot view but not normal ───────────────────
    local spam_patterns='\b(viagra|cialis|levitra|sildenafil|casino|poker|payday loan|cheap pills|online pharmacy|buy online cheap)\b'
    local spam_in_bot=false spam_in_normal=false
    echo "$body_googlebot" | grep -qiE "$spam_patterns" && spam_in_bot=true
    echo "$body_normal"    | grep -qiE "$spam_patterns" && spam_in_normal=true

    if $spam_in_bot && ! $spam_in_normal; then
        checks+=("FAIL|Pharma/spam keywords visible to Googlebot but NOT to normal visitors — active SEO spam backdoor|No spam content in any view|CRITICAL|SEC-BACKDOOR-002")
        overall="CRITICAL"
    elif $spam_in_bot && $spam_in_normal; then
        checks+=("WARN|Pharma/spam keywords visible to both Googlebot and normal visitors|No spam content at all|HIGH|SEC-BACKDOOR-002")
        [[ "$overall" != "CRITICAL" ]] && overall="WARN"
    else
        checks+=("PASS|No pharma/spam keywords found in bot or normal view|N/A|INFO|")
    fi

    # ── 4. Bingbot vs normal ─────────────────────────────────────────────────
    local diff_bing; diff_bing=$(pct_diff "$len_normal" "$len_bing")
    if [[ $diff_bing -gt 40 ]]; then
        checks+=("FAIL|Bingbot response ~${diff_bing}% different from normal UA — multi-bot cloaking confirmed|Consistent content for all bots|CRITICAL|SEC-CLOAK-001")
        overall="CRITICAL"
    else
        checks+=("PASS|Bingbot response consistent with normal UA (~${diff_bing}% diff)|N/A|INFO|")
    fi

    # ── Output JSON ───────────────────────────────────────────────────────────
    local OUTPUT_DIR="$OUT/step5"
    mkdir -p "$OUTPUT_DIR"
    local OUTPUT_FILE="$OUTPUT_DIR/cloaking_check.json"

    local check_names=("UA Cloaking (Googlebot)" "Referer Cloaking (Google)" "Pharma/SEO Cloaking" "UA Cloaking (Bingbot)")
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
            name_e=$(json_escape "${check_names[$i]:-Cloaking Check}")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"$name_e\",\"status\":\"$st_e\",\"found\":\"$fd_e\",\"expected\":\"$ex_e\",\"severity\":\"$sv_e\",\"remediation_id\":\"$rm_e\"}"
            (( i++ )) || true
        done
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$overall" "Cloaking check complete (overall: $overall)"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking for cloaking: $TARGET"
    check_cloaking "$TARGET"
done
