#!/usr/bin/env bash
# Phase 5 - Malicious Content Detection
# Scans page HTML for obfuscated JS, hidden iframes, cryptominers, pharma SEO,
# injected external scripts, suspicious meta refresh, and base64 payloads.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step5_malicious_content"

check_malicious_content() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    # ----- Fetch homepage twice: normal UA + Googlebot UA -----
    local html_normal
    html_normal=$(curl -sS -L --max-time "${TIMEOUT:-15}" \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36" \
        "$base_url/" 2>/dev/null | head -c 200000 || echo "")

    local html_googlebot
    html_googlebot=$(curl -sS -L --max-time "${TIMEOUT:-15}" \
        -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" \
        -H "Referer: https://www.google.com/search?q=site:$(echo "$base_url" | sed -E 's#https?://##')" \
        "$base_url/" 2>/dev/null | head -c 200000 || echo "")

    local checks=()
    local overall_severity="INFO"

    # ── 1. Obfuscated JavaScript ──────────────────────────────────────────────
    local obf_hits=()
    echo "$html_normal" | grep -qiE 'eval\s*\(\s*atob\s*\(' && obf_hits+=("eval(atob()")
    echo "$html_normal" | grep -qiE 'eval\s*\(\s*unescape\s*\(' && obf_hits+=("eval(unescape())")
    echo "$html_normal" | grep -qiE 'String\.fromCharCode\s*\([0-9, ]{20,}\)' && obf_hits+=("String.fromCharCode() with long sequence")
    echo "$html_normal" | grep -qiE '\bpackedJS\b|eval\(function\(p,a,c,k,e' && obf_hits+=("Packed/obfuscated JS (p,a,c,k,e,d pattern)")
    echo "$html_normal" | grep -qiE 'document\.write\s*\(\s*(unescape|atob|String\.fromCharCode)' && obf_hits+=("document.write with decoded payload")
    echo "$html_normal" | grep -qiE '<script[^>]*>[\s]*eval\s*\(' && obf_hits+=("Inline script starting with eval()")
    echo "$html_normal" | grep -qiE 'onload\s*=\s*["\'"'"']?eval\(' && obf_hits+=("onload handler executing eval()")

    if [[ ${#obf_hits[@]} -gt 0 ]]; then
        local obf_str; obf_str=$(IFS="; "; printf '%s' "${obf_hits[*]}")
        checks+=("FAIL|Obfuscated JavaScript detected: $obf_str|No obfuscated JS in page source|CRITICAL|SEC-MALJS-001")
        overall_severity="CRITICAL"
    else
        checks+=("PASS|No obfuscated JavaScript patterns detected|N/A|INFO|")
    fi

    # ── 2. Hidden Iframes ─────────────────────────────────────────────────────
    local iframe_hits=()
    echo "$html_normal" | grep -qiE '<iframe[^>]+(display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*["\'"'"']?0|height\s*=\s*["\'"'"']?0)' && \
        iframe_hits+=("Hidden iframe (display:none or 0-size)")
    echo "$html_normal" | grep -qiE '<iframe[^>]+style\s*=\s*["\'"'"'][^"'"'"']*left\s*:\s*-[0-9]{3,}' && \
        iframe_hits+=("Off-screen iframe (left: -NNNpx)")
    # Detect iframes sourcing external unknown domains
    local iframe_srcs
    iframe_srcs=$(echo "$html_normal" | grep -oiE '<iframe[^>]+src\s*=\s*["\'"'"'][^"\'"'"']+' | grep -oiE 'src\s*=\s*["\'"'"'][^"\'"'"']+' | sed "s/src=//;s/[\"']//g")
    local site_domain
    site_domain=$(echo "$base_url" | sed -E 's#https?://([^/]+).*#\1#' | sed 's/^www\.//')
    while IFS= read -r src; do
        [[ -z "$src" ]] && continue
        if ! echo "$src" | grep -qi "$site_domain" && echo "$src" | grep -qiE '^https?://'; then
            iframe_hits+=("External iframe: $src")
        fi
    done <<< "$iframe_srcs"

    if [[ ${#iframe_hits[@]} -gt 0 ]]; then
        local if_str; if_str=$(IFS="; "; printf '%s' "${iframe_hits[*]}")
        checks+=("FAIL|Hidden/suspicious iframes found: $if_str|No hidden iframes|CRITICAL|SEC-BACKDOOR-001")
        [[ "$overall_severity" != "CRITICAL" ]] && overall_severity="CRITICAL"
    else
        checks+=("PASS|No hidden or suspicious iframes detected|N/A|INFO|")
    fi

    # ── 3. Cryptominer Scripts ────────────────────────────────────────────────
    local miner_hits=()
    echo "$html_normal" | grep -qiE 'coinhive\.min\.js|coin-hive\.com|cryptonight|minero\.cc|webmr\.js|crypto-webminer|jsecoin|cryptoloot|coinblu\.com|hashfollow\.com' && \
        miner_hits+=("Known cryptominer library/domain in page source")
    echo "$html_normal" | grep -qiE 'CoinHive\.Anonymous|new CoinHive\.|new CryptoLoot\.' && \
        miner_hits+=("Cryptominer JS object instantiated")
    echo "$html_normal" | grep -qiE 'wasm.*proof.of.work|WebAssembly.*miner|SharedArrayBuffer.*hash' && \
        miner_hits+=("WebAssembly-based miner pattern")

    if [[ ${#miner_hits[@]} -gt 0 ]]; then
        local mn_str; mn_str=$(IFS="; "; printf '%s' "${miner_hits[*]}")
        checks+=("FAIL|Cryptominer detected: $mn_str|No mining scripts|CRITICAL|SEC-MINER-001")
        [[ "$overall_severity" != "CRITICAL" ]] && overall_severity="CRITICAL"
    else
        checks+=("PASS|No cryptominer scripts detected|N/A|INFO|")
    fi

    # ── 4. Pharma/Spam SEO Injection (Googlebot view) ────────────────────────
    local pharma_hits=()
    echo "$html_googlebot" | grep -qiE '\b(viagra|cialis|levitra|sildenafil|tadalafil|buy cheap|online pharmacy|cheap pills)\b' && \
        pharma_hits+=("Pharma keyword injection (visible to Googlebot)")
    echo "$html_googlebot" | grep -qiE '\b(casino|online gambling|slot machines|poker chips|free spins|sports betting)\b' && \
        pharma_hits+=("Casino/gambling SEO injection (visible to Googlebot)")
    echo "$html_googlebot" | grep -qiE '\b(payday loan|instant loan|bad credit loan|cash advance)\b' && \
        pharma_hits+=("Payday loan SEO injection (visible to Googlebot)")

    # Also check if Googlebot sees significantly different content size (cloaking indicator)
    local normal_len=${#html_normal}
    local bot_len=${#html_googlebot}
    local diff_pct=0
    if [[ $normal_len -gt 0 ]]; then
        diff_pct=$(( (bot_len - normal_len) * 100 / normal_len ))
        # Absolute value
        [[ $diff_pct -lt 0 ]] && diff_pct=$(( -diff_pct ))
    fi

    if [[ ${#pharma_hits[@]} -gt 0 ]]; then
        local ph_str; ph_str=$(IFS="; "; printf '%s' "${pharma_hits[*]}")
        checks+=("FAIL|SEO spam injection: $ph_str|No spam content in any view|CRITICAL|SEC-BACKDOOR-002")
        [[ "$overall_severity" != "CRITICAL" ]] && overall_severity="CRITICAL"
    elif [[ $diff_pct -gt 30 ]]; then
        checks+=("WARN|Googlebot response differs from normal UA by ~${diff_pct}% in size — possible cloaking/SEO injection|Consistent content for all user agents|MEDIUM|SEC-CLOAK-001")
        [[ "$overall_severity" == "INFO" ]] && overall_severity="MEDIUM"
    else
        checks+=("PASS|No pharma/casino SEO injection detected; Googlebot/normal UA responses consistent|N/A|INFO|")
    fi

    # ── 5. Injected External Scripts ─────────────────────────────────────────
    local ext_scripts=()
    local known_cdns="cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|ajax\.googleapis\.com|ajax\.aspnetcdn\.com|code\.jquery\.com|stackpath\.bootstrapcdn\.com|unpkg\.com|fonts\.googleapis\.com|fonts\.gstatic\.com"

    while IFS= read -r src; do
        [[ -z "$src" ]] && continue
        [[ "$src" =~ ^// ]] && src="https:$src"
        if echo "$src" | grep -qiE '^https?://'; then
            if ! echo "$src" | grep -qi "$site_domain" && ! echo "$src" | grep -qiE "$known_cdns"; then
                ext_scripts+=("$src")
            fi
        fi
    done < <(echo "$html_normal" | grep -oiE '<script[^>]+src\s*=\s*["\'"'"'][^"'"'"']+' | grep -oiE 'src\s*=\s*["\'"'"'][^"'"'"']+' | sed "s/src\s*=\s*//;s/[\"']//g")

    if [[ ${#ext_scripts[@]} -gt 3 ]]; then
        local es_str; es_str=$(IFS=", "; printf '%s' "${ext_scripts[@]:0:5}")
        checks+=("WARN|${#ext_scripts[@]} unknown external script sources: $es_str|Scripts served from own domain or known CDNs|MEDIUM|SEC-MALJS-002")
        [[ "$overall_severity" == "INFO" ]] && overall_severity="MEDIUM"
    elif [[ ${#ext_scripts[@]} -gt 0 ]]; then
        local es_str; es_str=$(IFS=", "; printf '%s' "${ext_scripts[*]}")
        checks+=("INFO|External script sources (review manually): $es_str|Verify these are authorised|LOW|SEC-MALJS-002")
    else
        checks+=("PASS|All scripts sourced from own domain or known CDNs|N/A|INFO|")
    fi

    # ── 6. Suspicious Meta Refresh ────────────────────────────────────────────
    local meta_refresh
    meta_refresh=$(echo "$html_normal" | grep -ioE '<meta[^>]+http-equiv\s*=\s*["\'"'"']?refresh["\'"'"']?[^>]+>' || echo "")
    if [[ -n "$meta_refresh" ]]; then
        local refresh_url
        refresh_url=$(echo "$meta_refresh" | grep -ioE 'url\s*=\s*[^\s"'"'"'>]+' | head -1)
        if echo "$refresh_url" | grep -qiE 'https?://' && ! echo "$refresh_url" | grep -qi "$site_domain"; then
            checks+=("FAIL|Off-site meta refresh redirect: $refresh_url|No external meta refresh|HIGH|SEC-BACKDOOR-003")
            [[ "$overall_severity" == "INFO" || "$overall_severity" == "LOW" ]] && overall_severity="HIGH"
        else
            checks+=("INFO|Meta refresh present but pointing to own domain: $refresh_url|Review if intentional|LOW|")
        fi
    else
        checks+=("PASS|No suspicious meta refresh redirects detected|N/A|INFO|")
    fi

    # ── Output JSON ───────────────────────────────────────────────────────────
    local OUTPUT_DIR="$OUT/step5"
    mkdir -p "$OUTPUT_DIR"
    local OUTPUT_FILE="$OUTPUT_DIR/malicious_content.json"

    {
        echo "{"
        echo "  \"step\": \"$STEP_NAME\","
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"target\": \"$target\","
        echo "  \"checks\": ["
        local first=true
        for check in "${checks[@]}"; do
            IFS='|' read -r st fd ex sv rm <<< "$check"
            local st_e fd_e ex_e sv_e rm_e
            st_e=$(json_escape "$st"); fd_e=$(json_escape "$fd")
            ex_e=$(json_escape "$ex"); sv_e=$(json_escape "$sv"); rm_e=$(json_escape "$rm")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"Malicious Content — ${st_e}\",\"status\":\"$st_e\",\"found\":\"$fd_e\",\"expected\":\"$ex_e\",\"severity\":\"$sv_e\",\"remediation_id\":\"$rm_e\"}"
        done
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$overall_severity" "Malicious content scan complete (overall: $overall_severity)"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Scanning for malicious content: $TARGET"
    check_malicious_content "$TARGET"
done
