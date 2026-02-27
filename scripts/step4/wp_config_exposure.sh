#!/usr/bin/env bash
# Phase 5 - WordPress Config File Exposure
# Checks if wp-config.php, wp-config.php.bak, and related config files
# are accessible and contain readable credentials.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"
source "$SCRIPT_DIR/lib/wp_detect.sh"

STEP_NAME="step4_wp_config_exposure"

# Config paths relative to web root — ordered by risk
CONFIG_PATHS=(
    "wp-config.php:CRITICAL:Primary WP config (DB_HOST, DB_USER, DB_PASSWORD, AUTH_KEY)"
    "wp-config.php.bak:CRITICAL:Backup of WP config — often left by editors/FTP clients"
    "wp-config.php.old:CRITICAL:Old WP config backup"
    "wp-config.php~:CRITICAL:Temp file left by text editor (nano/vim)"
    "wp-config.php.orig:CRITICAL:Original config (pre-migration)"
    "wp-config.php.save:CRITICAL:Editor auto-save of config"
    "wp-config.php.1:HIGH:Numbered backup of config"
    ".wp-config.php.swp:HIGH:Vim swap file containing config"
    "wp-config-sample.php:LOW:Sample config (no credentials, but confirms WP and discloses structure)"
    "../wp-config.php:HIGH:Config in parent directory (traversal test)"
    "wp-config.txt:CRITICAL:Config accidentally saved as .txt (served by web server)"
)

# Patterns that confirm credential exposure
CRED_PATTERNS=(
    "DB_PASSWORD"
    "DB_USER"
    "DB_HOST"
    "DB_NAME"
    "AUTH_KEY"
    "SECURE_AUTH_KEY"
    "LOGGED_IN_KEY"
    "NONCE_KEY"
    "SECRET_KEY"
    "table_prefix"
)

check_wp_config() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    local OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    local OUTPUT_FILE="$OUTPUT_DIR/wp_config_exposure.json"

    detect_wordpress "$target"

    if [[ "$WP_DETECTED" != "true" ]]; then
        {
            echo "{"
            echo "  \"step\": \"$STEP_NAME\","
            echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
            echo "  \"target\": \"$target\","
            echo "  \"checks\": ["
            echo "    {\"name\":\"WP Config Exposure\",\"status\":\"INFO\",\"found\":\"WordPress not detected\",\"expected\":\"N/A\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
            echo "  ]"
            echo "}"
        } > "$OUTPUT_FILE"
        print_status "INFO" "WP config: WordPress not detected — skipped"
        return
    fi

    local crit_findings=()
    local high_findings=()
    local low_findings=()

    for entry in "${CONFIG_PATHS[@]}"; do
        local path="${entry%%:*}"
        local rest="${entry#*:}"
        local sev="${rest%%:*}"
        local desc="${rest#*:}"

        # The parent-dir traversal path needs special handling
        local url
        if [[ "$path" == "../wp-config.php" ]]; then
            url="${base_url}/../wp-config.php"
        else
            url="${base_url}/${path}"
        fi

        local http_code
        http_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-6}" "$url" 2>/dev/null || echo "000")

        if [[ "$http_code" == "200" ]]; then
            local content
            content=$(curl -sS --max-time "${TIMEOUT:-6}" "$url" 2>/dev/null | head -c 16384 || echo "")
            local content_len=${#content}

            # Check for PHP source (not executed = PHP not configured for this extension/path)
            local cred_hits=()
            for pattern in "${CRED_PATTERNS[@]}"; do
                if echo "$content" | grep -q "$pattern"; then
                    cred_hits+=("$pattern")
                fi
            done

            # Check if it looks like executed PHP (blank or HTML page = PHP ran)
            if [[ ${#cred_hits[@]} -gt 0 ]]; then
                local ch_str; ch_str=$(IFS=", "; printf '%s' "${cred_hits[*]}")
                local db_pass=""
                # Try to extract the actual DB_PASSWORD value (redact partially)
                db_pass=$(echo "$content" | grep -i "DB_PASSWORD" | grep -oE "'[^']{3,}'" | head -1 | \
                    sed "s/'\(.\{3\}\).*'/'\1...REDACTED'/" || echo "")
                local finding="${sev}: /${path} accessible (${content_len}B) — credentials exposed: $ch_str"
                [[ -n "$db_pass" ]] && finding="${finding} (DB_PASSWORD: ${db_pass})"
                case "$sev" in
                    CRITICAL) crit_findings+=("$finding") ;;
                    HIGH)     high_findings+=("$finding") ;;
                    *)        low_findings+=("$finding") ;;
                esac
            elif [[ $content_len -lt 10 ]]; then
                : # Blank response — PHP likely executed it (no source code leaked)
            elif echo "$content" | grep -qi '<!DOCTYPE\|<html\|403 Forbidden\|Not Found'; then
                : # HTML error/redirect — false positive
            else
                # File accessible but PHP not parsed (e.g., .bak, .txt, .old)
                case "$sev" in
                    CRITICAL) crit_findings+=("${sev}: /${path} accessible (${content_len}B) — ${desc}") ;;
                    HIGH)     high_findings+=("${sev}: /${path} accessible (${content_len}B) — ${desc}") ;;
                    *)        low_findings+=("${sev}: /${path} accessible (${content_len}B) — ${desc}") ;;
                esac
            fi
        fi
    done

    # ── Check if wp-config.php leaks via PHP error ────────────────────────────
    # Some servers parse it but misconfigured error_reporting shows the path
    local homepage
    homepage=$(curl -sS --max-time "${TIMEOUT:-8}" "$base_url/" 2>/dev/null | head -c 20000 || echo "")
    if echo "$homepage" | grep -qi "wp-config.php"; then
        local config_context
        config_context=$(echo "$homepage" | grep -i "wp-config.php" | head -1 | sed 's/<[^>]*>//g' | \
            tr -d '\r\n' | sed 's/^ *//' | head -c 200 || echo "")
        [[ -n "$config_context" ]] && \
            high_findings+=("HIGH: wp-config.php path referenced in homepage HTML/errors: $config_context")
    fi

    local OUTPUT_FILE="$OUTPUT_DIR/wp_config_exposure.json"
    {
        echo "{"
        echo "  \"step\": \"$STEP_NAME\","
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"target\": \"$target\","
        echo "  \"checks\": ["
        local first=true

        if [[ ${#crit_findings[@]} -gt 0 ]]; then
            local cf_str; cf_str=$(IFS="; "; printf '%s' "${crit_findings[*]}")
            local cf_e; cf_e=$(json_escape "$cf_str")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"Config Credentials Exposed\",\"status\":\"FAIL\",\"found\":\"$cf_e\",\"expected\":\"wp-config.php not readable from web\",\"severity\":\"CRITICAL\",\"remediation_id\":\"SEC-WPCONF-001\"}"
        fi

        if [[ ${#high_findings[@]} -gt 0 ]]; then
            local hf_str; hf_str=$(IFS="; "; printf '%s' "${high_findings[*]}")
            local hf_e; hf_e=$(json_escape "$hf_str")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"Config File Accessible\",\"status\":\"FAIL\",\"found\":\"$hf_e\",\"expected\":\"Config files blocked\",\"severity\":\"HIGH\",\"remediation_id\":\"SEC-WPCONF-001\"}"
        fi

        if [[ ${#low_findings[@]} -gt 0 ]]; then
            local lf_str; lf_str=$(IFS="; "; printf '%s' "${low_findings[*]}")
            local lf_e; lf_e=$(json_escape "$lf_str")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"Sample/Info Config Accessible\",\"status\":\"INFO\",\"found\":\"$lf_e\",\"expected\":\"Remove unused config files\",\"severity\":\"LOW\",\"remediation_id\":\"\"}"
        fi

        if [[ ${#crit_findings[@]} -eq 0 && ${#high_findings[@]} -eq 0 && ${#low_findings[@]} -eq 0 ]]; then
            echo "    {\"name\":\"WP Config Exposure\",\"status\":\"PASS\",\"found\":\"No config files accessible at ${#CONFIG_PATHS[@]} probed paths\",\"expected\":\"Config files not readable from web\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
        fi

        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    if [[ ${#crit_findings[@]} -gt 0 ]]; then
        print_status "FAIL" "WP config: CRITICAL — config file with credentials exposed"
    elif [[ ${#high_findings[@]} -gt 0 ]]; then
        print_status "FAIL" "WP config: config file exposure found"
    elif [[ ${#low_findings[@]} -gt 0 ]]; then
        print_status "INFO" "WP config: sample files accessible"
    else
        print_status "PASS" "WP config: no config files accessible"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking WordPress config exposure: $TARGET"
    check_wp_config "$TARGET"
done
