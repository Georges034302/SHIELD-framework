#!/usr/bin/env bash
# Phase 5 - WordPress Debug Mode Exposure
# Checks if WP_DEBUG is active via visible PHP errors on page,
# exposed debug.log, and error log accessibility.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"
source "$SCRIPT_DIR/lib/wp_detect.sh"

STEP_NAME="step4_wp_debug"

check_wp_debug() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    local OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    local OUTPUT_FILE="$OUTPUT_DIR/wp_debug.json"

    detect_wordpress "$target"

    if [[ "$WP_DETECTED" != "true" ]]; then
        {
            echo "{"
            echo "  \"step\": \"$STEP_NAME\","
            echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
            echo "  \"target\": \"$target\","
            echo "  \"checks\": ["
            echo "    {\"name\":\"WP Debug Check\",\"status\":\"INFO\",\"found\":\"WordPress not detected\",\"expected\":\"N/A\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
            echo "  ]"
            echo "}"
        } > "$OUTPUT_FILE"
        print_status "INFO" "WP debug: WordPress not detected — skipped"
        return
    fi

    local checks=()

    # ── 1. PHP errors visible on homepage ────────────────────────────────────
    local homepage_html
    homepage_html=$(curl -sS -L --max-time "${TIMEOUT:-10}" "$base_url/" 2>/dev/null | head -c 50000 || echo "")

    local error_hits=()
    echo "$homepage_html" | grep -qiE '<b>Warning</b>:|<b>Notice</b>:|<b>Fatal error</b>:|<b>Parse error</b>:' && \
        error_hits+=("HTML-rendered PHP error messages on homepage (WP_DEBUG_DISPLAY=true)")
    echo "$homepage_html" | grep -qiE 'Stack trace:|on line [0-9]+|in /.*\.php on line' && \
        error_hits+=("Stack trace or file path visible in page source")
    echo "$homepage_html" | grep -qiE 'class="wp-die-message"' && \
        error_hits+=("wp-die-message visible — verbose WP error output enabled")
    echo "$homepage_html" | grep -qiE 'PHP [0-9]+\.[0-9]+ (/[a-zA-Z0-9/_.-]+\.php):' && \
        error_hits+=("PHP error with absolute file path disclosed")

    if [[ ${#error_hits[@]} -gt 0 ]]; then
        local err_str; err_str=$(IFS="; "; printf '%s' "${error_hits[*]}")
        checks+=("FAIL|WP_DEBUG active — PHP errors visible on page: $err_str|WP_DEBUG=false; WP_DEBUG_DISPLAY=false|HIGH|SEC-WPDEBUG-001")
    else
        checks+=("PASS|No PHP errors or debug output visible on page|N/A|INFO|")
    fi

    # ── 2. debug.log file accessible ─────────────────────────────────────────
    local debug_url="${base_url}/wp-content/debug.log"
    local debug_code
    debug_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-8}" "$debug_url" 2>/dev/null || echo "000")

    if [[ "$debug_code" == "200" ]]; then
        local debug_content
        debug_content=$(curl -sS --max-time "${TIMEOUT:-8}" "$debug_url" 2>/dev/null | head -c 8192 || echo "")
        local dlog_len=${#debug_content}

        # Check for sensitive data in log
        local log_hits=()
        echo "$debug_content" | grep -qiE 'password|passwd|secret|credential|DB_PASSWORD|AUTH_KEY' && \
            log_hits+=("Credential/secret pattern found in log content")
        echo "$debug_content" | grep -qiE '/home/[a-zA-Z0-9_-]+/|/var/www/|/srv/www/' && \
            log_hits+=("Absolute file system paths disclosed in log")
        echo "$debug_content" | grep -qiE 'SQL query was|WordPress database error|MySQL error' && \
            log_hits+=("Database error/SQL queries in log")

        if [[ ${#log_hits[@]} -gt 0 ]]; then
            local lh_str; lh_str=$(IFS="; "; printf '%s' "${log_hits[*]}")
            checks+=("FAIL|debug.log accessible (${dlog_len}B) with sensitive content: $lh_str|Block web access to debug.log; set WP_DEBUG_LOG=false|CRITICAL|SEC-WPDEBUG-002")
        else
            checks+=("FAIL|debug.log accessible (${dlog_len}B) — file paths and error output exposed|Block web access to debug.log; set WP_DEBUG_LOG=false|HIGH|SEC-WPDEBUG-002")
        fi
    elif [[ "$debug_code" == "403" ]]; then
        checks+=("WARN|debug.log exists but returns 403 — file may still be present on disk; confirm deletion|Delete or move debug.log outside web root|LOW|")
    else
        checks+=("PASS|debug.log not accessible (HTTP $debug_code)|N/A|INFO|")
    fi

    # ── 3. Check WP error log in alternate locations ──────────────────────────
    for log_path in "/error_log" "/wp-content/error_log" "/.error_log"; do
        local log_code
        log_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-5}" \
            "${base_url}${log_path}" 2>/dev/null || echo "000")
        if [[ "$log_code" == "200" ]]; then
            local log_size
            log_size=$(curl -sS --max-time "${TIMEOUT:-5}" "${base_url}${log_path}" 2>/dev/null | wc -c | tr -d ' ' || echo "0")
            checks+=("FAIL|Error log at ${log_path} accessible (${log_size}B) — discloses server errors and paths|Block web access to error log files|MEDIUM|SEC-WPDEBUG-002")
        fi
    done

    # ── 4. Query Monitor plugin active ────────────────────────────────────────
    local qm_code
    qm_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-5}" \
        "${base_url}/wp-content/plugins/query-monitor/query-monitor.php" 2>/dev/null || echo "000")
    if [[ "$qm_code" == "200" ]]; then
        checks+=("WARN|Query Monitor plugin appears active — may expose DB queries and performance data to unauthenticated users|Disable or restrict Query Monitor on production|MEDIUM|SEC-WPDEBUG-001")
    fi

    {
        echo "{"
        echo "  \"step\": \"$STEP_NAME\","
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"target\": \"$target\","
        echo "  \"checks\": ["
        local check_names=("PHP Errors on Page" "debug.log Exposure" "Error Log Exposure" "Query Monitor Plugin")
        local first=true
        local i=0
        for check in "${checks[@]}"; do
            IFS='|' read -r st fd ex sv rm <<< "$check"
            local st_e fd_e ex_e sv_e rm_e name_e
            st_e=$(json_escape "$st"); fd_e=$(json_escape "$fd")
            ex_e=$(json_escape "$ex"); sv_e=$(json_escape "$sv"); rm_e=$(json_escape "$rm")
            name_e=$(json_escape "${check_names[$i]:-WP Debug Check}")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"$name_e\",\"status\":\"$st_e\",\"found\":\"$fd_e\",\"expected\":\"$ex_e\",\"severity\":\"$sv_e\",\"remediation_id\":\"$rm_e\"}"
            (( i++ )) || true
        done
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    local has_crit=false has_fail=false has_warn=false
    for c in "${checks[@]}"; do
        [[ "$c" =~ CRITICAL ]] && has_crit=true
        [[ "$c" == FAIL* ]] && has_fail=true
        [[ "$c" == WARN* ]] && has_warn=true
    done
    $has_crit && print_status "FAIL" "WP debug: CRITICAL — debug.log with credentials exposed" && return
    $has_fail && print_status "FAIL" "WP debug: debug output exposed" && return
    $has_warn && print_status "WARN" "WP debug: warnings found" && return
    print_status "PASS" "WP debug check complete"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking WordPress debug exposure: $TARGET"
    check_wp_debug "$TARGET"
done
