#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

# Phase 5 - Webshell Path Detection
# Probes ~40 known webshell paths, checks HTTP status + response signatures,
# performs timing probe for execution evidence on suspicious endpoints.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step5_webshell_paths"

WEBSHELL_PATHS=(
    "/shell.php" "/cmd.php" "/c99.php" "/r57.php" "/wso.php" "/b374k.php"
    "/alfa.php" "/alfacgiapi/perl.alfa" "/x.php" "/1.php" "/2.php" "/test.php"
    "/up.php" "/upload.php" "/upfile.php" "/uploader.php"
    "/admin/shell.php" "/wp-content/uploads/shell.php"
    "/wp-content/uploads/cmd.php" "/wp-content/uploads/x.php"
    "/wp-content/uploads/alfa.php" "/wp-content/uploads/wso.php"
    "/wp-includes/css/shell.php" "/wp-includes/images/shell.php"
    "/wp-admin/shell.php" "/admin.php" "/webshell.php"
    "/images/shell.php" "/files/shell.php" "/uploads/shell.php"
    "/include/shell.php" "/includes/shell.php" "/tmp/shell.php"
    "/cgi-bin/shell.cgi" "/cgi-bin/cmd.cgi" "/cgi-bin/php.php"
    "/phpspy.php" "/spy.php" "/mini.php" "/priv8.php"
    "/wp-content/themes/twentyfifteen/shell.php"
    "/wp-content/plugins/akismet/shell.php"
    "/.shell.php" "/.cmd.php" "/. .php"
    "/timthumb.php" "/thumb.php" "/wp-content/themes/classic/timthumb.php"
    "/eval-stdin.php"
)

# Known webshell signatures in response body
SHELL_SIGNATURES=(
    "FilesMan" "WSO Shell" "c99shell" "r57shell" "b374k"
    "uname -a" "safe_mode" "disable_functions" "PHP Shell"
    "File Manager" "Command execution" "Execute command"
    "id;uname" "system()" "passthru(" "/etc/passwd"
)

check_webshells() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    local found_shells=()
    local timing_evidence=()

    for path in "${WEBSHELL_PATHS[@]}"; do
        local url="${base_url}${path}"
        local http_code
        http_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-8}" "$url" 2>/dev/null || echo "000")

        if [[ "$http_code" == "200" ]]; then
            # Fetch content and check for shell signatures
            local content
            content=$(curl -sS -L --max-time "${TIMEOUT:-8}" "$url" 2>/dev/null | head -c 4096 || echo "")

            local sig_hit=""
            for sig in "${SHELL_SIGNATURES[@]}"; do
                if echo "$content" | grep -qi "$sig"; then
                    sig_hit="$sig"
                    break
                fi
            done

            if [[ -n "$sig_hit" ]]; then
                found_shells+=("CONFIRMED: $path — signature '${sig_hit}' found in response")
            else
                # Timing probe: add ?cmd=sleep+3 and measure delta
                local t_start t_end t_delta
                t_start=$(date +%s%3N)
                curl -sS -o /dev/null --max-time 10 "${url}?cmd=sleep+3" 2>/dev/null || true
                t_end=$(date +%s%3N)
                t_delta=$(( t_end - t_start ))

                if [[ $t_delta -gt 2800 ]]; then
                    timing_evidence+=("TIMING: $path responded in ${t_delta}ms to ?cmd=sleep+3 — LIKELY EXECUTING CODE")
                    found_shells+=("TIMING EVIDENCE: $path (response: ${t_delta}ms to sleep probe)")
                else
                    found_shells+=("SUSPICIOUS: $path returns HTTP 200 (no shell signature confirmed, but accessible)")
                fi
            fi
        fi
    done

    # ── Special: eval-stdin.php (CVE-2012-1823) ───────────────────────────────
    local eval_url="${base_url}/eval-stdin.php"
    local eval_code
    eval_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-5}" \
        -X POST -d "<?php echo 'PHPTEST123'; ?>" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        "$eval_url" 2>/dev/null || echo "000")
    local eval_body
    eval_body=$(curl -sS -L --max-time "${TIMEOUT:-5}" \
        -X POST -d "<?php echo 'PHPTEST123'; ?>" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        "$eval_url" 2>/dev/null || echo "")
    if echo "$eval_body" | grep -q "PHPTEST123"; then
        found_shells+=("CRITICAL RCE: /eval-stdin.php executes PHP from POST body (CVE-2012-1823)")
    fi

    # ── Shellshock probe ──────────────────────────────────────────────────────
    local ss_response
    ss_response=$(curl -sS -L --max-time "${TIMEOUT:-5}" \
        -H "User-Agent: () { :; }; echo Content-Type: text/plain; echo; echo SHELLSHOCKED" \
        -H "Referer: () { :; }; echo Content-Type: text/plain; echo; echo SHELLSHOCKED" \
        "${base_url}/cgi-bin/test.cgi" 2>/dev/null || echo "")
    if echo "$ss_response" | grep -q "SHELLSHOCKED"; then
        found_shells+=("CRITICAL: Shellshock (CVE-2014-6271) — /cgi-bin/test.cgi executed injected header")
    fi

    local OUTPUT_DIR="$OUT/step5"
    mkdir -p "$OUTPUT_DIR"
    local OUTPUT_FILE="$OUTPUT_DIR/webshell_paths.json"

    if [[ ${#found_shells[@]} -eq 0 ]]; then
        {
            echo "{"
            echo "  \"step\": \"$STEP_NAME\","
            echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
            echo "  \"target\": \"$target\","
            echo "  \"checks\": ["
            echo "    {\"name\":\"Webshell Path Probe\",\"status\":\"PASS\",\"found\":\"No webshells found at ${#WEBSHELL_PATHS[@]} probed paths\",\"expected\":\"No accessible shell paths\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
            echo "  ]"
            echo "}"
        } > "$OUTPUT_FILE"
        print_status "PASS" "Webshell scan: no shells found"
        return
    fi

    # Determine severity: any CONFIRMED/TIMING/RCE = CRITICAL, SUSPICIOUS = HIGH
    local severity="HIGH"
    for s in "${found_shells[@]}"; do
        echo "$s" | grep -qiE 'CONFIRMED|TIMING|CRITICAL|RCE' && severity="CRITICAL" && break
    done

    local shells_str; shells_str=$(IFS="; "; printf '%s' "${found_shells[*]}")
    local shells_e; shells_e=$(json_escape "$shells_str")

    {
        echo "{"
        echo "  \"step\": \"$STEP_NAME\","
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"target\": \"$target\","
        echo "  \"checks\": ["
        echo "    {\"name\":\"Webshell Path Probe\",\"status\":\"FAIL\",\"found\":\"$shells_e\",\"expected\":\"No accessible shell paths\",\"severity\":\"$severity\",\"remediation_id\":\"SEC-SHELL-001\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "FAIL" "Webshell scan: ${#found_shells[@]} findings — $severity"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Probing webshell paths: $TARGET"
    check_webshells "$TARGET"
done
