#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step5_php_info"

check_php_info() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    local phpinfo_paths=(
        "/phpinfo.php" "/info.php" "/php_info.php" "/phpinfo/" "/test.php"
        "/php.php" "/pi.php" "/_info.php" "/server-info" "/server-status"
        "/admin/phpinfo.php" "/wp-admin/phpinfo.php" "/debug.php" "/status.php"
    )

    local found_pages=()
    local severity="INFO"

    for path in "${phpinfo_paths[@]}"; do
        local url="${base_url}${path}"
        local http_code
        http_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-10}" "$url" 2>/dev/null || echo "000")

        if [[ "$http_code" == "200" ]]; then
            local content
            content=$(curl -sS -L --max-time "${TIMEOUT:-10}" "$url" 2>/dev/null | head -c 2048 || echo "")

            # Confirm it's actually phpinfo() output
            if echo "$content" | grep -qi "PHP Version\|phpinfo()\|PHP Configuration\|php_flag\|disable_functions\|open_basedir"; then
                found_pages+=("$path: phpinfo() page exposed")
                severity="CRITICAL"
            # Apache server-status
            elif echo "$content" | grep -qi "Apache Server Status\|Server uptime\|requests currently being processed"; then
                found_pages+=("$path: Apache server-status exposed (leaks internal IPs, request details)")
                severity="HIGH"
            fi
        fi
    done

    if [[ ${#found_pages[@]} -eq 0 ]]; then
        echo "PASS|No phpinfo() or server-status pages found at common paths|Debug pages removed from production|INFO|"
        return
    fi

    local pages_str
    pages_str=$(IFS="; "; printf '%s' "${found_pages[*]}")

    echo "FAIL|$pages_str|Remove phpinfo() files; disable apache server-status in production; set expose_php=Off|CRITICAL|SEC-PHPINFO-001"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking for phpinfo() / debug pages for $TARGET"

    OUTPUT_DIR="$OUT/step5"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/php_info.json"

    result=$(check_php_info "$TARGET")
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
        echo "    {\"name\":\"phpinfo() / Debug Pages\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "phpinfo check complete"
done
