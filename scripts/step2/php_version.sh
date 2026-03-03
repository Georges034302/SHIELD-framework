#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step2_php_version"

check_php_version() {
    local target="$1"

    local response
    response=$(curl -sS -I --max-time "${TIMEOUT:-10}" "$target" 2>/dev/null || echo "")

    local powered_by
    powered_by=$(echo "$response" | grep -i "^X-Powered-By:" | head -1 | sed 's/^[Xx]-[Pp]owered-[Bb]y: //;s/\r//')

    if [[ -z "$powered_by" ]]; then
        echo "PASS|X-Powered-By header not present|PHP version hidden|INFO|"
        return
    fi

    if echo "$powered_by" | grep -qi "PHP"; then
        local php_version
        php_version=$(echo "$powered_by" | grep -oE "[0-9]+\.[0-9]+(\.[0-9]+)?" | head -1)

        if [[ -n "$php_version" ]]; then
            local major
            major=$(echo "$php_version" | cut -d'.' -f1)
            local minor
            minor=$(echo "$php_version" | cut -d'.' -f2)

            # PHP EOL versions: 5.x, 7.0, 7.1, 7.2, 7.3, 7.4, 8.0, 8.1
            if [[ "$major" -le 5 ]]; then
                echo "FAIL|EOL PHP version exposed: $powered_by (PHP 5.x reached end-of-life Dec 2018)|Upgrade to PHP 8.2+ and remove X-Powered-By|CRITICAL|SEC-PHP-001"
                return
            elif [[ "$major" -eq 7 ]]; then
                echo "FAIL|EOL PHP version exposed: $powered_by (PHP 7.x reached end-of-life Dec 2022)|Upgrade to PHP 8.2+ and remove X-Powered-By|CRITICAL|SEC-PHP-001"
                return
            elif [[ "$major" -eq 8 && "$minor" -le 1 ]]; then
                echo "WARN|End-of-life PHP version exposed: $powered_by (PHP 8.1 EOL Nov 2024)|Upgrade to PHP 8.2+ and remove X-Powered-By|HIGH|SEC-PHP-001"
                return
            else
                echo "WARN|PHP version exposed in X-Powered-By: $powered_by|Remove X-Powered-By header (expose_php=Off in php.ini)|MEDIUM|SEC-PHP-002"
                return
            fi
        fi
        echo "WARN|PHP detected in X-Powered-By (version hidden): $powered_by|Remove X-Powered-By header entirely|LOW|SEC-PHP-002"
        return
    fi

    echo "WARN|X-Powered-By header exposes technology stack: $powered_by|Remove X-Powered-By header|LOW|SEC-PHP-002"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking PHP version disclosure for $TARGET"

    OUTPUT_DIR="$OUT/step2"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/php_version.json"

    result=$(check_php_version "$TARGET")
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
        echo "    {\"name\":\"PHP Version Disclosure\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "PHP version check complete"
done
