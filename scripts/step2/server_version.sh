#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step2_server_version"

check_server_version() {
    local target="$1"

    local response
    response=$(curl -sS -I --max-time "${TIMEOUT:-10}" "$target" 2>/dev/null || echo "")

    local server_header
    server_header=$(echo "$response" | grep -i "^Server:" | head -1 | sed 's/^[Ss]erver: //;s/\r//')

    local issues=()
    local severity="INFO"

    if [[ -z "$server_header" ]]; then
        echo "PASS|Server header not present (version hidden)|Server header suppressed|INFO|"
        return
    fi

    # Check if version number is exposed
    if echo "$server_header" | grep -qE "[0-9]+\.[0-9]+"; then
        local version
        version=$(echo "$server_header" | grep -oE "[0-9]+\.[0-9]+(\.[0-9]+)?")

        # Check for known EOL Apache versions
        if echo "$server_header" | grep -qi "Apache"; then
            local major_minor
            major_minor=$(echo "$version" | head -1 | cut -d'.' -f1,2)
            if [[ "$major_minor" == "2.2" ]] || [[ "$major_minor" == "2.0" ]] || [[ "$major_minor" == "1."* ]]; then
                echo "FAIL|End-of-life Apache version exposed: $server_header|Upgrade Apache + suppress version with ServerTokens Prod|CRITICAL|SEC-SRVVER-001"
                return
            fi
        fi

        # Check for known EOL Nginx versions
        if echo "$server_header" | grep -qi "nginx"; then
            local major_minor
            major_minor=$(echo "$version" | head -1 | cut -d'.' -f1,2)
            if echo "$major_minor" | grep -qE "^1\.(0|2|4|6|8|10|12|14|16)\." 2>/dev/null || [[ "$major_minor" == "0."* ]]; then
                echo "FAIL|End-of-life Nginx version exposed: $server_header|Upgrade Nginx + suppress version with server_tokens off|CRITICAL|SEC-SRVVER-001"
                return
            fi
        fi

        echo "WARN|Server version exposed: $server_header|Suppress version info (ServerTokens Prod / server_tokens off)|MEDIUM|SEC-SRVVER-001"
        return
    fi

    # Product name exposed but no version
    echo "WARN|Server product name exposed: $server_header|Remove or suppress Server header entirely|LOW|SEC-SRVVER-002"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking server version disclosure for $TARGET"

    OUTPUT_DIR="$OUT/step2"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/server_version.json"

    result=$(check_server_version "$TARGET")
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
        echo "    {\"name\":\"Server Version Disclosure\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "Server version check complete"
done
