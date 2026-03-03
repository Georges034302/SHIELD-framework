#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step4_path_traversal"

check_path_traversal() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    # Traversal payloads targeting common sensitive files
    local payloads=(
        "/../../../etc/passwd"
        "/..%2F..%2F..%2Fetc%2Fpasswd"
        "/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        "/../../../windows/win.ini"
        "/..%5c..%5c..%5cwindows%5cwin.ini"
    )

    # Common vulnerable parameters and endpoints
    local endpoints=(
        "/?file="
        "/?page="
        "/?path="
        "/?include="
        "/?doc="
        "/?template="
        "/download?file="
        "/view?path="
    )

    local issues=()
    local severity="INFO"

    # Test direct path traversal on URL
    for payload in "${payloads[@]}"; do
        local url="${base_url}${payload}"
        local response
        response=$(curl -sS -L --max-time "${TIMEOUT:-10}" "$url" 2>/dev/null || echo "")

        if echo "$response" | grep -qE "^root:|nobody:|daemon:" 2>/dev/null; then
            issues+=("Path traversal allows /etc/passwd read: $payload")
            severity="CRITICAL"
        fi
        if echo "$response" | grep -qi "\[extensions\]\|for 16-bit app"; then
            issues+=("Path traversal allows windows/win.ini read: $payload")
            severity="CRITICAL"
        fi
    done

    # Test parameter-based LFI
    for endpoint in "${endpoints[@]}"; do
        for payload in "../../etc/passwd" "../../../etc/passwd" "..%2F..%2Fetc%2Fpasswd"; do
            local url="${base_url}${endpoint}${payload}"
            local response
            response=$(curl -sS -L --max-time "${TIMEOUT:-10}" "$url" 2>/dev/null || echo "")

            if echo "$response" | grep -qE "^root:|nobody:|daemon:"; then
                issues+=("LFI via ${endpoint}parameter: $payload succeeds")
                severity="CRITICAL"
                break 2
            fi
        done
    done

    if [[ ${#issues[@]} -eq 0 ]]; then
        echo "PASS|No path traversal or LFI vulnerabilities detected|Path traversal mitigated|INFO|"
        return
    fi

    local issues_str
    issues_str=$(IFS="; "; printf '%s' "${issues[*]}")
    echo "FAIL|$issues_str|Sanitize file path inputs; use basename(); disable allow_url_include; chroot web root|CRITICAL|SEC-TRAVERSAL-001"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking path traversal vulnerabilities for $TARGET"

    OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/path_traversal.json"

    result=$(check_path_traversal "$TARGET")
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
        echo "    {\"name\":\"Path Traversal / LFI\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "Path traversal check complete"
done
