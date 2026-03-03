#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step4_http_methods"

check_http_methods() {
    local target="$1"

    # Send OPTIONS request to discover allowed methods
    local options_response
    options_response=$(curl -sS -I -X OPTIONS --max-time "${TIMEOUT:-10}" "$target" 2>/dev/null || echo "")

    local allow_header
    allow_header=$(echo "$options_response" | grep -i "^Allow:" | head -1 | sed 's/^[Aa]llow: //;s/\r//')

    local issues=()
    local severity="INFO"

    # Check for dangerous methods in Allow header
    local dangerous_methods=("PUT" "DELETE" "TRACE" "CONNECT" "PATCH" "PROPFIND" "PROPPATCH" "MKCOL" "COPY" "MOVE" "LOCK" "UNLOCK")

    for method in "${dangerous_methods[@]}"; do
        if echo "$allow_header" | grep -qi "\b$method\b"; then
            case "$method" in
                TRACE)
                    issues+=("TRACE enabled (Cross-Site Tracing / XST attack vector)")
                    severity="HIGH"
                    ;;
                PUT)
                    # Verify PUT actually works by probing
                    local put_response
                    put_response=$(curl -sS -X PUT \
                        --max-time "${TIMEOUT:-10}" \
                        -d "shield-test" \
                        -o /dev/null -w "%{http_code}" \
                        "${target}/shield-put-test-$(date +%s).txt" 2>/dev/null || echo "000")
                    if [[ "$put_response" == "201" ]] || [[ "$put_response" == "200" ]]; then
                        issues+=("PUT method active and accepted file upload (HTTP $put_response) — arbitrary file write possible")
                        severity="CRITICAL"
                    else
                        issues+=("PUT listed in Allow header (HTTP $put_response on probe)")
                        [[ "$severity" == "INFO" ]] && severity="MEDIUM"
                    fi
                    ;;
                DELETE)
                    issues+=("DELETE method enabled (resource deletion risk)")
                    [[ "$severity" == "INFO" ]] && severity="MEDIUM"
                    ;;
                PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK)
                    issues+=("WebDAV method enabled: $method")
                    [[ "$severity" == "INFO" ]] && severity="MEDIUM"
                    ;;
                *)
                    issues+=("Potentially dangerous method enabled: $method")
                    [[ "$severity" == "INFO" ]] && severity="LOW"
                    ;;
            esac
        fi
    done

    # Direct TRACE test regardless of Allow header
    local trace_response
    trace_response=$(curl -sS -X TRACE --max-time "${TIMEOUT:-10}" "$target" 2>/dev/null || echo "")
    if echo "$trace_response" | grep -qi "TRACE / HTTP\|Content-Type: message/http"; then
        if ! echo "${issues[*]}" | grep -qi "TRACE"; then
            issues+=("TRACE method responds with request reflection (XST vulnerability confirmed)")
            severity="HIGH"
        fi
    fi

    if [[ ${#issues[@]} -eq 0 ]]; then
        local methods="${allow_header:-not disclosed}"
        echo "PASS|Dangerous HTTP methods not detected (Allow: $methods)|Only GET/POST/HEAD/OPTIONS permitted|INFO|"
        return
    fi

    local issues_str
    issues_str=$(IFS="; "; printf '%s' "${issues[*]}")

    if [[ "$severity" == "CRITICAL" ]]; then
        echo "FAIL|$issues_str|Disable PUT/DELETE/TRACE in server config; restrict to GET/POST/HEAD only|CRITICAL|SEC-METHODS-002"
    else
        echo "FAIL|$issues_str|Disable unnecessary HTTP methods; restrict to GET/POST/HEAD only|$severity|SEC-METHODS-001"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking HTTP methods for $TARGET"

    OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/http_methods.json"

    result=$(check_http_methods "$TARGET")
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
        echo "    {\"name\":\"HTTP Methods\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "HTTP methods check complete"
done
