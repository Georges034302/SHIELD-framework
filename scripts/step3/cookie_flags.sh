#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"
source "$SCRIPT_DIR/lib/http.sh"

STEP_NAME="step3_cookie_flags"

# Check cookie security attributes
check_cookie_flags() {
    local target="$1"
    local headers=$(fetch_headers "$target")
    
    # Extract all Set-Cookie headers
    local cookies=$(echo "$headers" | grep -i "^Set-Cookie:" || true)
    
    if [[ -z "$cookies" ]]; then
        echo "INFO|No cookies set by server|N/A|INFO|"
        return
    fi
    
    local cookie_count=$(echo "$cookies" | wc -l)
    local issues=()
    
    # Check each cookie
    while IFS= read -r cookie_line; do
        local cookie_value=$(echo "$cookie_line" | sed 's/^Set-Cookie: *//' | tr -d '\r')
        local cookie_name=$(echo "$cookie_value" | cut -d'=' -f1)
        
        # Check for Secure flag
        if ! echo "$cookie_value" | grep -qi ";\s*Secure" || true; then
            issues+=("$cookie_name: missing Secure flag")
        fi
        
        # Check for HttpOnly flag
        if ! echo "$cookie_value" | grep -qi ";\s*HttpOnly" || true; then
            issues+=("$cookie_name: missing HttpOnly flag")
        fi
        
        # Check for SameSite flag
        if ! echo "$cookie_value" | grep -qiE ";\s*SameSite=(Strict|Lax|None)" || true; then
            issues+=("$cookie_name: missing SameSite attribute")
        elif echo "$cookie_value" | grep -qi ";\s*SameSite=None" || true; then
            # SameSite=None requires Secure
            if ! echo "$cookie_value" | grep -qi ";\s*Secure" || true; then
                issues+=("$cookie_name: SameSite=None without Secure")
            fi
        fi
        
    done <<< "$cookies"
    
    if [[ ${#issues[@]} -eq 0 ]]; then
        echo "PASS|All $cookie_count cookie(s) properly secured|Secure, HttpOnly, SameSite flags|INFO|"
    elif [[ ${#issues[@]} -le 2 ]]; then
        local issues_str=$(IFS="; "; echo "${issues[*]}")
        echo "WARN|$issues_str|Secure, HttpOnly, SameSite flags|LOW|SEC-COOKIE-001"
    else
        echo "WARN|${#issues[@]} cookie security issues found|Secure, HttpOnly, SameSite flags|MEDIUM|SEC-COOKIE-002"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking cookie security flags for $TARGET"
    
    OUTPUT_DIR="$OUT/step3"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/cookie_flags.json"
    
    # Run check
    result=$(check_cookie_flags "$TARGET")
    
    # Parse result
    IFS='|' read -r status found expected severity remediation_id <<< "$result"
    
    # Escape for JSON
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
        echo "    {\"name\":\"Cookie Security Attributes\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "Cookie flags check complete"
done
