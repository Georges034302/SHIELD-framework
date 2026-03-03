#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step5_owasp_defensive"

json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/}"
    echo -n "$str"
}

check_owasp_defensive() {
    local target="$1"
    local base_url="${target%/}"
    
    local missing_controls=()
    local present_controls=()
    local warnings=()
    local total_checks=0
    
    # Fetch main page headers and content
    local response
    response=$(curl -sS -I --max-time "${TIMEOUT:-10}" "$target" 2>/dev/null || echo "")
    local page_content
    page_content=$(curl -sS -L --max-time "${TIMEOUT:-10}" "$target" 2>/dev/null || echo "")
    
    # 1. Content Security Policy (CSP)
    total_checks=$((total_checks + 1))
    if echo "$response" | grep -qi "^Content-Security-Policy:"; then
        present_controls+=("CSP")
        # Check for unsafe-inline or unsafe-eval
        local csp_value
        csp_value=$(echo "$response" | grep -i "^Content-Security-Policy:" | cut -d: -f2-)
        if echo "$csp_value" | grep -qi "unsafe-inline\|unsafe-eval"; then
            warnings+=("CSP contains unsafe-inline or unsafe-eval")
        fi
    else
        missing_controls+=("Content-Security-Policy header")
    fi
    
    # 2. X-Frame-Options or frame-ancestors in CSP
    total_checks=$((total_checks + 1))
    if echo "$response" | grep -qi "^X-Frame-Options:\|frame-ancestors"; then
        present_controls+=("Clickjacking protection")
    else
        missing_controls+=("X-Frame-Options header (clickjacking protection)")
    fi
    
    # 3. X-Content-Type-Options
    total_checks=$((total_checks + 1))
    if echo "$response" | grep -qi "^X-Content-Type-Options:.*nosniff"; then
        present_controls+=("X-Content-Type-Options: nosniff")
    else
        missing_controls+=("X-Content-Type-Options: nosniff")
    fi
    
    # 4. Strict-Transport-Security (HSTS)
    total_checks=$((total_checks + 1))
    if [[ "$target" =~ ^https:// ]]; then
        if echo "$response" | grep -qi "^Strict-Transport-Security:"; then
            present_controls+=("HSTS")
            # Check for sufficient max-age
            local hsts_value
            hsts_value=$(echo "$response" | grep -i "^Strict-Transport-Security:" | cut -d: -f2-)
            if echo "$hsts_value" | grep -oE "max-age=([0-9]+)" | grep -E "[0-9]+" | awk -F= '{if($2 < 31536000) exit 1}'; then
                warnings+=("HSTS max-age less than 1 year (31536000 seconds)")
            fi
        else
            missing_controls+=("Strict-Transport-Security (HSTS)")
        fi
    fi
    
    # 5. X-XSS-Protection (legacy but still relevant)
    total_checks=$((total_checks + 1))
    if echo "$response" | grep -qi "^X-XSS-Protection:"; then
        local xss_value
        xss_value=$(echo "$response" | grep -i "^X-XSS-Protection:" | cut -d: -f2- | tr -d ' ')
        if [[ "$xss_value" =~ 1 ]]; then
            present_controls+=("X-XSS-Protection")
        fi
    fi
    
    # 6. Referrer-Policy
    total_checks=$((total_checks + 1))
    if echo "$response" | grep -qi "^Referrer-Policy:"; then
        present_controls+=("Referrer-Policy")
    else
        missing_controls+=("Referrer-Policy header")
    fi
    
    # 7. Permissions-Policy (formerly Feature-Policy)
    total_checks=$((total_checks + 1))
    if echo "$response" | grep -qi "^Permissions-Policy:\|^Feature-Policy:"; then
        present_controls+=("Permissions-Policy")
    fi
    
    # 8. Check for information disclosure in headers
    total_checks=$((total_checks + 1))
    if echo "$response" | grep -qi "^Server:.*Apache/[0-9]\|^Server:.*nginx/[0-9]\|^X-Powered-By:"; then
        warnings+=("Server version information disclosed in headers")
    else
        present_controls+=("Server version hidden")
    fi
    
    # 9. CORS configuration check
    total_checks=$((total_checks + 1))
    if echo "$response" | grep -qi "^Access-Control-Allow-Origin:.*\*"; then
        warnings+=("Overly permissive CORS: Access-Control-Allow-Origin: *")
    elif echo "$response" | grep -qi "^Access-Control-Allow-Origin:"; then
        present_controls+=("CORS configured (verify policy)")
    fi
    
    # 10. Cookie security attributes check
    total_checks=$((total_checks + 1))
    local set_cookies
    set_cookies=$(echo "$response" | grep -i "^Set-Cookie:" || echo "")
    if [[ -n "$set_cookies" ]]; then
        local insecure_cookies=false
        while IFS= read -r cookie_line; do
            [[ -z "$cookie_line" ]] && continue
            if ! echo "$cookie_line" | grep -qi "HttpOnly"; then
                insecure_cookies=true
                warnings+=("Cookie missing HttpOnly flag")
                break
            fi
            if [[ "$target" =~ ^https:// ]] && ! echo "$cookie_line" | grep -qi "Secure"; then
                insecure_cookies=true
                warnings+=("Cookie missing Secure flag on HTTPS site")
                break
            fi
            if ! echo "$cookie_line" | grep -qi "SameSite"; then
                warnings+=("Cookie missing SameSite attribute")
                break
            fi
        done <<< "$set_cookies"
        
        if [[ "$insecure_cookies" == false ]]; then
            present_controls+=("Secure cookie attributes")
        fi
    fi
    
    # 11. Subresource Integrity (SRI) check for external scripts
    total_checks=$((total_checks + 1))
    local external_scripts
    external_scripts=$(echo "$page_content" | grep -oE '<script[^>]+src="http' || echo "")
    if [[ -n "$external_scripts" ]]; then
        if echo "$external_scripts" | grep -q "integrity="; then
            present_controls+=("Subresource Integrity (SRI) on external scripts")
        else
            missing_controls+=("Subresource Integrity (SRI) on external scripts")
        fi
    fi
    
    # Calculate score
    local controls_present=${#present_controls[@]}
    local controls_missing=${#missing_controls[@]}
    local warning_count=${#warnings[@]}
    
    # Determine status and severity
    local status="PASS"
    local severity="INFO"
    local remediation_id=""
    
    if [[ $controls_missing -ge 5 ]]; then
        status="FAIL"
        severity="HIGH"
        remediation_id="SEC-OWASP-003"
    elif [[ $controls_missing -ge 3 ]]; then
        status="FAIL"
        severity="MEDIUM"
        remediation_id="SEC-OWASP-002"
    elif [[ $controls_missing -ge 1 ]] || [[ $warning_count -ge 2 ]]; then
        status="WARN"
        severity="MEDIUM"
        remediation_id="SEC-OWASP-001"
    fi
    
    # Build message
    local message=""
    if [[ $controls_present -gt 0 ]]; then
        message="$controls_present of $total_checks OWASP controls present"
    fi
    
    if [[ $controls_missing -gt 0 ]]; then
        local missing_str=$(IFS=", "; echo "${missing_controls[*]}")
        if [[ -n "$message" ]]; then
            message="$message; Missing: $missing_str"
        else
            message="Missing controls: $missing_str"
        fi
    fi
    
    if [[ $warning_count -gt 0 ]]; then
        local warnings_str=$(IFS="; "; echo "${warnings[*]}")
        if [[ -n "$message" ]]; then
            message="$message; Warnings: $warnings_str"
        else
            message="Warnings: $warnings_str"
        fi
    fi
    
    if [[ -z "$message" ]]; then
        message="Checked $total_checks OWASP defensive controls"
    fi
    
    echo "$status|$message|All OWASP defensive headers and controls properly configured|$severity|$remediation_id"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking OWASP defensive controls for $TARGET"
    
    OUTPUT_DIR="$OUT/step5"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/owasp_defensive.json"
    
    result=$(check_owasp_defensive "$TARGET")
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
        echo "    {\"name\":\"OWASP Defensive Controls\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "OWASP defensive controls check complete"
done
