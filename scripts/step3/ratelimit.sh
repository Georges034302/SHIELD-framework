#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step3_ratelimit"

json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/}"
    echo -n "$str"
}

check_rate_limit() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    # Find login endpoint
    local login_paths=("/wp-login.php" "/login" "/admin/login" "/user/login" "/signin" "/account/login" "/auth/login")
    local login_url=""

    for path in "${login_paths[@]}"; do
        local url="${base_url}${path}"
        local status_code
        status_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-10}" "$url" 2>/dev/null || echo "000")
        if [[ "$status_code" == "200" ]] || [[ "$status_code" == "302" ]]; then
            login_url="$url"
            break
        fi
    done

    if [[ -z "$login_url" ]]; then
        echo "INFO|No common login endpoint found at standard paths|N/A|INFO|"
        return
    fi

    # Send 5 rapid login requests
    local request_count=5
    local start_time=$(date +%s)
    local responses=()
    local status_codes=()

    for i in $(seq 1 $request_count); do
        local response
        response=$(curl -sS -X POST \
            --max-time "${TIMEOUT:-10}" \
            -d "log=shield_ratelimit_test&pwd=test_password_$(date +%s%N)&wp-submit=Log+In" \
            -w "\nHTTP_CODE:%{http_code}" \
            -c /dev/null -b /dev/null \
            "$login_url" 2>/dev/null || echo "")
        
        local http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
        local body=$(echo "$response" | grep -v "HTTP_CODE:")
        
        responses+=("$body")
        status_codes+=("$http_code")
    done

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # Analyze responses for rate limiting indicators
    local rate_limited=false
    local rate_limit_count=0

    for i in "${!status_codes[@]}"; do
        local code="${status_codes[$i]}"
        local body="${responses[$i]}"
        
        # Check for HTTP 429 (Too Many Requests) or 403
        if [[ "$code" == "429" ]] || [[ "$code" == "403" ]]; then
            rate_limited=true
            rate_limit_count=$((rate_limit_count + 1))
        fi
        
        # Check for rate limit messages in response body
        if echo "$body" | grep -qi "rate limit\|too many\|slow down\|throttl\|blocked\|banned\|try again later"; then
            rate_limited=true
            rate_limit_count=$((rate_limit_count + 1))
        fi
    done

    # Check for rate limiting headers
    local headers
    headers=$(curl -sS -I --max-time "${TIMEOUT:-10}" "$login_url" 2>/dev/null || echo "")
    local has_ratelimit_headers=false
    if echo "$headers" | grep -qi "x-ratelimit\|x-rate-limit\|ratelimit\|retry-after"; then
        has_ratelimit_headers=true
    fi

    # Assess findings
    if [[ "$rate_limited" == true ]] && [[ "$rate_limit_count" -ge 2 ]]; then
        echo "PASS|Rate limiting active: $rate_limit_count of $request_count requests blocked/throttled in ${duration}s|Rate limiting properly configured|INFO|"
    elif [[ "$has_ratelimit_headers" == true ]]; then
        echo "PASS|Rate limiting headers detected (X-RateLimit-* or Retry-After present)|Rate limiting properly configured|INFO|"
    elif [[ "$rate_limited" == true ]]; then
        echo "PASS|Rate limiting detected: ${rate_limit_count} response(s) showed throttling in ${duration}s|Rate limiting properly configured|INFO|"
    else
        echo "FAIL|No rate limiting detected: sent $request_count rapid login attempts in ${duration}s with no throttling|Implement rate limiting on login endpoints (e.g., 5 attempts per minute)|HIGH|SEC-RATELIMIT-001"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking rate limiting for $TARGET"
    
    OUTPUT_DIR="$OUT/step3"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/ratelimit.json"
    
    result=$(check_rate_limit "$TARGET")
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
        echo "    {\"name\":\"Rate Limiting\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "Rate limit check complete"
done
