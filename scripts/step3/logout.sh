#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step3_logout"

json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/}"
    echo -n "$str"
}

check_logout() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    # Check if credentials are provided
    if [[ -z "${WP_USER:-}" ]] || [[ -z "${WP_PASS:-}" ]]; then
        echo "SKIP|Authentication required: Set WP_USER and WP_PASS environment variables to test logout|Session properly invalidated after logout|INFO|"
        return
    fi

    # Find login endpoint
    local login_paths=("/wp-login.php" "/login" "/admin/login" "/user/login" "/signin" "/account/login")
    local login_url=""
    local logout_url=""

    for path in "${login_paths[@]}"; do
        local url="${base_url}${path}"
        local status_code
        status_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-10}" "$url" 2>/dev/null || echo "000")
        if [[ "$status_code" == "200" ]] || [[ "$status_code" == "302" ]]; then
            login_url="$url"
            if [[ "$path" == "/wp-login.php" ]]; then
                logout_url="${base_url}/wp-login.php?action=logout"
            else
                logout_url="${url//login/logout}"
            fi
            break
        fi
    done

    if [[ -z "$login_url" ]]; then
        echo "INFO|No common login endpoint found at standard paths|N/A|INFO|"
        return
    fi

    # Create temporary cookie jar
    local cookie_jar
    cookie_jar=$(mktemp /tmp/shield_logout_XXXXXX.txt)
    trap "rm -f $cookie_jar" EXIT

    # Step 1: Attempt login with provided credentials
    local login_response
    login_response=$(curl -sS -L --max-time "${TIMEOUT:-10}" \
        -c "$cookie_jar" -b "$cookie_jar" \
        -d "log=${WP_USER}&pwd=${WP_PASS}&wp-submit=Log+In" \
        -w "\nHTTP_CODE:%{http_code}" \
        "$login_url" 2>/dev/null || echo "")

    local login_code=$(echo "$login_response" | grep "HTTP_CODE:" | cut -d: -f2)
    local login_body=$(echo "$login_response" | grep -v "HTTP_CODE:")

    # Check if login was successful
    local login_success=false
    if echo "$login_body" | grep -qi "wp-admin\|dashboard\|howdy\|logged.*in\|welcome.*admin"; then
        login_success=true
    fi

    if [[ "$login_success" != true ]]; then
        echo "SKIP|Unable to authenticate with provided credentials|Session properly invalidated after logout|INFO|"
        return
    fi

    # Get cookies before logout
    local cookies_before=""
    if [[ -f "$cookie_jar" ]]; then
        cookies_before=$(grep -v "^#" "$cookie_jar" 2>/dev/null | grep -E "wordpress|wp-|PHPSESSID|session" || echo "")
    fi

    # Step 2: Access a protected page to verify authenticated session
    local protected_url="${base_url}/wp-admin/"
    local protected_response
    protected_response=$(curl -sS -L --max-time "${TIMEOUT:-10}" \
        -b "$cookie_jar" \
        -w "\nHTTP_CODE:%{http_code}" \
        "$protected_url" 2>/dev/null || echo "")

    local protected_code=$(echo "$protected_response" | grep "HTTP_CODE:" | cut -d: -f2)
    local protected_accessible=false
    if [[ "$protected_code" == "200" ]]; then
        protected_accessible=true
    fi

    # Step 3: Perform logout
    if [[ -n "$logout_url" ]]; then
        curl -sS -L --max-time "${TIMEOUT:-10}" \
            -c "$cookie_jar" -b "$cookie_jar" \
            "$logout_url" > /dev/null 2>&1 || true
    fi

    # Step 4: Attempt to access protected page again with old session
    local post_logout_response
    post_logout_response=$(curl -sS -L --max-time "${TIMEOUT:-10}" \
        -b "$cookie_jar" \
        -w "\nHTTP_CODE:%{http_code}" \
        "$protected_url" 2>/dev/null || echo "")

    local post_logout_code=$(echo "$post_logout_response" | grep "HTTP_CODE:" | cut -d: -f2)
    local post_logout_body=$(echo "$post_logout_response" | grep -v "HTTP_CODE:")

    # Analyze if session was properly terminated
    local still_authenticated=false
    if [[ "$post_logout_code" == "200" ]] && echo "$post_logout_body" | grep -qi "wp-admin\|dashboard\|howdy"; then
        still_authenticated=true
    fi

    # Get cookies after logout
    local cookies_after=""
    if [[ -f "$cookie_jar" ]]; then
        cookies_after=$(grep -v "^#" "$cookie_jar" 2>/dev/null | grep -E "wordpress|wp-|PHPSESSID|session" || echo "")
    fi

    # Assess logout security
    if [[ "$still_authenticated" == true ]]; then
        echo "FAIL|Session remains valid after logout: protected resources still accessible with old session cookie|Session invalidated on logout; cookies cleared|CRITICAL|SEC-LOGOUT-001"
    elif [[ "$protected_accessible" == true ]] && [[ "$post_logout_code" != "200" ]]; then
        echo "PASS|Logout properly invalidates session: post-logout access returned HTTP $post_logout_code|Session invalidated on logout|INFO|"
    elif [[ -n "$cookies_before" ]] && [[ "$cookies_before" != "$cookies_after" ]]; then
        echo "PASS|Logout detected: session cookies changed/cleared after logout|Session invalidated on logout|INFO|"
    else
        echo "WARN|Logout behavior inconclusive: could not fully verify session termination|Session invalidated on logout; cookies cleared|MEDIUM|SEC-LOGOUT-002"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking logout mechanism for $TARGET"
    
    OUTPUT_DIR="$OUT/step3"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/logout.json"
    
    result=$(check_logout "$TARGET")
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
        echo "    {\"name\":\"Logout Session Termination\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "Logout check complete"
done
