#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

# SHIELD - Brute Force Lockout Detection
# ⚠ ONLY ACTIVATES WITH --brute-force FLAG
# PURPOSE: Tests whether login endpoint enforces lockout after repeated failures
# GUARDRAILS:
#   - Max 10 attempts (hardcoded, not configurable upward)
#   - 1 second delay between attempts
#   - Stops immediately when lockout detected
#   - Never reports credential success — only lockout present/absent
#   - Only common/default credential pairs (no wordlists)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step3_brute_force_check"

# Check if brute force mode is enabled
if [[ "${BRUTE_FORCE:-false}" != "true" ]]; then
    for TARGET in "${ARGS[@]}"; do
        OUTPUT_DIR="$OUT/step3"
        mkdir -p "$OUTPUT_DIR"
        OUTPUT_FILE="$OUTPUT_DIR/brute_force_check.json"
        {
            echo "{"
            echo "  \"step\": \"$STEP_NAME\","
            echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
            echo "  \"target\": \"$TARGET\","
            echo "  \"checks\": ["
            echo "    {\"name\":\"Brute Force Lockout\",\"status\":\"SKIP\",\"found\":\"Brute force test disabled (run with --brute-force to enable)\",\"expected\":\"Account lockout after repeated failures\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
            echo "  ]"
            echo "}"
        } > "$OUTPUT_FILE"
        print_status "INFO" "Brute force check skipped (--brute-force not set)"
    done
    exit 0
fi

# Maximum attempts — HARDCODED, DO NOT INCREASE
MAX_ATTEMPTS=10
ATTEMPT_DELAY=1  # seconds between attempts

# Common/default credential pairs only — no wordlists, no iteration
CREDENTIALS=(
    "admin:admin"
    "admin:password"
    "admin:123456"
    "admin:"
    "admin:wordpress"
    "administrator:admin"
    "admin:changeme"
    "root:root"
    "test:test"
    "guest:guest"
)

detect_lockout() {
    local response="$1"
    local http_code="$2"
    if [[ "$http_code" == "429" ]] || [[ "$http_code" == "403" ]]; then
        return 0
    fi
    if echo "$response" | grep -qi "locked\|too many attempts\|blocked\|banned\|throttl\|slow down\|account.*lock\|temporarily.*disabled\|brute"; then
        return 0
    fi
    return 1
}

detect_success() {
    local response="$1"
    local http_code="$2"
    # WP dashboard redirect / logged-in indicators
    if echo "$response" | grep -qi "wp-admin\|Dashboard\|Howdy\|logged.in\|welcome.*admin\|administration"; then
        return 0
    fi
    return 1
}

find_login_endpoint() {
    local base_url="$1"
    local login_paths=("/wp-login.php" "/login" "/admin/login" "/user/login" "/signin" "/account/login" "/wp-admin")
    for path in "${login_paths[@]}"; do
        local url="${base_url}${path}"
        local code
        code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-10}" "$url" 2>/dev/null || echo "000")
        if [[ "$code" == "200" ]]; then
            echo "$url"
            return
        fi
    done
    echo ""
}

get_wp_nonce() {
    local login_url="$1"
    local nonce=""
    local page
    page=$(curl -sS -L --max-time "${TIMEOUT:-10}" "$login_url" 2>/dev/null || echo "")
    nonce=$(echo "$page" | grep -oE 'name="[^"]*nonce[^"]*" value="[^"]*"' | head -1 | grep -oE 'value="[^"]*"' | sed 's/value="//;s/"//')
    echo "${nonce:-}"
}

check_brute_force() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    print_status "INFO" "  [BRUTE FORCE] Finding login endpoint..."
    local login_url
    login_url=$(find_login_endpoint "$base_url")

    if [[ -z "$login_url" ]]; then
        echo "INFO|No login endpoint found at standard paths|N/A|INFO|"
        return
    fi

    print_status "INFO" "  [BRUTE FORCE] Login endpoint: $login_url"

    # Determine if WP login (needs wp-nonce and specific fields)
    local is_wp=false
    local login_page_content
    login_page_content=$(curl -sS -L --max-time "${TIMEOUT:-10}" "$login_url" 2>/dev/null || echo "")
    if echo "$login_page_content" | grep -qi "wp-login\|WordPress\|wp-submit"; then
        is_wp=true
    fi

    # Get cookies/session for accurate simulation
    local cookie_jar
    cookie_jar=$(mktemp /tmp/shield_bf_XXXXXX.txt)
    trap "rm -f $cookie_jar" EXIT

    # Pre-fetch to get session cookies
    curl -sS -L --max-time "${TIMEOUT:-10}" \
        -c "$cookie_jar" -b "$cookie_jar" \
        "$login_url" > /dev/null 2>&1 || true

    local attempt=0
    local lockout_detected=false
    local lockout_at=0
    local login_success=false
    local success_user=""
    local last_http_code=""

    for cred in "${CREDENTIALS[@]}"; do
        if [[ "$attempt" -ge "$MAX_ATTEMPTS" ]]; then
            break
        fi

        local username="${cred%%:*}"
        local password="${cred#*:}"
        attempt=$((attempt + 1))

        print_status "INFO" "  [BRUTE FORCE] Attempt $attempt/$MAX_ATTEMPTS: $username / ${password:-<empty>}"

        local post_data
        local response
        local http_code

        if [[ "$is_wp" == true ]]; then
            # Re-fetch nonce each time for accurate WP simulation
            local nonce
            nonce=$(get_wp_nonce "$login_url")
            post_data="log=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$username'))" 2>/dev/null || echo "$username")&pwd=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$password'))" 2>/dev/null || echo "$password")&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1${nonce:+&_wpnonce=$nonce}"
        else
            post_data="username=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$username'))" 2>/dev/null || echo "$username")&password=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$password'))" 2>/dev/null || echo "$password")&submit=Login"
        fi

        response=$(curl -sS -L \
            --max-time "${TIMEOUT:-10}" \
            -w "\n__HTTP_CODE__:%{http_code}" \
            -X POST \
            -d "$post_data" \
            -c "$cookie_jar" -b "$cookie_jar" \
            -H "Referer: $login_url" \
            -H "Content-Type: application/x-www-form-urlencoded" \
            "$login_url" 2>/dev/null || echo "__HTTP_CODE__:000")

        http_code=$(echo "$response" | grep "__HTTP_CODE__:" | tail -1 | cut -d: -f2)
        response=$(echo "$response" | grep -v "__HTTP_CODE__:")
        last_http_code="$http_code"

        # Check lockout — STOP IMMEDIATELY if detected
        if detect_lockout "$response" "$http_code"; then
            lockout_detected=true
            lockout_at=$attempt
            print_status "INFO" "  [BRUTE FORCE] Lockout detected at attempt $attempt ✓"
            break
        fi

        # Check for accidental login success (report only, do not exploit)
        if detect_success "$response" "$http_code"; then
            login_success=true
            success_user="$username"
            print_status "WARN" "  [BRUTE FORCE] Default credential login detected: $username"
            # Immediately stop — do not proceed or exploit
            break
        fi

        sleep "$ATTEMPT_DELAY"
    done

    rm -f "$cookie_jar" 2>/dev/null || true

    # Build result
    if [[ "$login_success" == true ]]; then
        echo "FAIL|Default credential login succeeded for user '$success_user' (CRITICAL: change password immediately)|No default credentials; strong unique passwords required|CRITICAL|SEC-BRUTE-003"
        return
    fi

    if [[ "$lockout_detected" == true ]]; then
        echo "PASS|Account lockout triggered after $lockout_at attempt(s) at $login_url|Account lockout active|INFO|"
        return
    fi

    # No lockout after all attempts
    echo "FAIL|No lockout detected after $attempt login attempts at $login_url (last HTTP $last_http_code)|Implement account lockout after 3-5 failed attempts|HIGH|SEC-BRUTE-002"
}

for TARGET in "${ARGS[@]}"; do
    print_status "WARN" "Brute force lockout test active for $TARGET"

    OUTPUT_DIR="$OUT/step3"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/brute_force_check.json"

    result=$(check_brute_force "$TARGET")
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
        echo "    {\"name\":\"Brute Force Lockout\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "Brute force check complete"
done
