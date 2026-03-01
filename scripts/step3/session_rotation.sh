#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step3_session_rotation"

json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/}"
    echo -n "$str"
}

check_session_rotation() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    # Check if credentials are provided
    if [[ -z "${WP_USER:-}" ]] || [[ -z "${WP_PASS:-}" ]]; then
        echo "SKIP|Authentication required: Set WP_USER and WP_PASS environment variables to test session rotation|Session ID regenerated on login|INFO|"
        return
    fi

    # Find login endpoint
    local login_paths=("/wp-login.php" "/login" "/admin/login" "/user/login" "/signin" "/account/login")
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

    # Create temporary cookie jars
    local cookie_jar_pre
    local cookie_jar_post
    cookie_jar_pre=$(mktemp /tmp/shield_pre_XXXXXX.txt)
    cookie_jar_post=$(mktemp /tmp/shield_post_XXXXXX.txt)
    trap "rm -f $cookie_jar_pre $cookie_jar_post" EXIT

    # Step 1: Visit login page (unauthenticated) to get initial session cookie
    curl -sS -L --max-time "${TIMEOUT:-10}" \
        -c "$cookie_jar_pre" \
        "$login_url" > /dev/null 2>&1 || true

    # Extract pre-login session ID
    local pre_session_id=""
    if [[ -f "$cookie_jar_pre" ]]; then
        # Look for common session cookie names
        pre_session_id=$(grep -v "^#" "$cookie_jar_pre" 2>/dev/null | \
            grep -E "PHPSESSID|wordpress_logged_in|wp-settings|session|JSESSIONID" | \
            head -1 | awk '{print $7}' || echo "")
    fi

    # Step 2: Perform login with credentials
    curl -sS -L --max-time "${TIMEOUT:-10}" \
        -c "$cookie_jar_post" -b "$cookie_jar_pre" \
        -d "log=${WP_USER}&pwd=${WP_PASS}&wp-submit=Log+In" \
        "$login_url" > /dev/null 2>&1 || true

    # Extract post-login session ID
    local post_session_id=""
    if [[ -f "$cookie_jar_post" ]]; then
        # Look for authenticated session cookie
        post_session_id=$(grep -v "^#" "$cookie_jar_post" 2>/dev/null | \
            grep -E "PHPSESSID|wordpress_logged_in|wp-settings|session|JSESSIONID" | \
            head -1 | awk '{print $7}' || echo "")
    fi

    # Step 3: Check if login was successful
    local protected_url="${base_url}/wp-admin/"
    local protected_response
    protected_response=$(curl -sS -L --max-time "${TIMEOUT:-10}" \
        -b "$cookie_jar_post" \
        "$protected_url" 2>/dev/null || echo "")

    local login_success=false
    if echo "$protected_response" | grep -qi "wp-admin\|dashboard\|howdy\|logged.*in"; then
        login_success=true
    fi

    # Analyze session rotation
    if [[ "$login_success" != true ]]; then
        echo "SKIP|Unable to authenticate with provided credentials|Session ID regenerated on login|INFO|"
        return
    fi

    if [[ -z "$pre_session_id" ]] && [[ -z "$post_session_id" ]]; then
        echo "WARN|No session cookies detected before or after login|Session ID regenerated on privilege escalation|MEDIUM|SEC-SESSROT-003"
        return
    fi

    if [[ -z "$pre_session_id" ]] && [[ -n "$post_session_id" ]]; then
        echo "PASS|Session ID created on authentication: no pre-auth session, post-auth session present|Session ID regenerated on login|INFO|"
        return
    fi

    if [[ -n "$pre_session_id" ]] && [[ -z "$post_session_id" ]]; then
        echo "WARN|Pre-auth session detected but no post-auth session (unusual pattern)|Session ID regenerated on privilege escalation|MEDIUM|SEC-SESSROT-004"
        return
    fi

    # Compare session IDs
    if [[ "$pre_session_id" != "$post_session_id" ]]; then
        echo "PASS|Session ID properly rotated on authentication: pre-login vs post-login session IDs differ|Session ID regenerated on login|INFO|"
    else
        echo "FAIL|Session fixation risk: Session ID unchanged after authentication|Regenerate session ID on login/privilege change to prevent session fixation|HIGH|SEC-SESSROT-001"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking session rotation for $TARGET"
    
    OUTPUT_DIR="$OUT/step3"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/session_rotation.json"
    
    result=$(check_session_rotation "$TARGET")
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
        echo "    {\"name\":\"Session ID Rotation\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "Session rotation check complete"
done
