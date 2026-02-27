#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step3_session_fixation"

# Check for session fixation indicators:
# - Pre-auth session cookie set before login
# - Session ID does not change after login (hard to test without credentials)
# - Checks: pre-login cookie assignment, Set-Cookie before auth context
check_session_fixation() {
    local target="$1"
    local hostname
    hostname=$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##')

    local issues=()
    local severity="INFO"

    # Fetch root page headers
    local response
    response=$(curl -sS -I --max-time "${TIMEOUT:-10}" "$target" 2>/dev/null || echo "")

    # Check if session cookie is set on unauthenticated request (indicator of potential fixation)
    local set_cookie
    set_cookie=$(echo "$response" | grep -i "^Set-Cookie:" || echo "")

    local session_cookies
    session_cookies=$(echo "$set_cookie" | grep -iE "PHPSESSID|JSESSIONID|ASP\.NET_SessionId|session|sess" || echo "")

    if [[ -n "$session_cookies" ]]; then
        # Check if HttpOnly and Secure flags are present
        local missing_flags=()
        echo "$session_cookies" | while IFS= read -r cookie_line; do
            [[ -z "$cookie_line" ]] && continue
            echo "$cookie_line" | grep -qi "HttpOnly" || missing_flags+=("HttpOnly missing")
            echo "$cookie_line" | grep -qi "Secure" || missing_flags+=("Secure missing")
        done

        # Session fixation risk: session ID assigned before authentication
        issues+=("Session cookie assigned on unauthenticated request (potential fixation vector)")
        severity="MEDIUM"

        # Check SameSite attribute
        local no_samesite=false
        if ! echo "$session_cookies" | grep -qi "SameSite"; then
            issues+=("Session cookie missing SameSite attribute")
            no_samesite=true
        fi

        if [[ ${#issues[@]} -ge 2 ]] || [[ "$no_samesite" == true && ${#issues[@]} -ge 1 ]]; then
            severity="HIGH"
            local issues_str
            issues_str=$(IFS=", "; printf '%s' "${issues[*]}")
            echo "FAIL|$issues_str|Session ID regenerated after auth; Secure+HttpOnly+SameSite set|$severity|SEC-SESS-002"
            return
        fi

        local issues_str
        issues_str=$(IFS=", "; printf '%s' "${issues[*]}")
        echo "WARN|$issues_str|Session ID should regenerate post-authentication|$severity|SEC-SESS-001"
        return
    fi

    # No pre-auth session cookie
    echo "PASS|No pre-auth session cookie detected|No session fixation indicators found|INFO|"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking session fixation indicators for $TARGET"

    OUTPUT_DIR="$OUT/step3"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/session_fixation.json"

    result=$(check_session_fixation "$TARGET")

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
        echo "    {\"name\":\"Session Fixation Indicators\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "Session fixation check complete"
done
