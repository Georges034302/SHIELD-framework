#!/usr/bin/env bash
# Step 3: Session Timeout Check (3 minutes)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"
source "$SCRIPT_DIR/lib/wp_detect.sh"

STEP_NAME="step3_timeout"

json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/}"
    echo -n "$str"
}

check_timeout() {
    local target="$1"
    local base_url=$(echo "$target" | sed 's|/$||')
    
    # Requires authentication
    if [[ -z "${WP_USER:-}" ]] || [[ -z "${WP_PASS:-}" ]]; then
        echo "SKIP|Authentication required for timeout test (use --user --pass)|Appropriate timeout configured|INFO|"
        return
    fi
    
    local is_wp=$(detect_wordpress "$target")
    if [[ "$is_wp" != "true" ]]; then
        echo "SKIP|Non-WordPress site - timeout test not implemented|Appropriate timeout configured|INFO|"
        return
    fi
    
    print_status "INFO" "  Logging in..."
    
    # Login and save cookie
    local login_response=$(curl -sL -c /tmp/wp_timeout_$$.txt \
        --max-time "${TIMEOUT:-15}" \
        -d "log=$WP_USER&pwd=$WP_PASS&wp-submit=Log+In" \
        "$base_url/wp-login.php" 2>/dev/null)
    
    if [[ ! -f "/tmp/wp_timeout_$$.txt" ]] || ! grep -q "wordpress_logged_in" "/tmp/wp_timeout_$$.txt"; then
        rm -f "/tmp/wp_timeout_$$.txt"
        echo "SKIP|Login failed - cannot test timeout|Appropriate timeout configured|INFO|"
        return
    fi
    
    # Test admin access immediately after login
    local admin_immediate=$(curl -sI -b "/tmp/wp_timeout_$$.txt" --max-time 10 "$base_url/wp-admin/" 2>/dev/null | head -1)
    
    if [[ "$admin_immediate" =~ "200" ]]; then
        print_status "PASS" "  Session active immediately after login"
    else
        rm -f "/tmp/wp_timeout_$$.txt"
        echo "SKIP|Session not established properly|Appropriate timeout configured|INFO|"
        return
    fi
    
    # Wait 3 minutes (180 seconds)
    print_status "INFO" "  Waiting 3 minutes to test session timeout..."
    sleep 180
    
    # Test admin access after 3 minutes
    local admin_after=$(curl -sI -b "/tmp/wp_timeout_$$.txt" --max-time 10 "$base_url/wp-admin/" 2>/dev/null | head -1)
    
    rm -f "/tmp/wp_timeout_$$.txt"
    
    # Check if session expired
    if [[ "$admin_after" =~ "302" ]] || [[ "$admin_after" =~ "301" ]] || echo "$admin_after" | grep -q "login"; then
        echo "PASS|Session timeout active (~3 min or less)|Session timeout < 15 minutes|INFO|"
    elif [[ "$admin_after" =~ "200" ]]; then
        echo "WARN|Session still active after 3 minutes|Session timeout should be < 15 min for sensitive apps|MEDIUM|SEC-TIMEOUT-001"
    else
        echo "SKIP|Unable to verify timeout behavior|Appropriate timeout configured|INFO|"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking session timeout for $TARGET (3-minute wait)"
    
    OUTPUT_DIR="$OUT/step3"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/timeout.json"
    
    # Run check
    result=$(check_timeout "$TARGET" || echo "SKIP|Test failed|Appropriate timeout configured|INFO|")
    IFS='|' read -r status found expected severity remediation_id <<< "$result"
    
    # Escape for JSON
    status_esc=$(json_escape "$status")
    found_esc=$(json_escape "$found")
    expected_esc=$(json_escape "$expected")
    severity_esc=$(json_escape "$severity")
    remediation_id_esc=$(json_escape "$remediation_id")
    
    # Write JSON
    {
        echo "{"
        echo "  \"step\": \"$STEP_NAME\","
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"target\": \"$TARGET\","
        echo "  \"checks\": ["
        echo "    {\"name\":\"Session Timeout (3 min test)\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "Timeout: $found"
    print_status "INFO" "Report written to $OUTPUT_FILE"
done
