#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step3_login_protection"

check_login_protection() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    # Common login endpoints to probe
    local login_paths=("/wp-login.php" "/login" "/admin/login" "/user/login" "/signin" "/account/login" "/auth/login" "/admin")
    local login_url=""
    local login_type=""

    # Find a login page
    for path in "${login_paths[@]}"; do
        local url="${base_url}${path}"
        local status_code
        status_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-10}" "$url" 2>/dev/null || echo "000")
        if [[ "$status_code" == "200" ]] || [[ "$status_code" == "302" ]]; then
            login_url="$url"
            login_type="$path"
            break
        fi
    done

    if [[ -z "$login_url" ]]; then
        echo "INFO|No common login endpoints found at standard paths|N/A|INFO|"
        return
    fi

    local issues=()
    local severity="INFO"

    # Fetch the login page
    local login_page
    login_page=$(curl -sS -L --max-time "${TIMEOUT:-10}" "$login_url" 2>/dev/null || echo "")

    # Check for CAPTCHA
    local has_captcha=false
    if echo "$login_page" | grep -qi "captcha\|recaptcha\|hcaptcha\|turnstile\|g-recaptcha"; then
        has_captcha=true
    fi

    # Check for rate limiting headers on login page
    local headers
    headers=$(curl -sS -I --max-time "${TIMEOUT:-10}" "$login_url" 2>/dev/null || echo "")
    local has_ratelimit=false
    if echo "$headers" | grep -qi "x-ratelimit\|retry-after\|x-rate-limit"; then
        has_ratelimit=true
    fi

    # Check response for lockout indicators by probing with a dummy POST
    local dummy_response
    dummy_response=$(curl -sS -X POST \
        --max-time "${TIMEOUT:-10}" \
        -d "log=shield_test_user&pwd=shield_test_pass_12345&wp-submit=Log+In" \
        -c /dev/null -b /dev/null \
        "$login_url" 2>/dev/null || echo "")

    local has_lockout=false
    if echo "$dummy_response" | grep -qi "locked\|too many\|blocked\|banned\|attempts\|throttl\|slow down"; then
        has_lockout=true
    fi

    # Check for two-factor auth hints
    local has_2fa=false
    if echo "$login_page" | grep -qi "two.factor\|2fa\|totp\|authenticator\|verification code"; then
        has_2fa=true
    fi

    # Build assessment
    if [[ "$has_captcha" == true ]] && [[ "$has_ratelimit" == true || "$has_lockout" == true ]]; then
        echo "PASS|Login at $login_type: CAPTCHA present + rate limiting/lockout active|CAPTCHA + lockout + rate limiting|INFO|"
        return
    fi

    if [[ "$has_captcha" == false ]]; then
        issues+=("No CAPTCHA on login page ($login_type)")
        severity="MEDIUM"
    fi

    if [[ "$has_ratelimit" == false ]] && [[ "$has_lockout" == false ]]; then
        issues+=("No rate limiting or lockout response detected")
        severity="HIGH"
    fi

    if [[ ${#issues[@]} -eq 0 ]]; then
        local detail="Login found at $login_type"
        [[ "$has_2fa" == true ]] && detail="$detail; 2FA indicators present"
        echo "PASS|$detail|Login protection adequate|INFO|"
        return
    fi

    local issues_str
    issues_str=$(IFS="; "; printf '%s' "${issues[*]}")
    local remediation_id="SEC-LOGIN-001"
    [[ "$severity" == "HIGH" ]] && remediation_id="SEC-LOGIN-002"

    echo "FAIL|$issues_str|Add CAPTCHA + account lockout + rate limiting to login|$severity|$remediation_id"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking login protection for $TARGET"

    OUTPUT_DIR="$OUT/step3"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/login_protection.json"

    result=$(check_login_protection "$TARGET")
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
        echo "    {\"name\":\"Login Protection\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "Login protection check complete"
done
