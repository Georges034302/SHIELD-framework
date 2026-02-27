#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step5_open_redirect"

# Check for open redirect vulnerabilities via common redirect parameters
check_open_redirect() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    local redirect_params=("url" "redirect" "redirect_url" "return" "returnUrl" "next" "goto" "target" "dest" "destination" "redir" "ref")
    local canary="https://evil-redirect-test.example.com"
    local issues=()
    local severity="INFO"

    for param in "${redirect_params[@]}"; do
        local test_url="${base_url}/?${param}=${canary}"

        local response
        response=$(curl -sS -I -L \
            --max-time "${TIMEOUT:-10}" \
            --max-redirs 5 \
            "$test_url" 2>/dev/null || echo "")

        # Check if we were redirected to the canary domain
        if echo "$response" | grep -qi "Location:.*evil-redirect-test"; then
            issues+=("Open redirect via ?$param= parameter")
            severity="HIGH"
        fi

        # Also check for relative redirect bypass attempts
        local encoded_canary
        encoded_canary=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$canary'))" 2>/dev/null || echo "$canary")
        local encoded_url="${base_url}/?${param}=${encoded_canary}"

        local encoded_response
        encoded_response=$(curl -sS -I -L \
            --max-time "${TIMEOUT:-10}" \
            --max-redirs 3 \
            "$encoded_url" 2>/dev/null || echo "")

        if echo "$encoded_response" | grep -qi "Location:.*evil-redirect-test"; then
            issues+=("Open redirect via encoded ?$param= parameter")
            [[ "$severity" == "INFO" ]] && severity="HIGH"
        fi
    done

    if [[ ${#issues[@]} -eq 0 ]]; then
        echo "PASS|No open redirect vulnerabilities detected in common parameters|No unvalidated redirects|INFO|"
        return
    fi

    local issues_str
    issues_str=$(IFS=", "; printf '%s' "${issues[*]}")

    if [[ ${#issues[@]} -ge 2 ]]; then
        echo "FAIL|$issues_str|Validate all redirect destinations against allowlist|$severity|SEC-REDIRECT-002"
    else
        echo "FAIL|$issues_str|Validate redirect destinations against allowlist|$severity|SEC-REDIRECT-001"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking open redirect vulnerabilities for $TARGET"

    OUTPUT_DIR="$OUT/step5"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/open_redirect.json"

    result=$(check_open_redirect "$TARGET")

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
        echo "    {\"name\":\"Open Redirect\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "Open redirect check complete"
done
