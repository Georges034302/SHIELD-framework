#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step5_error_pages"

check_error_pages() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    local issues=()
    local severity="INFO"

    # Trigger a 404 with a highly unlikely path
    local not_found_url="${base_url}/shield-nonexistent-$(date +%s)-test"
    local not_found_response
    not_found_response=$(curl -sS -L --max-time "${TIMEOUT:-10}" "$not_found_url" 2>/dev/null || echo "")

    # Trigger a 500 by sending malformed input
    local error_url="${base_url}/?__shield_error_test[]=1&id=0%27"
    local error_response
    error_response=$(curl -sS -L --max-time "${TIMEOUT:-10}" "$error_url" 2>/dev/null || echo "")

    # Combined content for analysis
    local combined="${not_found_response}${error_response}"

    # Check for stack traces
    if echo "$combined" | grep -qiE "stack trace|at .*\.(php|java|py|rb|js):[0-9]+|Traceback \(most recent|Exception in thread|Fatal error.*on line|ParseError|SyntaxError.*at line"; then
        issues+=("Stack trace or code error exposed in error page")
        severity="HIGH"
    fi

    # Check for server paths
    if echo "$combined" | grep -qiE "/var/www/|/home/[a-z]+/public_html|/srv/www|C:\\\\inetpub|C:\\\\xampp|/usr/local/apache|DocumentRoot"; then
        issues+=("Server filesystem path exposed in error page")
        [[ "$severity" == "INFO" ]] && severity="HIGH"
    fi

    # Check for database errors
    if echo "$combined" | grep -qiE "SQL syntax|mysql_fetch|ORA-[0-9]{5}|pg_query|SQLSTATE|PDOException|Doctrine.*Exception|you have an error in your sql|Warning.*mysql"; then
        issues+=("Database error / SQL details exposed in error page")
        severity="HIGH"
    fi

    # Check for PHP errors
    if echo "$combined" | grep -qiE "Warning: .* in /.* on line|Notice: .* in /.* on line|Fatal error: .* in /.* on line|Deprecated: .* in /"; then
        issues+=("PHP error messages exposed (including file path and line numbers)")
        [[ "$severity" == "INFO" ]] && severity="HIGH"
    fi

    # Check for framework/version info in errors
    if echo "$combined" | grep -qiE "Laravel|Symfony|CodeIgniter|CakePHP|Zend|Yii|Django|Rails.*Exception|ASP\.NET.*stack"; then
        issues+=("Framework name/version exposed in error response")
        [[ "$severity" == "INFO" ]] && severity="MEDIUM"
    fi

    # Check for internal IPs
    if echo "$combined" | grep -qE "10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+|192\.168\.[0-9]+\.[0-9]+"; then
        issues+=("Internal IP address exposed in error response")
        [[ "$severity" == "INFO" ]] && severity="MEDIUM"
    fi

    if [[ ${#issues[@]} -eq 0 ]]; then
        echo "PASS|Error pages do not expose sensitive server/code information|Generic error pages with no debug information|INFO|"
        return
    fi

    local issues_str
    issues_str=$(IFS="; "; printf '%s' "${issues[*]}")
    echo "FAIL|$issues_str|Implement custom error pages; disable debug mode in production; suppress error output|$severity|SEC-ERRPAGE-001"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking error page information disclosure for $TARGET"

    OUTPUT_DIR="$OUT/step5"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/error_pages.json"

    result=$(check_error_pages "$TARGET")
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
        echo "    {\"name\":\"Error Page Disclosure\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "Error pages check complete"
done
