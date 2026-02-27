#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step5_verbose_errors"

# Check for verbose error pages
check_verbose_errors() {
    local target="$1"
    local base_url="${target%/}"
    
    # Request a non-existent path to trigger error page
    local test_url="$base_url/this-definitely-does-not-exist-$(date +%s)"
    local response=$(curl -sS --max-time 5 "$test_url" 2>/dev/null || echo "")
    
    local issues=()
    
    # Look for common debug/verbose error patterns
    if echo "$response" | grep -qiE "(stack trace|backtrace|thrown in|error in line|syntax error)" || true; then
        issues+=("Stack traces visible")
    fi
    
    if echo "$response" | grep -qiE "(DEBUG|SQLSTATE|SQLException|mysql_|mysqli_|PDOException)" || true; then
        issues+=("Database errors exposed")
    fi
    
    if echo "$response" | grep -qiE "(Warning:|Notice:|Fatal error:|Parse error:)" || true; then
        issues+=("PHP error messages visible")
    fi
    
    if echo "$response" | grep -qiE "(Django|Traceback \(most recent|File \"/.*\.py\")" || true; then
        issues+=("Python/Django debug info visible")
    fi
    
    if echo "$response" | grep -qiE "(ASP\.NET|Server Error in|Description:|Exception Details:)" || true; then
        issues+=("ASP.NET debug info visible")
    fi
    
    if echo "$response" | grep -qiE "(at .*\.js:[0-9]+|Error: |TypeError:|ReferenceError:)" || true; then
        issues+=("JavaScript errors visible")
    fi
    
    # Check for file paths
    if echo "$response" | grep -qE "(/var/www/|/home/|C:\\\\|/usr/local/|/opt/)" || true; then
        issues+=("Server file paths exposed")
    fi
    
    if [[ ${#issues[@]} -eq 0 ]]; then
        echo "PASS|No verbose error information detected|Generic error pages|INFO|"
    elif [[ ${#issues[@]} -eq 1 ]]; then
        echo "WARN|${issues[0]}|Generic error pages|MEDIUM|SEC-ERROR-001"
    else
        local issues_str=$(IFS=", "; echo "${issues[*]}")
        echo "WARN|${#issues[@]} verbose error patterns found: $issues_str|Generic error pages|HIGH|SEC-ERROR-002"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking for verbose error pages on $TARGET"
    
    OUTPUT_DIR="$OUT/step5"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/verbose_errors.json"
    
    # Run check
    result=$(check_verbose_errors "$TARGET")
    
    # Parse result
    IFS='|' read -r status found expected severity remediation_id <<< "$result"
    
    # Escape for JSON
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
        echo "    {\"name\":\"Verbose Error Pages\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "Verbose error check complete"
done
