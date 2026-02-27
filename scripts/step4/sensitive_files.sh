#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step4_sensitive_files"

# Common sensitive files and directories
SENSITIVE_PATHS=(
    ".git/HEAD"
    ".git/config"
    ".env"
    ".env.local"
    ".env.production"
    "config.php"
    "wp-config.php"
    "database.yml"
    "settings.py"
    "web.config"
    ".htaccess"
    "phpinfo.php"
    "info.php"
    "backup.sql"
    "backup.zip"
    "backup.tar.gz"
    "dump.sql"
    ".DS_Store"
    "id_rsa"
    "id_rsa.pub"
    ".aws/credentials"
)

# Check for sensitive file exposure
check_sensitive_files() {
    local target="$1"
    local base_url="${target%/}"
    
    local exposed=()
    local checked=0
    
    for path in "${SENSITIVE_PATHS[@]}"; do
        local url="$base_url/$path"
        local status_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 "$url" 2>/dev/null || echo "000")
        checked=$((checked + 1))
        
        if [[ "$status_code" == "200" ]]; then
            exposed+=("$path (HTTP $status_code)")
        fi
    done
    
    if [[ ${#exposed[@]} -eq 0 ]]; then
        echo "PASS|No sensitive files exposed (checked $checked paths)|Sensitive files protected|INFO|"
    elif [[ ${#exposed[@]} -eq 1 ]]; then
        echo "FAIL|Exposed: ${exposed[0]}|Sensitive files protected|HIGH|SEC-FILES-001"
    else
        local exposed_str=$(IFS=", "; echo "${exposed[*]}")
        echo "FAIL|${#exposed[@]} sensitive files exposed: $exposed_str|Sensitive files protected|CRITICAL|SEC-FILES-002"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking sensitive file exposure for $TARGET"
    
    OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/sensitive_files.json"
    
    # Run check
    result=$(check_sensitive_files "$TARGET")
    
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
        echo "    {\"name\":\"Sensitive File Exposure\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "Sensitive files check complete"
done
