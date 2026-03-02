#!/usr/bin/env bash
# JSON output formatting utilities

# Helper to escape JSON strings safely
json_escape() {
    local str="$1"
    # Replace backslash, then quotes, then newlines
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/}"
    echo -n "$str"
}

# Initialize a step report
init_report() {
    local step_name="$1"
    local target="$2"
    
    cat <<EOF
{
  "step": "$step_name",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "target": "$target",
  "checks": []
}
EOF
}

# Add a check result to report (Phase 6A enhanced)
add_check() {
    local name="$1"
    local status="$2"      # PASS, FAIL, WARN, INFO
    local found="$3"
    local expected="$4"
    local severity="$5"    # HIGH, MEDIUM, LOW, INFO
    local remediation_id="$6"
    local message="${7:-}"
    local confidence="${8:-HIGH}"  # Phase 6A: HIGH, MEDIUM, LOW
    
    cat <<EOF
{
  "name": "$name",
  "status": "$status",
  "found": $(echo "$found" | jq -R .),
  "expected": $(echo "$expected" | jq -R .),
  "severity": "$severity",
  "remediation_id": "$remediation_id",
  "message": $(echo "$message" | jq -R .),
  "confidence": "$confidence"
}
EOF
}

# Phase 6A: Add check with full metadata
add_check_with_metadata() {
    local name="$1"
    local status="$2"
    local found="$3"
    local expected="$4"
    local severity="$5"
    local remediation_id="$6"
    local confidence="${7:-HIGH}"
    local metadata="${8:-{}}"  # JSON object string
    
    cat <<EOF
{
  "name": "$name",
  "status": "$status",
  "found": $(echo "$found" | jq -R .),
  "expected": $(echo "$expected" | jq -R .),
  "severity": "$severity",
  "remediation_id": "$remediation_id",
  "confidence": "$confidence",
  "metadata": $metadata
}
EOF
}

# Phase 6A: Build metadata object for a check
build_metadata() {
    local user_agent="${1:-}"
    local resolved_ips="${2:-}"
    local http_code="${3:-}"
    local response_time_ms="${4:-}"
    
    local metadata="{"
    local has_fields=false
    
    if [[ -n "$user_agent" ]]; then
        metadata="${metadata}\"user_agent\": $(echo "$user_agent" | jq -R .)"
        has_fields=true
    fi
    
    if [[ -n "$resolved_ips" ]]; then
        [[ "$has_fields" == true ]] && metadata="${metadata}, "
        metadata="${metadata}\"resolved_ips\": $(echo "$resolved_ips" | jq -R . | jq -c 'split(",")')"
        has_fields=true
    fi
    
    if [[ -n "$http_code" ]]; then
        [[ "$has_fields" == true ]] && metadata="${metadata}, "
        metadata="${metadata}\"http_code\": \"$http_code\""
        has_fields=true
    fi
    
    if [[ -n "$response_time_ms" ]]; then
        [[ "$has_fields" == true ]] && metadata="${metadata}, "
        metadata="${metadata}\"response_time_ms\": $response_time_ms"
        has_fields=true
    fi
    
    metadata="${metadata}}"
    echo "$metadata"
}

# Write report to JSON file (Phase 6A enhanced)
write_report() {
    local output_file="$1"
    local step_name="$2"
    local target="$3"
    shift 3
    local checks=("$@")
    
    mkdir -p "$(dirname "$output_file")"
    
    {
        echo "{"
        echo "  \"step\": \"$step_name\","
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"target\": \"$target\","
        
        # Phase 6A: Add mode metadata if available
        if declare -f get_mode_metadata >/dev/null 2>&1; then
            echo "  $(get_mode_metadata),"
        fi
        
        echo "  \"checks\": ["
        
        local first=true
        for check in "${checks[@]}"; do
            if [ "$first" = true ]; then
                first=false
            else
                echo ","
            fi
            echo "    $check"
        done
        
        echo ""
        echo "  ]"
        
        # Phase 6A: Add stability summary if available
        if declare -f get_stability_summary >/dev/null 2>&1; then
            echo "  ,"
            echo "  $(get_stability_summary)"
        fi
        
        echo "}"
    } > "$output_file"
}

# Color-coded console output
print_status() {
    local status="$1"
    local message="$2"
    
    case "$status" in
        PASS)  echo -e "[\033[32m✓\033[0m] $message" ;;
        FAIL)  echo -e "[\033[31m✗\033[0m] $message" ;;
        WARN)  echo -e "[\033[33m!\033[0m] $message" ;;
        INFO)  echo -e "[\033[34mi\033[0m] $message" ;;
        *)     echo "[$status] $message" ;;
    esac
}
