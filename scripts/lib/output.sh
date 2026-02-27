#!/usr/bin/env bash
# JSON output formatting utilities

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

# Add a check result to report
add_check() {
    local name="$1"
    local status="$2"      # PASS, FAIL, WARN, INFO
    local found="$3"
    local expected="$4"
    local severity="$5"    # HIGH, MEDIUM, LOW, INFO
    local remediation_id="$6"
    local message="${7:-}"
    
    cat <<EOF
{
  "name": "$name",
  "status": "$status",
  "found": $(echo "$found" | jq -R .),
  "expected": $(echo "$expected" | jq -R .),
  "severity": "$severity",
  "remediation_id": "$remediation_id",
  "message": $(echo "$message" | jq -R .)
}
EOF
}

# Write report to JSON file
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
