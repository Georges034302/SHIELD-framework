#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step3_user_enumeration"

# Common user enumeration endpoints
ENUM_ENDPOINTS=(
    "wp-json/wp/v2/users"           # WordPress REST API
    "api/users"                     # Generic API
    "api/v1/users"                  # Versioned API
    "?author=1"                     # WordPress author enumeration
    "users"                         # Direct users endpoint
)

# Check for user enumeration vulnerabilities
check_user_enumeration() {
    local target="$1"
    local base_url="${target%/}"
    
    local vulnerable=()
    local checked=0
    
    for endpoint in "${ENUM_ENDPOINTS[@]}"; do
        local url="$base_url/$endpoint"
        local response=$(curl -sS -I --max-time 5 "$url" 2>/dev/null || echo "")
        local status_code=$(echo "$response" | grep -i "HTTP/" | head -1 | awk '{print $2}' || echo "000")
        checked=$((checked + 1))
        
        # 200 = enumerable, 401/403 = exists but protected (good), 404 = doesn't exist (good)
        if [[ "$status_code" == "200" ]]; then
            # Check if response contains user data (basic check)
            local body=$(curl -sS --max-time 5 "$url" 2>/dev/null || echo "")
            if echo "$body" | grep -qiE "(username|login|email|name.*user)" || true; then
                vulnerable+=("$endpoint (HTTP 200)")
            fi
        fi
    done
    
    if [[ ${#vulnerable[@]} -eq 0 ]]; then
        echo "PASS|No user enumeration endpoints found (checked $checked paths)|User enumeration prevented|INFO|"
    elif [[ ${#vulnerable[@]} -eq 1 ]]; then
        echo "WARN|User enumeration possible via: ${vulnerable[0]}|User enumeration prevented|MEDIUM|SEC-ENUM-001"
    else
        local vuln_str=$(IFS=", "; echo "${vulnerable[*]}")
        echo "FAIL|${#vulnerable[@]} enumeration vectors found: $vuln_str|User enumeration prevented|HIGH|SEC-ENUM-002"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking user enumeration vectors for $TARGET"
    
    OUTPUT_DIR="$OUT/step3"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/user_enumeration.json"
    
    # Run check
    result=$(check_user_enumeration "$TARGET")
    
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
        echo "    {\"name\":\"User Enumeration Check\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "User enumeration check complete"
done
