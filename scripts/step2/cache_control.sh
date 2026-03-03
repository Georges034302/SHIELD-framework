#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"
source "$SCRIPT_DIR/lib/http.sh"

STEP_NAME="step2_cache_control"

# Sensitive paths that should not be cached
SENSITIVE_PATHS=(
    "login"
    "admin"
    "account"
    "profile"
    "settings"
    "checkout"
    "payment"
    "auth"
)

# Check Cache-Control on sensitive paths
check_cache_control() {
    local target="$1"
    local base_url="${target%/}"
    
    local issues=()
    local checked=0
    
    for path in "${SENSITIVE_PATHS[@]}"; do
        local url="$base_url/$path"
        local headers=$(curl -sS -I --max-time 5 "$url" 2>/dev/null || echo "")
        
        if [[ -n "$headers" ]]; then
            local status_code=$(echo "$headers" | grep -i "HTTP/" | head -1 | awk '{print $2}' || echo "000")
            
            # Only check if the path exists (200, 301, 302)
            if [[ "$status_code" =~ ^(200|301|302)$ ]]; then
                checked=$((checked + 1))
                local cache_control=$(echo "$headers" | grep -i "^Cache-Control:" | head -1 | sed 's/^Cache-Control: *//i' | tr -d '\r' || echo "")
                
                # Check if no-store is present
                if [[ ! "$cache_control" =~ no-store ]]; then
                    issues+=("/$path missing 'no-store'")
                fi
            fi
        fi
    done
    
    if [[ $checked -eq 0 ]]; then
        echo "INFO|No sensitive paths found to check|Cache-Control on auth paths|INFO|"
    elif [[ ${#issues[@]} -eq 0 ]]; then
        echo "PASS|All $checked sensitive path(s) properly protected with no-store|Cache-Control: no-store|INFO|"
    elif [[ ${#issues[@]} -eq 1 ]]; then
        echo "WARN|${issues[0]}|Cache-Control: no-store on auth paths|LOW|SEC-CACHE-001"
    else
        local issues_str=$(IFS=", "; echo "${issues[*]}")
        echo "WARN|${#issues[@]} paths without no-store: $issues_str|Cache-Control: no-store on auth paths|MEDIUM|SEC-CACHE-002"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking Cache-Control on sensitive paths for $TARGET"
    
    OUTPUT_DIR="$OUT/step2"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/cache_control.json"
    
    # Run check
    result=$(check_cache_control "$TARGET")
    
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
        echo "    {\"name\":\"Cache-Control on Sensitive Paths\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "Cache-Control check complete"
done
