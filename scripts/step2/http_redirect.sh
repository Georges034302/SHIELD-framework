#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"
source "$SCRIPT_DIR/lib/http.sh"

STEP_NAME="step2_http_redirect"

# Check HTTP to HTTPS redirect quality
check_http_redirect() {
    local target="$1"
    local http_url="${target/https:/http:}"
    
    # Try HTTP version
    local response=$(curl -sS -I -L --max-redirects 5 "$http_url" 2>&1 || true)
    
    # Check if we got redirected
    if echo "$response" | grep -qi "HTTP/.*30[18]" || true; then
        local status_code=$(echo "$response" | grep -i "HTTP/" | head -1 | awk '{print $2}')
        local location=$(echo "$response" | grep -i "^Location:" | head -1 | awk '{print $2}' | tr -d '\r' || true)
        
        if [[ "$location" =~ ^https:// ]]; then
            if [[ "$status_code" == "308" ]]; then
                echo "PASS|$status_code permanent redirect to $location|308 permanent redirect|INFO|"
            elif [[ "$status_code" == "301" ]]; then
                echo "WARN|$status_code redirect (308 preferred)|308 permanent redirect|LOW|SEC-REDIR-001"
            else
                echo "WARN|$status_code temporary redirect|308 permanent redirect|MEDIUM|SEC-REDIR-002"
            fi
        else
            echo "FAIL|Redirect to non-HTTPS URL: $location|HTTPS redirect|HIGH|SEC-REDIR-003"
        fi
    else
        echo "FAIL|No HTTPS redirect detected|HTTP→HTTPS redirect|HIGH|SEC-REDIR-004"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking HTTP→HTTPS redirect for $TARGET"
    
    OUTPUT_DIR="$OUT/step2"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/http_redirect.json"
    
    # Run check
    result=$(check_http_redirect "$TARGET")
    
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
        echo "    {\"name\":\"HTTP to HTTPS Redirect\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "HTTP redirect check complete"
done
