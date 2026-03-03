#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

# Step 2: HTTPS Enforcement Check
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step2_https"

json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/}"
    echo -n "$str"
}

check_https_enforcement() {
    local target="$1"
    
    # Skip if already HTTPS
    if [[ "$target" == https://* ]]; then
        # Convert to HTTP and test redirect
        local http_url="${target/https:/http:}"
        local response=$(curl -sI -L --max-time "${TIMEOUT:-10}" "$http_url" 2>/dev/null || echo "")
        
        if echo "$response" | grep -qi "HTTP.*301\|HTTP.*302\|HTTP.*307\|HTTP.*308"; then
            local location=$(echo "$response" | grep -i "^Location:" | head -1 | cut -d' ' -f2- | tr -d '\r')
            if [[ "$location" == https://* ]]; then
                echo "PASS|HTTP redirects to HTTPS (301/302/307/308)|Automatic HTTPS redirect|INFO|"
            else
                echo "WARN|HTTP redirects but not to HTTPS: $location|HTTPS redirect|MEDIUM|SEC-HTTPS-001"
            fi
        else
            # Check if final response is HTTPS
            if echo "$response" | tail -5 | grep -q "HTTP"; then
                echo "WARN|HTTP accessible without redirect to HTTPS|HTTPS redirect enforced|HIGH|SEC-HTTPS-001"
            else
                echo "PASS|Target serves HTTPS|HTTPS enabled|INFO|"
            fi
        fi
    else
        # Target is HTTP - check if it redirects
        local response=$(curl -sI -L --max-time "${TIMEOUT:-10}" "$target" 2>/dev/null || echo "")
        if echo "$response" | grep -qi "location:.*https://"; then
            echo "PASS|HTTP redirects to HTTPS|HTTPS redirect enabled|INFO|"
        else
            echo "FAIL|HTTP does not redirect to HTTPS|HTTPS redirect required|HIGH|SEC-HTTPS-001"
        fi
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking HTTPS enforcement for $TARGET"
    
    OUTPUT_DIR="$OUT/step2"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/https.json"
    
    # Run check
    result=$(check_https_enforcement "$TARGET" || echo "FAIL|Check failed|HTTPS redirect|MEDIUM|SEC-HTTPS-001")
    IFS='|' read -r status found expected severity remediation_id <<< "$result"
    
    # Escape for JSON
    status_esc=$(json_escape "$status")
    found_esc=$(json_escape "$found")
    expected_esc=$(json_escape "$expected")
    severity_esc=$(json_escape "$severity")
    remediation_id_esc=$(json_escape "$remediation_id")
    
    # Write JSON
    {
        echo "{"
        echo "  \"step\": \"$STEP_NAME\","
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"target\": \"$TARGET\","
        echo "  \"checks\": ["
        echo "    {\"name\":\"HTTPS Enforcement\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
       echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "HTTPS: $found"
    print_status "INFO" "Report written to $OUTPUT_FILE"
done
