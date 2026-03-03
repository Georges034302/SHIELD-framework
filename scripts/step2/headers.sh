#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

# Step 2: Security Headers Check
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"
source "$SCRIPT_DIR/lib/http.sh"
source "$SCRIPT_DIR/lib/checks.sh"

STEP_NAME="step2_headers"

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

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking security headers for $TARGET"
    
    # Fetch headers
    HEADERS=$(fetch_headers "$TARGET")
    
    if [ -z "$HEADERS" ]; then
        print_status "FAIL" "Could not fetch headers from $TARGET"
        continue
    fi
    
    # Array to store check results
    CHECKS=()
    
    # 1. HSTS Check
    print_status "INFO" "  Checking Strict-Transport-Security..."
    result=$(check_hsts "$HEADERS")
    IFS='|' read -r status found expected <<< "$result"
    
    if [ "$status" = "PASS" ]; then
        severity="INFO"
        remediation_id=""
        print_status "PASS" "    HSTS header found and valid"
    elif [ "$status" = "WARN" ]; then
        severity="MEDIUM"
        remediation_id="SEC-HSTS-001"
        print_status "WARN" "    HSTS max-age too low"
    else
        severity="HIGH"
        remediation_id="SEC-HSTS-001"
        print_status "FAIL" "    HSTS header missing"
    fi
    
    found_esc=$(json_escape "$found")
    expected_esc=$(json_escape "$expected")
    CHECKS+=("{\"name\":\"Strict-Transport-Security\",\"status\":\"$status\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity\",\"remediation_id\":\"$remediation_id\"}")
    
    # 2. Clickjacking Protection
    print_status "INFO" "  Checking clickjacking protection..."
    result=$(check_clickjacking "$HEADERS")
    IFS='|' read -r status found expected <<< "$result"
    
    if [ "$status" = "PASS" ]; then
        severity="INFO"
        remediation_id=""
        print_status "PASS" "    Clickjacking protection found"
    else
        severity="MEDIUM"
        remediation_id="SEC-FRAME-001"
        print_status "FAIL" "    Clickjacking protection missing"
    fi
    
    found_esc=$(json_escape "$found")
    expected_esc=$(json_escape "$expected")
    CHECKS+=("{\"name\":\"Clickjacking Protection\",\"status\":\"$status\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity\",\"remediation_id\":\"$remediation_id\"}")
    
    # 3. Content-Type-Options
    print_status "INFO" "  Checking X-Content-Type-Options..."
    result=$(check_content_type_options "$HEADERS")
    IFS='|' read -r status found expected <<< "$result"
    
    if [ "$status" = "PASS" ]; then
        severity="INFO"
        remediation_id=""
        print_status "PASS" "    X-Content-Type-Options: nosniff found"
    else
        severity="LOW"
        remediation_id="SEC-XCTO-001"
        print_status "FAIL" "    X-Content-Type-Options missing"
    fi
    
    found_esc=$(json_escape "$found")
    expected_esc=$(json_escape "$expected")
    CHECKS+=("{\"name\":\"X-Content-Type-Options\",\"status\":\"$status\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity\",\"remediation_id\":\"$remediation_id\"}")
    
    # 4. Referrer-Policy
    print_status "INFO" "  Checking Referrer-Policy..."
    result=$(check_referrer_policy "$HEADERS")
    IFS='|' read -r status found expected <<< "$result"
    
    if [ "$status" = "PASS" ]; then
        severity="INFO"
        remediation_id=""
        print_status "PASS" "    Referrer-Policy found and restrictive"
    elif [ "$status" = "WARN" ]; then
        severity="LOW"
        remediation_id="SEC-RP-001"
        print_status "WARN" "    Referrer-Policy could be stricter"
    else
        severity="LOW"
        remediation_id="SEC-RP-001"
        print_status "WARN" "    Referrer-Policy missing"
    fi
    
    found_esc=$(json_escape "$found")
    expected_esc=$(json_escape "$expected")
    CHECKS+=("{\"name\":\"Referrer-Policy\",\"status\":\"$status\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity\",\"remediation_id\":\"$remediation_id\"}")
    
    # Write JSON report
    OUTPUT_DIR="$OUT/step2"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/headers.json"
    
    {
        echo "{"
        echo "  \"step\": \"$STEP_NAME\","
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"target\": \"$TARGET\","
        echo "  \"checks\": ["
        
        first=true
        for check in "${CHECKS[@]}"; do
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
    } > "$OUTPUT_FILE"
    
    print_status "INFO" "Report written to $OUTPUT_FILE"
done
