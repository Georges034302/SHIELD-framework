#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

# SHIELD - WordPress Authentication
# PURPOSE: Authenticate to WordPress and establish session for authenticated tests
# Only runs if --user and --pass are provided

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step1_authenticate"

for TARGET in "${ARGS[@]}"; do
    OUTPUT_DIR="$OUT/step1"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/authenticate.json"
    
    # Skip if no credentials provided
    if [[ -z "${WP_USER:-}" ]] || [[ -z "${WP_PASS:-}" ]]; then
        print_status "INFO" "Authentication skipped (no credentials provided)"
        {
            echo "{"
            echo "  \"step\": \"$STEP_NAME\","
            echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
            echo "  \"target\": \"$TARGET\","
            echo "  \"checks\": ["
            echo "    {\"name\":\"Authentication\",\"status\":\"SKIP\",\"found\":\"No credentials provided\",\"expected\":\"Run with --user and --pass for authenticated tests\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
            echo "  ]"
            echo "}"
        } > "$OUTPUT_FILE"
        continue
    fi
    
    print_status "INFO" "Attempting WordPress authentication: $TARGET"
    
    base_url="${TARGET%/}"
    login_url="${base_url}/wp-login.php"
    admin_url="${base_url}/wp-admin/"
    cookies_file="$OUT/.session_cookies"
    
    # URL-encode password
    encoded_pass=$(printf '%s' "$WP_PASS" | jq -sRr @uri)
    
    # Attempt login
    login_response=$(curl -sS --max-time "${TIMEOUT:-10}" \
        -c "$cookies_file" \
        -L \
        -d "log=${WP_USER}&pwd=${encoded_pass}&wp-submit=Log+In&redirect_to=${admin_url}&testcookie=1" \
        -w "\n%{http_code}" \
        "$login_url" 2>/dev/null)
    
    http_code=$(echo "$login_response" | tail -n1)
    
    # Check if we got valid cookies
    if [[ -f "$cookies_file" ]] && grep -q "wordpress_logged_in" "$cookies_file" 2>/dev/null; then
        # Verify admin access
        admin_check=$(curl -sS --max-time "${TIMEOUT:-10}" \
            -b "$cookies_file" \
            -w "%{http_code}" \
            -o /dev/null \
            "$admin_url" 2>/dev/null)
        
        if [[ "$admin_check" == "200" ]]; then
            print_status "PASS" "Authentication successful"
            export AUTHENTICATED=true
            
            {
                echo "{"
                echo "  \"step\": \"$STEP_NAME\","
                echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
                echo "  \"target\": \"$TARGET\","
                echo "  \"checks\": ["
                echo "    {\"name\":\"Authentication\",\"status\":\"PASS\",\"found\":\"Successfully authenticated as ${WP_USER}\",\"expected\":\"N/A\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
                echo "  ]"
                echo "}"
            } > "$OUTPUT_FILE"
        else
            print_status "FAIL" "Authentication failed: admin access denied (HTTP $admin_check)"
            rm -f "$cookies_file"
            
            {
                echo "{"
                echo "  \"step\": \"$STEP_NAME\","
                echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
                echo "  \"target\": \"$TARGET\","
                echo "  \"checks\": ["
                echo "    {\"name\":\"Authentication\",\"status\":\"FAIL\",\"found\":\"Login succeeded but admin access denied (HTTP $admin_check)\",\"expected\":\"Valid admin credentials\",\"severity\":\"HIGH\",\"remediation_id\":\"\"}"
                echo "  ]"
                echo "}"
            } > "$OUTPUT_FILE"
        fi
    else
        print_status "FAIL" "Authentication failed: invalid credentials"
        rm -f "$cookies_file"
        
        {
            echo "{"
            echo "  \"step\": \"$STEP_NAME\","
            echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
            echo "  \"target\": \"$TARGET\","
            echo "  \"checks\": ["
            echo "    {\"name\":\"Authentication\",\"status\":\"FAIL\",\"found\":\"Login failed - invalid username or password\",\"expected\":\"Valid admin credentials\",\"severity\":\"HIGH\",\"remediation_id\":\"\"}"
            echo "  ]"
            echo "}"
        } > "$OUTPUT_FILE"
    fi
done
