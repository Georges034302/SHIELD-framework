#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

# SHIELD - File Editor Access Check
# PURPOSE: Check if theme/plugin editors are accessible (requires authentication)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step4_file_editors_auth"

for TARGET in "${ARGS[@]}"; do
    OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/file_editors_auth.json"
    cookies_file="$OUT/.session_cookies"
    
    # Skip if not authenticated
    if [[ ! -f "$cookies_file" ]]; then
        print_status "INFO" "File editor check skipped (not authenticated)"
        {
            echo "{"
            echo "  \"step\": \"$STEP_NAME\","
            echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
            echo "  \"target\": \"$TARGET\","
            echo "  \"checks\": ["
            echo "    {\"name\":\"File Editor Check\",\"status\":\"SKIP\",\"found\":\"Not authenticated\",\"expected\":\"Provide credentials with --user and --pass\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
            echo "  ]"
            echo "}"
        } > "$OUTPUT_FILE"
        continue
    fi
    
    print_status "INFO" "Checking file editor access (authenticated): $TARGET"
    
    base_url="${TARGET%/}"
    theme_editor_url="${base_url}/wp-admin/theme-editor.php"
    plugin_editor_url="${base_url}/wp-admin/plugin-editor.php"
    
    checks=()
    
    # Check theme editor
    theme_editor_response=$(curl -sS --max-time "${TIMEOUT:-10}" \
        -b "$cookies_file" \
        -w "\n%{http_code}" \
        "$theme_editor_url" 2>/dev/null)
    
    theme_code=$(echo "$theme_editor_response" | tail -n1)
    theme_body=$(echo "$theme_editor_response" | sed '$d')
    
    if [[ "$theme_code" == "200" ]] && echo "$theme_body" | grep -q "theme-editor\|editing"; then
        checks+=("FAIL|Theme editor is accessible and functional|Disable theme editor (define('DISALLOW_FILE_EDIT', true) in wp-config.php)|HIGH|SEC-EDIT-001")
        print_status "FAIL" "Theme editor is accessible"
    elif echo "$theme_body" | grep -qi "error\|disabled\|denied"; then
        checks+=("PASS|Theme editor is disabled|N/A|INFO|")
        print_status "PASS" "Theme editor is disabled"
    else
        checks+=("WARN|Theme editor returned HTTP $theme_code|Verify editor configuration|MEDIUM|SEC-EDIT-001")
    fi
    
    # Check plugin editor
    plugin_editor_response=$(curl -sS --max-time "${TIMEOUT:-10}" \
        -b "$cookies_file" \
        -w "\n%{http_code}" \
        "$plugin_editor_url" 2>/dev/null)
    
    plugin_code=$(echo "$plugin_editor_response" | tail -n1)
    plugin_body=$(echo "$plugin_editor_response" | sed '$d')
    
    if [[ "$plugin_code" == "200" ]] && echo "$plugin_body" | grep -q "plugin-editor\|editing"; then
        checks+=("FAIL|Plugin editor is accessible and functional|Disable plugin editor (define('DISALLOW_FILE_EDIT', true) in wp-config.php)|HIGH|SEC-EDIT-002")
        print_status "FAIL" "Plugin editor is accessible"
    elif echo "$plugin_body" | grep -qi "error\|disabled\|denied"; then
        checks+=("PASS|Plugin editor is disabled|N/A|INFO|")
        print_status "PASS" "Plugin editor is disabled"
    else
        checks+=("WARN|Plugin editor returned HTTP $plugin_code|Verify editor configuration|MEDIUM|SEC-EDIT-002")
    fi
    
    # Write JSON output
    {
        echo "{"
        echo "  \"step\": \"$STEP_NAME\","
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"target\": \"$TARGET\","
        echo "  \"checks\": ["
        
        for i in "${!checks[@]}"; do
            IFS='|' read -r status found expected severity remediation_id <<< "${checks[$i]}"
            echo "    {\"name\":\"File Editor Access\",\"status\":\"$status\",\"found\":\"$found\",\"expected\":\"$expected\",\"severity\":\"$severity\",\"remediation_id\":\"$remediation_id\"}"
            if [[ $i -lt $((${#checks[@]} - 1)) ]]; then echo ","; fi
        done
        
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
done
