#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

# Step 3: Authentication Endpoint Discovery
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"
source "$SCRIPT_DIR/lib/wp_detect.sh"

STEP_NAME="step3_discover"

json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/}"
    echo -n "$str"
}

discover_auth_endpoints() {
    local target="$1"
    local base_url=$(echo "$target" | sed 's|/$||')
    
    local found_endpoints=()
    
    # Check if WordPress
    local is_wp=$(detect_wordpress "$target")
    
    if [[ "$is_wp" == "true" ]]; then
        # WordPress endpoints
        local login_check=$(curl -sI --max-time "${TIMEOUT:-10}" "$base_url/wp-login.php" 2>/dev/null | head -1)
        [[ "$login_check" =~ "200" ]] && found_endpoints+=("/wp-login.php")
        
        local admin_check=$(curl -sI --max-time "${TIMEOUT:-10}" "$base_url/wp-admin/" 2>/dev/null | head -1)
        [[ "$admin_check" =~ "200"|"302"|"301" ]] && found_endpoints+=("/wp-admin/")
        
        local xmlrpc_check=$(curl -sI --max-time "${TIMEOUT:-10}" "$base_url/xmlrpc.php" 2>/dev/null | head -1)
        [[ "$xmlrpc_check" =~ "200"|"405" ]] && found_endpoints+=("/xmlrpc.php")
    fi
    
    # Common login paths
    for path in "/login" "/signin" "/admin" "/admin/login" "/user/login" "/account/login"; do
        local check=$(curl -sI --max-time "${TIMEOUT:-5}" "$base_url$path" 2>/dev/null | head -1)
        [[ "$check" =~ "200" ]] && found_endpoints+=("$path")
    done
    
    if [[ ${#found_endpoints[@]} -gt 0 ]]; then
        local endpoints_str=$(IFS=", "; echo "${found_endpoints[*]}")
        echo "PASS|Found auth endpoints: $endpoints_str|Login/logout endpoints identified|INFO|"
    else
        echo "SKIP|No standard auth endpoints found|Login/logout endpoints identified|INFO|"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Discovering authentication endpoints for $TARGET"
    
    OUTPUT_DIR="$OUT/step3"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/discover.json"
    
    # Run check
    result=$(discover_auth_endpoints "$TARGET" || echo "SKIP|Discovery failed|Endpoints identified|INFO|")
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
        echo "    {\"name\":\"Authentication Endpoint Discovery\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "Discovery: $found"
    print_status "INFO" "Report written to $OUTPUT_FILE"
done
