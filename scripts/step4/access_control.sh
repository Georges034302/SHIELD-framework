#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step4_access_control"

json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/}"
    echo -n "$str"
}

# Paths that should require authentication
PROTECTED_PATHS=(
    "wp-admin/index.php"
    "wp-admin/admin.php"
    "wp-admin/users.php"
    "wp-admin/plugins.php"
    "wp-admin/themes.php"
    "wp-admin/options-general.php"
    "wp-admin/profile.php"
    "admin"
    "admin/"
    "admin/config"
    "admin/users"
    "admin/settings"
    "dashboard"
    "dashboard/"
    "api/admin"
    "api/users"
    "api/config"
    "private"
    "account/settings"
    "user/profile"
)

check_access_control() {
    local target="$1"
    local base_url="${target%/}"
    
    local unauthorized_accessible=()
    local properly_protected=()
    local checked=0
    
    for path in "${PROTECTED_PATHS[@]}"; do
        local url="$base_url/$path"
        
        # Make request without authentication
        local response
        response=$(curl -sS -L --max-time "${TIMEOUT:-10}" \
            -w "\nHTTP_CODE:%{http_code}" \
            "$url" 2>/dev/null || echo "HTTP_CODE:000")
        
        local http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
        local body=$(echo "$response" | grep -v "HTTP_CODE:")
        
        checked=$((checked + 1))
        
        # Analyze response
        # 401 Unauthorized / 403 Forbidden = Good (protected)
        # 302/301 redirect to login = Good
        # 404 Not Found = Acceptable (doesn't exist)
        # 200 OK = Bad if it shows admin content
        
        if [[ "$http_code" == "401" ]] || [[ "$http_code" == "403" ]]; then
            properly_protected+=("/$path")
        elif [[ "$http_code" == "302" ]] || [[ "$http_code" == "301" ]]; then
            # Check if redirect goes to login
            local location
            location=$(curl -sS -I --max-time "${TIMEOUT:-10}" "$url" 2>/dev/null | \
                grep -i "^Location:" | cut -d' ' -f2 | tr -d '\r' || echo "")
            
            if echo "$location" | grep -qi "login\|signin\|auth"; then
                properly_protected+=("/$path")
            else
                # Redirect but not to login - suspicious
                unauthorized_accessible+=("/$path (HTTP $http_code, redirect to: $location)")
            fi
        elif [[ "$http_code" == "200" ]]; then
            # Check if the content indicates admin/protected area
            if echo "$body" | grep -qi "dashboard\|administration\|admin panel\|control panel\|users\|settings\|configuration"; then
                unauthorized_accessible+=("/$path (HTTP 200, admin content accessible)")
            elif echo "$body" | grep -qi "login\|sign in\|authentication required"; then
                # Shows login form - acceptable
                properly_protected+=("/$path")
            else
                # 200 but unclear if protected content - check content length
                local content_length=${#body}
                if [[ $content_length -gt 1000 ]]; then
                    unauthorized_accessible+=("/$path (HTTP 200, substantial content returned)")
                fi
            fi
        fi
        # Ignore 404s and other error codes as they indicate path doesn't exist
    done
    
    # Generate report based on findings
    if [[ ${#unauthorized_accessible[@]} -eq 0 ]]; then
        local protected_count=${#properly_protected[@]}
        if [[ $protected_count -gt 0 ]]; then
            echo "PASS|All protected paths properly secured (found $protected_count protected, ${checked} checked)|Proper authorization enforced on sensitive endpoints|INFO|"
        else
            echo "PASS|No unauthorized access detected (checked ${checked} common protected paths)|Proper authorization enforced on sensitive endpoints|INFO|"
        fi
    elif [[ ${#unauthorized_accessible[@]} -eq 1 ]]; then
        echo "FAIL|Unauthorized access possible: ${unauthorized_accessible[0]}|Implement authentication and authorization checks|HIGH|SEC-ACCESS-001"
    elif [[ ${#unauthorized_accessible[@]} -le 3 ]]; then
        local accessible_str=$(IFS="; "; echo "${unauthorized_accessible[*]}")
        echo "FAIL|${#unauthorized_accessible[@]} unauthorized access vectors: $accessible_str|Implement authentication and authorization checks|HIGH|SEC-ACCESS-002"
    else
        echo "FAIL|${#unauthorized_accessible[@]} protected paths accessible without authentication (checked ${checked} paths)|Implement proper authentication and authorization controls|CRITICAL|SEC-ACCESS-003"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking access control for $TARGET"
    
    OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/access_control.json"
    
    result=$(check_access_control "$TARGET")
    IFS='|' read -r status found expected severity remediation_id <<< "$result"

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
        echo "    {\"name\":\"Access Control\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "Access control check complete"
done
