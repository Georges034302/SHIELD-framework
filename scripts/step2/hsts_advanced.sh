#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"
source "$SCRIPT_DIR/lib/http.sh"

STEP_NAME="step2_hsts_advanced"

# Advanced HSTS check (includeSubDomains, preload)
check_hsts_advanced() {
    local target="$1"
    local headers=$(fetch_headers "$target")
    local hsts=$(get_header "$headers" "Strict-Transport-Security")
    
    if [[ -z "$hsts" ]]; then
        echo "FAIL|HSTS header missing|HSTS with includeSubDomains and preload|HIGH|SEC-HSTS-001"
        return
    fi
    
    local issues=()
    
    # Check max-age
    if echo "$hsts" | grep -qE "max-age=([0-9]+)" || true; then
        local max_age=$(echo "$hsts" | grep -oE "max-age=([0-9]+)" | grep -oE "[0-9]+" || echo "0")
        if [[ "$max_age" -lt 31536000 ]]; then
            issues+=("max-age too low ($max_age < 31536000)")
        fi
    else
        issues+=("max-age missing")
    fi
    
    # Check includeSubDomains
    if ! echo "$hsts" | grep -qi "includeSubDomains" || true; then
        issues+=("includeSubDomains missing")
    fi
    
    # Check preload (optional but recommended)
    local has_preload=false
    if echo "$hsts" | grep -qi "preload" || true; then
        has_preload=true
    fi
    
    if [[ ${#issues[@]} -eq 0 ]]; then
        if [[ "$has_preload" == true ]]; then
            echo "PASS|HSTS fully configured with preload|Complete HSTS configuration|INFO|"
        else
            echo "WARN|HSTS good but missing 'preload'|HSTS with preload directive|LOW|SEC-HSTS-002"
        fi
    elif [[ ${#issues[@]} -eq 1 ]] && [[ "$has_preload" == false ]]; then
        echo "WARN|HSTS: ${issues[*]}|HSTS with includeSubDomains and preload|LOW|SEC-HSTS-002"
    else
        echo "WARN|HSTS: ${issues[*]}|HSTS with includeSubDomains and preload|MEDIUM|SEC-HSTS-003"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking advanced HSTS configuration for $TARGET"
    
    OUTPUT_DIR="$OUT/step2"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/hsts_advanced.json"
    
    # Run check
    result=$(check_hsts_advanced "$TARGET")
    
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
        echo "    {\"name\":\"Advanced HSTS Configuration\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "Advanced HSTS check complete"
done
