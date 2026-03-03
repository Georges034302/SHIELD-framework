#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"
source "$SCRIPT_DIR/lib/http.sh"

STEP_NAME="step2_advanced_headers"

# Check modern security headers
check_advanced_headers() {
    local target="$1"
    local headers=$(fetch_headers "$target")
    
    local missing=()
    local present=()
    
    # Check Permissions-Policy (replaces Feature-Policy)
    local perms_policy=$(get_header "$headers" "Permissions-Policy")
    if [[ -z "$perms_policy" ]]; then
        missing+=("Permissions-Policy")
    else
        present+=("Permissions-Policy")
    fi
    
    # Check Cross-Origin-Opener-Policy
    local coop=$(get_header "$headers" "Cross-Origin-Opener-Policy")
    if [[ -z "$coop" ]]; then
        missing+=("COOP")
    else
        present+=("COOP")
    fi
    
    # Check Cross-Origin-Embedder-Policy
    local coep=$(get_header "$headers" "Cross-Origin-Embedder-Policy")
    if [[ -z "$coep" ]]; then
        missing+=("COEP")
    else
        present+=("COEP")
    fi
    
    # Check Cross-Origin-Resource-Policy
    local corp=$(get_header "$headers" "Cross-Origin-Resource-Policy")
    if [[ -z "$corp" ]]; then
        missing+=("CORP")
    else
        present+=("CORP")
    fi
    
    # Evaluate findings
    if [[ ${#missing[@]} -eq 0 ]]; then
        echo "PASS|All modern headers present: Permissions-Policy, COOP, COEP, CORP|Modern isolation headers|INFO|"
    elif [[ ${#missing[@]} -eq 1 ]]; then
        local missing_str=$(IFS=", "; echo "${missing[*]}")
        echo "WARN|Missing modern header: $missing_str|Modern security headers|LOW|SEC-HEADERS-001"
    elif [[ ${#missing[@]} -eq 2 ]]; then
        local missing_str=$(IFS=", "; echo "${missing[*]}")
        echo "WARN|Missing modern headers: $missing_str|Modern security headers|LOW|SEC-HEADERS-002"
    else
        local missing_str=$(IFS=", "; echo "${missing[*]}")
        echo "WARN|${#missing[@]} modern headers missing: $missing_str|Modern security headers|MEDIUM|SEC-HEADERS-003"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking advanced security headers for $TARGET"
    
    OUTPUT_DIR="$OUT/step2"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/advanced_headers.json"
    
    # Run check
    result=$(check_advanced_headers "$TARGET")
    
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
        echo "    {\"name\":\"Modern Security Headers\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "Advanced headers check complete"
done
