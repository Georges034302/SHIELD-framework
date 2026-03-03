#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"
source "$SCRIPT_DIR/lib/http.sh"

STEP_NAME="step2_csp_quality"

# Check Content Security Policy quality
check_csp_quality() {
    local target="$1"
    local headers=$(fetch_headers "$target")
    local csp=$(get_header "$headers" "Content-Security-Policy")
    
    if [[ -z "$csp" ]]; then
        echo "FAIL|CSP header missing|Strict Content Security Policy|MEDIUM|SEC-CSP-001"
        return
    fi
    
    local issues=()
    
    # Check for dangerous patterns
    if echo "$csp" | grep -qi "unsafe-inline" || true; then
        issues+=("'unsafe-inline' allows inline scripts")
    fi
    
    if echo "$csp" | grep -qi "unsafe-eval" || true; then
        issues+=("'unsafe-eval' allows eval()")
    fi
    
    # Check for wildcard in script-src or default-src
    if echo "$csp" | grep -qE "(script-src|default-src)[^;]*\*" || true; then
        issues+=("wildcard (*) in script sources")
    fi
    
    # Check if default-src is present
    if ! echo "$csp" | grep -qi "default-src" || true; then
        issues+=("missing 'default-src' fallback")
    fi
    
    # Check for data: URIs in script-src
    if echo "$csp" | grep -qE "script-src[^;]*data:" || true; then
        issues+=("'data:' URIs allowed in scripts")
    fi
    
    if [[ ${#issues[@]} -eq 0 ]]; then
        echo "PASS|CSP well configured|Strict CSP without unsafe directives|INFO|"
    elif [[ ${#issues[@]} -eq 1 ]]; then
        echo "WARN|CSP: ${issues[0]}|Strict CSP without unsafe directives|LOW|SEC-CSP-002"
    else
        local issues_str=$(IFS=", "; echo "${issues[*]}")
        echo "WARN|CSP has ${#issues[@]} issues: $issues_str|Strict CSP without unsafe directives|MEDIUM|SEC-CSP-003"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking CSP quality for $TARGET"
    
    OUTPUT_DIR="$OUT/step2"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/csp_quality.json"
    
    # Run check
    result=$(check_csp_quality "$TARGET")
    
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
        echo "    {\"name\":\"CSP Quality Analysis\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "CSP quality check complete"
done
