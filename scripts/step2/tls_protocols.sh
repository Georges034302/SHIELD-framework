#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step2_tls_protocols"

# Check for legacy TLS protocol support
check_tls_protocols() {
    local target="$1"
    
    # Extract hostname and port
    local hostname=$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##' | sed 's/:.*$//')
    local port="443"
    
    local issues=()
    local severity="INFO"
    
    # Check TLS 1.0
    if timeout 5 openssl s_client -connect "$hostname:$port" -tls1 </dev/null 2>&1 | grep -q "Cipher" || true; then
        issues+=("TLS 1.0 supported (deprecated)")
        severity="HIGH"
    fi
    
    # Check TLS 1.1
    if timeout 5 openssl s_client -connect "$hostname:$port" -tls1_1 </dev/null 2>&1 | grep -q "Cipher" || true; then
        issues+=("TLS 1.1 supported (deprecated)")
        [[ "$severity" == "INFO" ]] && severity="HIGH"
    fi
    
    # Check TLS 1.2 (should be supported)
    local tls12_supported=false
    if timeout 5 openssl s_client -connect "$hostname:$port" -tls1_2 </dev/null 2>&1 | grep -q "Cipher" || true; then
        tls12_supported=true
    fi
    
    # Check TLS 1.3 (recommended)
    local tls13_supported=false
    if timeout 5 openssl s_client -connect "$hostname:$port" -tls1_3 </dev/null 2>&1 | grep -q "Cipher" || true; then
        tls13_supported=true
    fi
    
    if [[ ${#issues[@]} -eq 0 ]]; then
        if [[ "$tls13_supported" == true ]] && [[ "$tls12_supported" == true ]]; then
            echo "PASS|TLS 1.2 and 1.3 supported, legacy protocols disabled|TLS 1.2+ only|INFO|"
        elif [[ "$tls12_supported" == true ]]; then
            echo "WARN|TLS 1.2 only (TLS 1.3 recommended)|TLS 1.2 and 1.3|LOW|SEC-TLS-002"
        else
            echo "FAIL|No modern TLS protocols detected|TLS 1.2+ support|HIGH|SEC-TLS-003"
        fi
    else
        local issues_str=$(IFS=", "; echo "${issues[*]}")
        echo "FAIL|$issues_str|TLS 1.2+ only|$severity|SEC-TLS-001"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking TLS protocol versions for $TARGET"
    
    OUTPUT_DIR="$OUT/step2"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/tls_protocols.json"
    
    # Run check
    result=$(check_tls_protocols "$TARGET")
    
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
        echo "    {\"name\":\"TLS Protocol Versions\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "TLS protocol check complete"
done
