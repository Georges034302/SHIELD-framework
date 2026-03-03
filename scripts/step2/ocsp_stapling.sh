#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step2_ocsp_stapling"

# Check OCSP stapling status on the TLS certificate
check_ocsp_stapling() {
    local target="$1"
    local hostname
    hostname=$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##' | sed 's/:.*$//')
    local port="443"

    # Query TLS handshake for OCSP staple
    local tls_output
    tls_output=$(echo "" | timeout "${TIMEOUT:-10}" openssl s_client \
        -connect "$hostname:$port" \
        -status \
        -servername "$hostname" 2>/dev/null || echo "")

    if [[ -z "$tls_output" ]]; then
        echo "WARN|Could not establish TLS connection to $hostname:$port|OCSP stapling enabled|LOW|SEC-OCSP-001"
        return
    fi

    # Check if OCSP staple response is present
    if echo "$tls_output" | grep -q "OCSP Response Status: successful"; then
        echo "PASS|OCSP stapling enabled and response is valid|OCSP stapling enabled|INFO|"
        return
    fi

    if echo "$tls_output" | grep -qi "OCSP response: no response sent"; then
        echo "WARN|OCSP stapling not enabled on this server|OCSP stapling enabled|LOW|SEC-OCSP-001"
        return
    fi

    if echo "$tls_output" | grep -qi "OCSP Response Status: revoked"; then
        echo "FAIL|Certificate is REVOKED (OCSP response indicates revocation)|Valid non-revoked certificate|CRITICAL|SEC-OCSP-002"
        return
    fi

    # Could not determine OCSP status
    echo "WARN|OCSP stapling status indeterminate (may not be supported)|OCSP stapling enabled|LOW|SEC-OCSP-001"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking OCSP stapling for $TARGET"

    OUTPUT_DIR="$OUT/step2"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/ocsp_stapling.json"

    result=$(check_ocsp_stapling "$TARGET")

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
        echo "    {\"name\":\"OCSP Stapling\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "OCSP stapling check complete"
done
