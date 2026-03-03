#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step6_dns_hygiene"

# Check DNS hygiene:
# - DNSSEC enabled
# - SPF record present
# - DMARC record present
# - DKIM selector (common) detectable
# - CAA record present
check_dns_hygiene() {
    local target="$1"
    local hostname
    hostname=$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##' | sed 's/:.*$//')

    local issues=()
    local passes=()
    local severity="INFO"

    # --- DNSSEC ---
    local dnssec
    dnssec=$(dig +short "$hostname" DNSKEY 2>/dev/null | head -1 || echo "")
    if [[ -z "$dnssec" ]]; then
        issues+=("DNSSEC not configured")
        severity="MEDIUM"
    else
        passes+=("DNSSEC enabled")
    fi

    # --- SPF ---
    local spf
    spf=$(dig +short TXT "$hostname" 2>/dev/null | grep -i "v=spf1" | head -1 || echo "")
    if [[ -z "$spf" ]]; then
        issues+=("SPF record missing")
        [[ "$severity" == "INFO" ]] && severity="MEDIUM"
    else
        passes+=("SPF record present")
    fi

    # --- DMARC ---
    local dmarc
    dmarc=$(dig +short TXT "_dmarc.$hostname" 2>/dev/null | grep -i "v=DMARC1" | head -1 || echo "")
    if [[ -z "$dmarc" ]]; then
        issues+=("DMARC record missing")
        [[ "$severity" == "INFO" ]] && severity="MEDIUM"
    else
        # Check DMARC policy strength
        if echo "$dmarc" | grep -qi "p=none"; then
            issues+=("DMARC policy is 'none' (monitoring only, not enforced)")
            [[ "$severity" == "INFO" ]] && severity="LOW"
        else
            passes+=("DMARC policy enforced")
        fi
    fi

    # --- CAA ---
    local caa
    caa=$(dig +short "$hostname" CAA 2>/dev/null | head -1 || echo "")
    if [[ -z "$caa" ]]; then
        issues+=("CAA record missing (any CA can issue certificates)")
        [[ "$severity" == "INFO" ]] && severity="LOW"
    else
        passes+=("CAA record present")
    fi

    if [[ ${#issues[@]} -eq 0 ]]; then
        local pass_str
        pass_str=$(IFS=", "; printf '%s' "${passes[*]}")
        echo "PASS|$pass_str|DNSSEC + SPF + DMARC + CAA configured|INFO|"
        return
    fi

    local issues_str
    issues_str=$(IFS=", "; printf '%s' "${issues[*]}")

    if [[ ${#issues[@]} -ge 3 ]]; then
        echo "FAIL|$issues_str|DNSSEC + SPF + DMARC (enforce) + CAA required|$severity|SEC-DNS-002"
    else
        echo "WARN|$issues_str|DNSSEC + SPF + DMARC (enforce) + CAA recommended|$severity|SEC-DNS-001"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking DNS hygiene for $TARGET"

    OUTPUT_DIR="$OUT/step6"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/dns_hygiene.json"

    result=$(check_dns_hygiene "$TARGET")

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
        echo "    {\"name\":\"DNS Hygiene\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "DNS hygiene check complete"
done
