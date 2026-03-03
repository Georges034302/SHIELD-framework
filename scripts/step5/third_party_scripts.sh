#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step5_third_party_scripts"

# Analyze third-party script domains loaded on the page
check_third_party_scripts() {
    local target="$1"
    local hostname
    hostname=$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##')

    # Fetch page HTML
    local html
    html=$(curl -sS -L --max-time "${TIMEOUT:-10}" "$target" 2>/dev/null || echo "")

    if [[ -z "$html" ]]; then
        echo "WARN|Could not fetch page HTML for third-party script analysis|Third-party scripts inventoried and reviewed|LOW|SEC-3P-001"
        return
    fi

    local issues=()
    local third_party_domains=()
    local high_risk_domains=()
    local severity="INFO"

    # Extract all script src attributes
    while IFS= read -r src; do
        [[ -z "$src" ]] && continue
        # Extract domain from src URL
        local domain
        domain=$(echo "$src" | sed -E 's#https?://##' | sed 's#/.*##' | sed 's/:.*$//')
        [[ -z "$domain" ]] && continue
        # Skip same-origin and relative
        if [[ "$domain" == "$hostname" ]] || [[ "$src" == /* ]] || [[ "$src" != http* ]]; then
            continue
        fi
        third_party_domains+=("$domain")
    done < <(echo "$html" | grep -ioP 'src=["'"'"'][^"'"'"']+["'"'"']' | sed "s/src=['\"]//;s/['\"]//g")

    # Deduplicate
    local unique_domains
    unique_domains=($(printf '%s\n' "${third_party_domains[@]}" | sort -u))

    local count="${#unique_domains[@]}"

    # Flag known high-risk / tracking patterns
    for domain in "${unique_domains[@]}"; do
        if echo "$domain" | grep -qiE "doubleclick|googlesyndication|googleadservices|adnxs|amazon-adsystem|taboola|outbrain|scorecardresearch|criteo|quantserve|chartbeat|hotjar|mouseflow|fullstory"; then
            high_risk_domains+=("$domain (advertising/tracking)")
        fi
    done

    if [[ "$count" -eq 0 ]]; then
        echo "PASS|No external third-party scripts detected|Third-party scripts minimized|INFO|"
        return
    fi

    local domains_str
    domains_str=$(IFS=", "; printf '%s' "${unique_domains[@]}")

    if [[ ${#high_risk_domains[@]} -gt 0 ]]; then
        local risk_str
        risk_str=$(IFS=", "; printf '%s' "${high_risk_domains[@]}")
        issues+=("$count third-party script domains ($count total); high-risk domains: $risk_str")
        severity="MEDIUM"
    elif [[ "$count" -gt 10 ]]; then
        issues+=("$count third-party script domains loaded (high supply chain risk): $domains_str")
        severity="MEDIUM"
    elif [[ "$count" -gt 5 ]]; then
        issues+=("$count third-party script domains loaded: $domains_str")
        severity="LOW"
    else
        echo "PASS|$count third-party script domains loaded: $domains_str|Third-party scripts inventoried with SRI|INFO|"
        return
    fi

    local issues_str
    issues_str=$(IFS="; "; printf '%s' "${issues[*]}")

    if [[ "$severity" == "MEDIUM" ]]; then
        echo "WARN|$issues_str|Audit third-party scripts; use SRI; minimize external dependencies|$severity|SEC-3P-002"
    else
        echo "WARN|$issues_str|Inventory and review all third-party script dependencies|$severity|SEC-3P-001"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Analyzing third-party scripts for $TARGET"

    OUTPUT_DIR="$OUT/step5"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/third_party_scripts.json"

    result=$(check_third_party_scripts "$TARGET")

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
        echo "    {\"name\":\"Third-Party Script Analysis\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "Third-party script check complete"
done
