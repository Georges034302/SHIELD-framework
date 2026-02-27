#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step5_sri_check"

# Check Subresource Integrity (SRI) on external scripts and stylesheets
check_sri() {
    local target="$1"
    local hostname
    hostname=$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##')

    # Fetch the HTML page
    local html
    html=$(curl -sS -L --max-time "${TIMEOUT:-10}" "$target" 2>/dev/null || echo "")

    if [[ -z "$html" ]]; then
        echo "WARN|Could not fetch page HTML for SRI analysis|SRI enforced on all external resources|LOW|SEC-SRI-001"
        return
    fi

    # Count external scripts total vs those with SRI
    local total_ext_scripts total_ext_scripts_sri
    total_ext_scripts=$(echo "$html" | grep -ciE '<script[^>]+src=' || true)
    # External scripts: src does not start with / and does not contain hostname
    local ext_scripts_raw
    ext_scripts_raw=$(echo "$html" | grep -iE '<script[^>]+src=' | grep -viE "src=[\"']\s*/" | grep -vF "$hostname" || true)
    local ext_script_count
    ext_script_count=$(echo "$ext_scripts_raw" | grep -c . || true)
    total_ext_scripts_sri=$(echo "$ext_scripts_raw" | grep -ci "integrity=" || true)

    # Count external stylesheets total vs those with SRI
    local ext_links_raw
    ext_links_raw=$(echo "$html" | grep -iE '<link[^>]+href=' | grep -iE "rel=[\"']stylesheet" | grep -viE "href=[\"']\s*/" | grep -vF "$hostname" || true)
    local ext_link_count
    ext_link_count=$(echo "$ext_links_raw" | grep -c . || true)
    local ext_links_sri
    ext_links_sri=$(echo "$ext_links_raw" | grep -ci "integrity=" || true)

    local external_count=$(( ext_script_count + ext_link_count ))
    local sri_present=$(( total_ext_scripts_sri + ext_links_sri ))
    local sri_missing=$(( external_count - sri_present ))

    # Example missing resource for reporting
    local first_missing=""
    first_missing=$(echo "$ext_scripts_raw" | grep -vi "integrity=" | \
        grep -oE "src=[\"'][^\"']*[\"']" | head -1 | sed "s/src=['\"]//;s/['\"]//g" || true)
    if [[ -z "$first_missing" ]]; then
        first_missing=$(echo "$ext_links_raw" | grep -vi "integrity=" | \
            grep -oE "href=[\"'][^\"']*[\"']" | head -1 | sed "s/href=['\"]//;s/['\"]//g" || true)
    fi

    if [[ "$external_count" -eq 0 ]]; then
        echo "PASS|No external scripts or stylesheets detected|SRI not required for inline/same-origin resources|INFO|"
        return
    fi

    if [[ "$sri_missing" -eq 0 ]]; then
        echo "PASS|All $external_count external resources use SRI integrity attributes|SRI enforced on all external resources|INFO|"
        return
    fi

    local severity="MEDIUM"
    [[ "$sri_missing" -ge 3 ]] && severity="HIGH"

    local desc="$sri_missing of $external_count external resources missing SRI"
    [[ -n "$first_missing" ]] && desc="$desc (e.g. $first_missing)"

    if [[ "$sri_missing" -ge 3 ]]; then
        echo "FAIL|$desc|Add integrity + crossorigin attributes to all external resources|$severity|SEC-SRI-002"
    else
        echo "WARN|$desc|Add SRI integrity attributes to external scripts and stylesheets|$severity|SEC-SRI-001"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking Subresource Integrity (SRI) for $TARGET"

    OUTPUT_DIR="$OUT/step5"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/sri_check.json"

    result=$(check_sri "$TARGET")

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
        echo "    {\"name\":\"Subresource Integrity (SRI)\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "SRI check complete"
done
