#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step6_waf_fingerprint"

# WAF / CDN detection and security posture fingerprinting
check_waf_fingerprint() {
    local target="$1"

    local response
    response=$(curl -sS -I --max-time "${TIMEOUT:-10}" "$target" 2>/dev/null || echo "")

    local waf_detected=""
    local waf_signals=()
    local severity="INFO"

    # --- Cloudflare ---
    if echo "$response" | grep -qi "cf-ray\|cloudflare\|__cfduid"; then
        waf_detected="Cloudflare"
        waf_signals+=("cf-ray header present")
    fi

    # --- AWS WAF / CloudFront ---
    if echo "$response" | grep -qi "x-amzn-requestid\|x-amz-cf-id\|aws-waf"; then
        waf_detected="${waf_detected:+$waf_detected + }AWS CloudFront/WAF"
        waf_signals+=("AWS CloudFront/WAF headers present")
    fi

    # --- Akamai ---
    if echo "$response" | grep -qi "akamai\|x-akamai\|x-check-cacheable"; then
        waf_detected="${waf_detected:+$waf_detected + }Akamai"
        waf_signals+=("Akamai headers present")
    fi

    # --- Fastly ---
    if echo "$response" | grep -qi "x-fastly\|fastly-restarts\|x-served-by.*cache"; then
        waf_detected="${waf_detected:+$waf_detected + }Fastly CDN"
        waf_signals+=("Fastly CDN headers present")
    fi

    # --- Sucuri ---
    if echo "$response" | grep -qi "x-sucuri\|sucuri"; then
        waf_detected="${waf_detected:+$waf_detected + }Sucuri WAF"
        waf_signals+=("Sucuri WAF headers present")
    fi

    # --- Imperva / Incapsula ---
    if echo "$response" | grep -qi "incap_ses\|visid_incap\|x-iinfo\|x-cdn.*incapsula"; then
        waf_detected="${waf_detected:+$waf_detected + }Imperva Incapsula"
        waf_signals+=("Imperva Incapsula WAF detected")
    fi

    # --- No WAF detected ---
    if [[ -z "$waf_detected" ]]; then
        # Check if security response headers are missing (indicator of no WAF)
        local missing_sec_headers=()
        echo "$response" | grep -qi "x-content-type-options" || missing_sec_headers+=("X-Content-Type-Options")
        echo "$response" | grep -qi "x-frame-options\|Content-Security-Policy" || missing_sec_headers+=("X-Frame-Options/CSP")

        if [[ ${#missing_sec_headers[@]} -ge 2 ]]; then
            waf_signals+=("No WAF/CDN detected; security headers also missing")
            echo "WARN|No WAF or CDN detected; site may be directly exposed|WAF or CDN in front of origin recommended|MEDIUM|SEC-WAF-001"
            return
        fi

        echo "INFO|No WAF/CDN fingerprint detected (may be custom or header-stripped)|WAF or CDN recommended for production|LOW|SEC-WAF-001"
        return
    fi

    # WAF/CDN is detected — provide tuning recommendations
    local signals_str
    signals_str=$(IFS=", "; printf '%s' "${waf_signals[*]}")
    echo "PASS|$waf_detected detected ($signals_str)|WAF/CDN active with security rules enabled|INFO|"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Fingerprinting WAF/CDN for $TARGET"

    OUTPUT_DIR="$OUT/step6"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/waf_fingerprint.json"

    result=$(check_waf_fingerprint "$TARGET")

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
        echo "    {\"name\":\"WAF/CDN Fingerprint\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    print_status "$status" "WAF/CDN fingerprint check complete"
done
