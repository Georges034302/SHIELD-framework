#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

# Phase 5 - WordPress Version Detection
# Detects WP version via multiple passive signals; flags EOL/outdated versions.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"
source "$SCRIPT_DIR/lib/wp_detect.sh"

STEP_NAME="step1_wp_version"

check_wp_version() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    local OUTPUT_DIR="$OUT/step1"
    mkdir -p "$OUTPUT_DIR"
    local OUTPUT_FILE="$OUTPUT_DIR/wp_version.json"

    # Detect WordPress first
    detect_wordpress "$target"

    if [[ "$WP_DETECTED" != "true" ]]; then
        {
            echo "{"
            echo "  \"step\": \"$STEP_NAME\","
            echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
            echo "  \"target\": \"$target\","
            echo "  \"checks\": ["
            echo "    {\"name\":\"WordPress Detection\",\"status\":\"INFO\",\"found\":\"WordPress not detected\",\"expected\":\"N/A — WP-specific check skipped\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
            echo "  ]"
            echo "}"
        } > "$OUTPUT_FILE"
        print_status "INFO" "WP version check: WordPress not detected — skipped"
        return
    fi

    local checks=()

    # ── Detection result ──────────────────────────────────────────────────────
    checks+=("PASS|WordPress detected (confidence: $WP_CONFIDENCE)|N/A|INFO|")

    # ── Version via additional sources ────────────────────────────────────────
    # Try feed for more precise version
    if [[ -z "$WP_VERSION" ]]; then
        local feed_content
        feed_content=$(curl -sS --max-time "${TIMEOUT:-8}" "${base_url}/?feed=rss2" 2>/dev/null | head -c 4096 || echo "")
        WP_VERSION=$(echo "$feed_content" | grep -ioE '<generator>https://wordpress.org/\?v=[0-9]+\.[0-9]+(\.[0-9]+)?' | \
            grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || echo "")
    fi

    # Try wp-links-opml.php
    if [[ -z "$WP_VERSION" ]]; then
        local opml_content
        opml_content=$(curl -sS --max-time "${TIMEOUT:-5}" "${base_url}/wp-links-opml.php" 2>/dev/null | head -c 1024 || echo "")
        WP_VERSION=$(echo "$opml_content" | grep -oE 'v=[0-9]+\.[0-9]+(\.[0-9]+)?' | \
            grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || echo "")
    fi

    # ── Version exposure check ────────────────────────────────────────────────
    if [[ -n "$WP_VERSION" ]]; then
        local wp_status; wp_status=$(classify_wp_version "$WP_VERSION")
        case "$wp_status" in
            EOL)
                checks+=("FAIL|WordPress $WP_VERSION is END-OF-LIFE and receives no security updates — critical vulnerability risk|WordPress 6.4+ (current stable)|CRITICAL|SEC-WPVER-001")
                ;;
            OUTDATED)
                checks+=("WARN|WordPress $WP_VERSION is outdated — security patches available for newer 6.x versions|Update to current WordPress|MEDIUM|SEC-WPVER-001")
                ;;
            CURRENT)
                checks+=("PASS|WordPress $WP_VERSION is current and supported|N/A|INFO|")
                ;;
            UNKNOWN)
                checks+=("INFO|WordPress version detected but could not classify: $WP_VERSION|N/A|LOW|")
                ;;
        esac

        # Version disclosure is always a finding regardless of version age
        checks+=("WARN|WordPress version $WP_VERSION is publicly visible — aids attacker targeting|Remove version metadata from generator tag, feed, and readme.html|MEDIUM|SEC-WPVER-002")
    else
        checks+=("PASS|WordPress version not exposed in public sources|N/A|INFO|")
    fi

    # ── readme.html exposure ──────────────────────────────────────────────────
    local readme_code
    readme_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-5}" \
        "${base_url}/readme.html" 2>/dev/null || echo "000")
    if [[ "$readme_code" == "200" ]]; then
        local version_in_readme
        version_in_readme=$(curl -sS --max-time "${TIMEOUT:-5}" "${base_url}/readme.html" 2>/dev/null | \
            grep -ioE '[Vv]ersion\s+[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || echo "")
        if [[ -n "$version_in_readme" ]]; then
            checks+=("FAIL|readme.html accessible and contains version: $version_in_readme|Block or remove readme.html|MEDIUM|SEC-WPVER-002")
        else
            checks+=("WARN|readme.html accessible (even without explicit version, confirms WP)|Block or remove readme.html|LOW|SEC-WPVER-002")
        fi
    else
        checks+=("PASS|readme.html not accessible (HTTP $readme_code)|N/A|INFO|")
    fi

    # ── wp-includes/version.php exposure ─────────────────────────────────────
    local vpfile_code
    vpfile_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-5}" \
        "${base_url}/wp-includes/version.php" 2>/dev/null || echo "000")
    if [[ "$vpfile_code" == "200" ]]; then
        checks+=("FAIL|wp-includes/version.php is publicly accessible — PHP source/version readable|Block direct access to wp-includes/*.php|HIGH|SEC-WPVER-002")
    else
        checks+=("PASS|wp-includes/version.php not directly accessible (HTTP $vpfile_code)|N/A|INFO|")
    fi

    {
        echo "{"
        echo "  \"step\": \"$STEP_NAME\","
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"target\": \"$target\","
        echo "  \"checks\": ["
        local check_names=("WordPress Detection" "WordPress Version" "Version Disclosure" "readme.html Exposure" "version.php Exposure")
        local first=true
        local i=0
        for check in "${checks[@]}"; do
            IFS='|' read -r st fd ex sv rm <<< "$check"
            local st_e fd_e ex_e sv_e rm_e name_e
            st_e=$(json_escape "$st"); fd_e=$(json_escape "$fd")
            ex_e=$(json_escape "$ex"); sv_e=$(json_escape "$sv"); rm_e=$(json_escape "$rm")
            name_e=$(json_escape "${check_names[$i]:-WP Version Check}")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"$name_e\",\"status\":\"$st_e\",\"found\":\"$fd_e\",\"expected\":\"$ex_e\",\"severity\":\"$sv_e\",\"remediation_id\":\"$rm_e\"}"
            (( i++ )) || true
        done
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    local has_crit=false has_fail=false has_warn=false
    for c in "${checks[@]}"; do
        [[ "$c" == FAIL*CRITICAL* ]] && has_crit=true
        [[ "$c" == FAIL* ]] && has_fail=true
        [[ "$c" == WARN* ]] && has_warn=true
    done
    $has_crit && print_status "FAIL" "WP version: CRITICAL — EOL version detected" && return
    $has_fail && print_status "FAIL" "WP version: failures found" && return
    $has_warn && print_status "WARN" "WP version: warnings found" && return
    print_status "PASS" "WP version check complete"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking WordPress version: $TARGET"
    check_wp_version "$TARGET"
done
