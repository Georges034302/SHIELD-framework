#!/usr/bin/env bash
# Phase 5 - WordPress Plugin Vulnerability Scan
# Enumerates plugins via readme.txt/changelog.txt, extracts versions,
# checks against a curated list of known-critical CVEs.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"
source "$SCRIPT_DIR/lib/wp_detect.sh"

STEP_NAME="step4_wp_plugins"

# Format: "plugin-slug:min_safe_version:CVE_description"
# Only plugins with confirmed high-severity CVEs in vulnerable older versions
KNOWN_VULN_PLUGINS=(
    "contact-form-7:5.8:CVE-2024-0550 — Unrestricted file upload in CF7 <5.8"
    "woocommerce:8.2:CVE-2023-47777 — Stored XSS in WooCommerce <8.2"
    "elementor:3.16:CVE-2023-48777 — RCE via file upload in Elementor Pro <3.16"
    "wordfence:7.11:CVE-2024-1029 — XSS in Wordfence <7.11"
    "wp-file-manager:6.9:CVE-2020-25213 — Unauthenticated RCE in WP File Manager <6.9 (actively exploited)"
    "ultimate-member:2.6.7:CVE-2023-3460 — Privilege escalation in Ultimate Member <2.6.7 (CVSS 9.8)"
    "gravityforms:2.7.4:CVE-2023-28782 — SQLi in Gravity Forms <2.7.4"
    "advanced-custom-fields:6.1.6:CVE-2023-30777 — Reflected XSS in ACF <6.1.6"
    "wpforms-lite:1.8.3:CVE-2023-4596 — Unrestricted file upload in WPForms <1.8.3"
    "loginizer:1.7.9:CVE-2022-4328 — Auth bypass in Loginizer <1.7.9"
    "all-in-one-wp-migration:7.80:CVE-2023-40000 — PHP object injection in AIOWP Migration <7.80"
    "duplicator:1.5.1:CVE-2023-1471 — Path traversal in Duplicator <1.5.1"
    "wp-super-cache:1.12.0:CVE-2023-38000 — Authenticated XSS in WP Super Cache <1.12.0"
    "litespeed-cache:6.1:CVE-2024-28000 — Privilege escalation in LiteSpeed Cache <6.1 (CVSS 9.8)"
    "really-simple-ssl:7.2.3:CVE-2024-10924 — Auth bypass in Really Simple SSL <7.2.3 (CVSS 9.8)"
    "jetpack:13.2:CVE-2023-2640 — Code injection via Jetpack <13.2"
    "yith-woocommerce-wishlist:3.19.2:CVE-2021-24624 — SQLi in YITH Wishlist <3.19.2"
    "ninja-forms:3.6.26:CVE-2021-34656 — SQLi in Ninja Forms <3.6.26"
    "the-events-calendar:6.2.3:CVE-2023-26540 — SQLi in The Events Calendar <6.2.3"
    "wpdiscuz:7.6.12:CVE-2024-3994 — Unauthenticated stored XSS in wpDiscuz <7.6.12"
    "tablesome:1.0.29:CVE-2023-0620 — SQLi in Tablesome <1.0.29"
    "mailchimp-for-wp:4.9.7:CVE-2024-0401 — Insecure direct object reference in Mailchimp for WP <4.9.7"
)

version_lt() {
    # Returns 0 (true) if version $1 < $2
    [[ "$1" == "$2" ]] && return 1
    local lower; lower=$(printf '%s\n' "$1" "$2" | sort -V | head -1)
    [[ "$lower" == "$1" ]]
}

check_wp_plugins() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    local OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    local OUTPUT_FILE="$OUTPUT_DIR/wp_plugins.json"

    detect_wordpress "$target"

    if [[ "$WP_DETECTED" != "true" ]]; then
        {
            echo "{"
            echo "  \"step\": \"$STEP_NAME\","
            echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
            echo "  \"target\": \"$target\","
            echo "  \"checks\": ["
            echo "    {\"name\":\"WP Plugin Scan\",\"status\":\"INFO\",\"found\":\"WordPress not detected\",\"expected\":\"N/A\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
            echo "  ]"
            echo "}"
        } > "$OUTPUT_FILE"
        print_status "INFO" "WP plugins: WordPress not detected — skipped"
        return
    fi

    local found_plugins=()
    local vuln_findings=()
    local accessible_dirs=()

    # ── 1. Enumerate plugins from known CVE list ──────────────────────────────
    for entry in "${KNOWN_VULN_PLUGINS[@]}"; do
        local slug="${entry%%:*}"
        local rest="${entry#*:}"
        local safe_ver="${rest%%:*}"
        local cve_desc="${rest#*:}"

        # Try readme.txt
        local readme_url="${base_url}/wp-content/plugins/${slug}/readme.txt"
        local readme_code
        readme_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-6}" "$readme_url" 2>/dev/null || echo "000")

        if [[ "$readme_code" == "200" ]]; then
            local readme_content
            readme_content=$(curl -sS --max-time "${TIMEOUT:-6}" "$readme_url" 2>/dev/null | head -c 2048 || echo "")
            local plugin_version
            plugin_version=$(echo "$readme_content" | grep -i "^Stable tag:" | head -1 | \
                grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || echo "")

            found_plugins+=("$slug (version: ${plugin_version:-unknown})")

            if [[ -n "$plugin_version" ]] && version_lt "$plugin_version" "$safe_ver"; then
                vuln_findings+=("VULNERABLE: $slug v${plugin_version} < v${safe_ver} — $cve_desc")
            else
                : # Plugin present but not in a known-vulnerable version range
            fi
        fi
    done

    # ── 2. Check if /wp-content/plugins/ directory is browsable ──────────────
    local plugins_dir_code
    plugins_dir_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-5}" \
        "${base_url}/wp-content/plugins/" 2>/dev/null || echo "000")
    if [[ "$plugins_dir_code" == "200" ]]; then
        local dir_content
        dir_content=$(curl -sS --max-time "${TIMEOUT:-5}" "${base_url}/wp-content/plugins/" 2>/dev/null | head -c 8192 || echo "")
        if echo "$dir_content" | grep -qi "Index of\|Directory listing\|<a href="; then
            accessible_dirs+=("DIRECTORY LISTING: /wp-content/plugins/ — all installed plugins enumerable")
        fi
    fi

    # Also check themes dir
    local themes_dir_code
    themes_dir_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-5}" \
        "${base_url}/wp-content/themes/" 2>/dev/null || echo "000")
    if [[ "$themes_dir_code" == "200" ]]; then
        local dir_content2
        dir_content2=$(curl -sS --max-time "${TIMEOUT:-5}" "${base_url}/wp-content/themes/" 2>/dev/null | head -c 4096 || echo "")
        echo "$dir_content2" | grep -qi "Index of\|<a href=" && \
            accessible_dirs+=("DIRECTORY LISTING: /wp-content/themes/ — all installed themes enumerable")
    fi

    local OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    local OUTPUT_FILE="$OUTPUT_DIR/wp_plugins.json"

    {
        echo "{"
        echo "  \"step\": \"$STEP_NAME\","
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"target\": \"$target\","
        echo "  \"checks\": ["
        local first=true

        if [[ ${#vuln_findings[@]} -gt 0 ]]; then
            local vf_str; vf_str=$(IFS="; "; printf '%s' "${vuln_findings[*]}")
            local vf_e; vf_e=$(json_escape "$vf_str")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"Known Vulnerable Plugins\",\"status\":\"FAIL\",\"found\":\"$vf_e\",\"expected\":\"All plugins updated to patched versions\",\"severity\":\"CRITICAL\",\"remediation_id\":\"SEC-WPPLUGIN-001\"}"
        fi

        if [[ ${#found_plugins[@]} -gt 0 && ${#vuln_findings[@]} -eq 0 ]]; then
            local fp_str; fp_str=$(IFS="; "; printf '%s' "${found_plugins[@]:0:10}")
            local fp_e; fp_e=$(json_escape "${#found_plugins[@]} plugin(s) detected from CVE list: $fp_str")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"Plugin Enumeration\",\"status\":\"INFO\",\"found\":\"$fp_e\",\"expected\":\"N/A\",\"severity\":\"LOW\",\"remediation_id\":\"\"}"
        fi

        if [[ ${#accessible_dirs[@]} -gt 0 ]]; then
            local ad_str; ad_str=$(IFS="; "; printf '%s' "${accessible_dirs[*]}")
            local ad_e; ad_e=$(json_escape "$ad_str")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"Directory Listing\",\"status\":\"FAIL\",\"found\":\"$ad_e\",\"expected\":\"Directory listing disabled\",\"severity\":\"MEDIUM\",\"remediation_id\":\"SEC-WPPLUGIN-002\"}"
        fi

        if [[ ${#vuln_findings[@]} -eq 0 && ${#accessible_dirs[@]} -eq 0 && ${#found_plugins[@]} -eq 0 ]]; then
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"WP Plugin Scan\",\"status\":\"PASS\",\"found\":\"No known-vulnerable plugins detected at ${#KNOWN_VULN_PLUGINS[@]} checked paths\",\"expected\":\"All plugins patched\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
        fi

        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    if [[ ${#vuln_findings[@]} -gt 0 ]]; then
        print_status "FAIL" "WP plugins: ${#vuln_findings[@]} vulnerable plugin(s) found"
    elif [[ ${#accessible_dirs[@]} -gt 0 ]]; then
        print_status "WARN" "WP plugins: directory listing exposed"
    else
        print_status "PASS" "WP plugin scan: no vulnerable plugins detected"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Scanning WordPress plugins: $TARGET"
    check_wp_plugins "$TARGET"
done
