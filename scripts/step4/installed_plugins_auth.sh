#!/usr/bin/env bash
# SHIELD - Authenticated Plugin Enumeration
# PURPOSE: List all installed WordPress plugins with versions (requires authentication)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step4_installed_plugins_auth"

for TARGET in "${ARGS[@]}"; do
    OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/installed_plugins_auth.json"
    cookies_file="$OUT/.session_cookies"
    
    # Skip if not authenticated
    if [[ ! -f "$cookies_file" ]]; then
        print_status "INFO" "Authenticated plugin enumeration skipped (not authenticated)"
        {
            echo "{"
            echo "  \"step\": \"$STEP_NAME\","
            echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
            echo "  \"target\": \"$TARGET\","
            echo "  \"checks\": ["
            echo "    {\"name\":\"Authenticated Plugin Enumeration\",\"status\":\"SKIP\",\"found\":\"Not authenticated\",\"expected\":\"Provide credentials with --user and --pass\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
            echo "  ]"
            echo "}"
        } > "$OUTPUT_FILE"
        continue
    fi
    
    print_status "INFO" "Enumerating installed plugins (authenticated): $TARGET"
    
    base_url="${TARGET%/}"
    plugins_url="${base_url}/wp-admin/plugins.php"
    
    # Fetch plugins page
    plugins_html=$(curl -sS --max-time "${TIMEOUT:-10}" \
        -b "$cookies_file" \
        "$plugins_url" 2>/dev/null)
    
    # Extract plugin names - more portable approach
    plugin_list=$(echo "$plugins_html" | \
        grep -o 'plugin-title[^>]*>[^<]*<strong>[^<]*' | \
        sed 's/.*<strong>//' | \
        head -20 || echo "")
    
    if [[ -n "$plugin_list" ]]; then
        plugin_count=$(echo "$plugin_list" | wc -l)
        plugins_found=$(echo "$plugin_list" | tr '\n' '; ' | sed 's/;$//')
        
        print_status "INFO" "Found $plugin_count installed plugins"
        
        {
            echo "{"
            echo "  \"step\": \"$STEP_NAME\","
            echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
            echo "  \"target\": \"$TARGET\","
            echo "  \"checks\": ["
            echo "    {\"name\":\"Installed Plugins\",\"status\":\"INFO\",\"found\":\"$plugin_count plugins: $plugins_found\",\"expected\":\"Review for vulnerable or unnecessary plugins\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
            echo "  ]"
            echo "}"
        } > "$OUTPUT_FILE"
    else
        print_status "WARN" "Could not enumerate plugins"
            echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
            echo "  \"target\": \"$TARGET\","
            echo "  \"checks\": ["
            echo "    {\"name\":\"Installed Plugins\",\"status\":\"WARN\",\"found\":\"Plugin page accessible but could not parse plugin list\",\"expected\":\"N/A\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
            echo "  ]"
            echo "}"
        } > "$OUTPUT_FILE"
    fi
done
