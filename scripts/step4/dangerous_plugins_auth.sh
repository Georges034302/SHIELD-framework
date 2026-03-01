#!/usr/bin/env bash
# SHIELD - Dangerous Plugin Detection
# PURPOSE: Detect plugins that allow code execution or file management (requires authentication)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step4_dangerous_plugins_auth"

# Dangerous plugins that allow code execution or file access
DANGEROUS_PLUGINS=(
    "wpcode"
    "insert-headers-and-footers"
    "code-snippets"
    "file-manager"
    "wp-file-manager"
    "advanced-file-manager"
    "filebird"
    "real-media-library"
)

for TARGET in "${ARGS[@]}"; do
    OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/dangerous_plugins_auth.json"
    cookies_file="$OUT/.session_cookies"
    
    # Skip if not authenticated
    if [[ ! -f "$cookies_file" ]]; then
        print_status "INFO" "Dangerous plugin check skipped (not authenticated)"
        {
            echo "{"
            echo "  \"step\": \"$STEP_NAME\","
            echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
            echo "  \"target\": \"$TARGET\","
            echo "  \"checks\": ["
            echo "    {\"name\":\"Dangerous Plugins Check\",\"status\":\"SKIP\",\"found\":\"Not authenticated\",\"expected\":\"Provide credentials with --user and --pass\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
            echo "  ]"
            echo "}"
        } > "$OUTPUT_FILE"
        continue
    fi
    
    print_status "INFO" "Checking for dangerous plugins (authenticated): $TARGET"
    
    base_url="${TARGET%/}"
    plugins_url="${base_url}/wp-admin/plugins.php"
    
    # Fetch plugins page
    plugins_html=$(curl -sS --max-time "${TIMEOUT:-10}" \
        -b "$cookies_file" \
        "$plugins_url" 2>/dev/null)
    
    found_dangerous=()
    
    # Check for each dangerous plugin
    for plugin in "${DANGEROUS_PLUGINS[@]}"; do
        if echo "$plugins_html" | grep -qi "$plugin"; then
            # Extract plugin name using portable grep
            plugin_name=$(echo "$plugins_html" | grep -i "$plugin" | grep -o 'plugin-title[^>]*>[^<]*<strong>[^<]*' | sed 's/.*<strong>//' | head -1)
            if [[ -z "$plugin_name" ]]; then
                plugin_name="$plugin"
            fi
            found_dangerous+=("$plugin_name")
            print_status "FAIL" "Found dangerous plugin: $plugin_name"
        fi
    done
    
    # Check specifically for WPCode (most critical)
    wpcode_check=$(echo "$plugins_html" | grep -i "wpcode\|insert-headers" | head -1)
    
    if [[ ${#found_dangerous[@]} -gt 0 ]]; then
        dangerous_list=$(IFS=', '; echo "${found_dangerous[*]}")
        
        {
            echo "{"
            echo "  \"step\": \"$STEP_NAME\","
            echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
            echo "  \"target\": \"$TARGET\","
            echo "  \"checks\": ["
            echo "    {\"name\":\"Dangerous Plugins\",\"status\":\"FAIL\",\"found\":\"Code execution plugins detected: $dangerous_list\",\"expected\":\"Remove plugins that allow arbitrary code execution\",\"severity\":\"CRITICAL\",\"remediation_id\":\"SEC-PLUGIN-001\"}"
            echo "  ]"
            echo "}"
        } > "$OUTPUT_FILE"
    else
        print_status "PASS" "No dangerous code execution plugins detected"
        
        {
            echo "{"
            echo "  \"step\": \"$STEP_NAME\","
            echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
            echo "  \"target\": \"$TARGET\","
            echo "  \"checks\": ["
            echo "    {\"name\":\"Dangerous Plugins\",\"status\":\"PASS\",\"found\":\"No code execution plugins detected\",\"expected\":\"N/A\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
            echo "  ]"
            echo "}"
        } > "$OUTPUT_FILE"
    fi
done
