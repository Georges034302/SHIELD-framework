#!/usr/bin/env bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step6_infra_exposure"

json_escape() {
    local str="$1"
    str="${str//\\/\\\\}"
    str="${str//\"/\\\"}"
    str="${str//$'\n'/\\n}"
    str="${str//$'\r'/}"
    echo -n "$str"
}

# Infrastructure-revealing paths
INFRA_PATHS=(
    ".git/config"
    ".git/HEAD"
    ".svn/entries"
    ".env"
    ".env.local"
    ".htaccess"
    "phpinfo.php"
    "info.php"
    "test.php"
    ".DS_Store"
    "composer.json"
    "package.json"
    "Gemfile"
    "requirements.txt"
    "docker-compose.yml"
    ".gitlab-ci.yml"
    ".travis.yml"
    "Jenkinsfile"
    ".dockerignore"
    "Dockerfile"
    "robots.txt"
    ".well-known/security.txt"
    "crossdomain.xml"
    "clientaccesspolicy.xml"
)

check_infra_exposure() {
    local target="$1"
    local base_url="${target%/}"
    
    local exposed=()
    local checked=0
    local severity="INFO"
    
    # Check for exposed infrastructure files
    for path in "${INFRA_PATHS[@]}"; do
        local url="$base_url/$path"
        local response
        response=$(curl -sS --max-time "${TIMEOUT:-10}" \
            -w "\nHTTP_CODE:%{http_code}" \
            "$url" 2>/dev/null || echo "HTTP_CODE:000")
        
        local http_code=$(echo "$response" | grep "HTTP_CODE:" | cut -d: -f2)
        local body=$(echo "$response" | grep -v "HTTP_CODE:")
        
        checked=$((checked + 1))
        
        # 200 = accessible and potentially exposing info
        if [[ "$http_code" == "200" ]]; then
            local content_length=${#body}
            
            # Check for actual content (not just empty 200)
            if [[ $content_length -gt 10 ]]; then
                case "$path" in
                    .git/*|.svn/*)
                        exposed+=("Version control: $path (CRITICAL)")
                        severity="CRITICAL"
                        ;;
                    .env*|docker-compose.yml)
                        exposed+=("Configuration: $path (CRITICAL)")
                        severity="CRITICAL"
                        ;;
                    phpinfo.php|info.php|test.php)
                        exposed+=("Debug/Info page: $path (HIGH)")
                        [[ "$severity" != "CRITICAL" ]] && severity="HIGH"
                        ;;
                    composer.json|package.json|requirements.txt|Gemfile)
                        exposed+=("Dependency manifest: $path (MEDIUM)")
                        [[ "$severity" == "INFO" ]] && severity="MEDIUM"
                        ;;
                    .htaccess)
                        exposed+=("Server config: $path (MEDIUM)")
                        [[ "$severity" == "INFO" ]] && severity="MEDIUM"
                        ;;
                    *)
                        exposed+=("$path (LOW)")
                        ;;
                esac
            fi
        fi
    done
    
    # Check HTTP headers for infrastructure indicators
    local headers
    headers=$(curl -sS -I --max-time "${TIMEOUT:-10}" "$target" 2>/dev/null || echo "")
    
    # Server header with version
    if echo "$headers" | grep -qiE "^Server:.*/(([0-9]+\.)+[0-9]+)"; then
        exposed+=("Server version in headers (LOW)")
        [[ "$severity" == "INFO" ]] && severity="LOW"
    fi
    
    # X-Powered-By revealing technology stack
    if echo "$headers" | grep -qi "^X-Powered-By:"; then
        local powered_by
        powered_by=$(echo "$headers" | grep -i "^X-Powered-By:" | cut -d: -f2- | tr -d '\r\n' | xargs)
        exposed+=("X-Powered-By: $powered_by (LOW)")
        [[ "$severity" == "INFO" ]] && severity="LOW"
    fi
    
    # X-AspNet-Version, X-AspNetMvc-Version
    if echo "$headers" | grep -qiE "^X-AspNet.*Version:"; then
        exposed+=("ASP.NET version in headers (LOW)")
        [[ "$severity" == "INFO" ]] && severity="LOW"
    fi
    
    # Via header (proxy/cache info)
    if echo "$headers" | grep -qi "^Via:"; then
        local via_header
        via_header=$(echo "$headers" | grep -i "^Via:" | cut -d: -f2- | tr -d '\r\n' | xargs)
        exposed+=("Via header reveals proxy/cache: $via_header (INFO)")
    fi
    
    # Check HTML for infrastructure comments
    local page_content
    page_content=$(curl -sS -L --max-time "${TIMEOUT:-10}" "$target" 2>/dev/null || echo "")
    
    # Check for deployment/build info in comments
    if echo "$page_content" | grep -qE "<!--.*[Bb]uild.*[Vv]ersion|<!--.*[Dd]eployed|<!--.*[Gg]enerated by"; then
        exposed+=("HTML comments reveal build/deployment info (LOW)")
        [[ "$severity" == "INFO" ]] && severity="LOW"
    fi
    
    # Check for internal IP addresses
    if echo "$page_content" | grep -qoE "\b10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b|\b172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}\b|\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b"; then
        exposed+=("Internal IP addresses in HTML (MEDIUM)")
        [[ "$severity" == "INFO" ]] && severity="MEDIUM"
    fi
    
    # Check for common cloud metadata endpoints (if running in cloud)
    local hostname
    hostname=$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##' | sed 's#:.*##')
    
    # Check if hostname suggests cloud provider
    if echo "$hostname" | grep -qiE "amazonaws\.com|compute\.amazonaws\.com|cloudfront\.net|azurewebsites\.net|appspot\.com|herokuapp\.com|digitalocean"; then
        exposed+=("Cloud infrastructure: hostname reveals provider ($hostname) (INFO)")
    fi
    
    # Generate report
    if [[ ${#exposed[@]} -eq 0 ]]; then
        echo "PASS|No infrastructure exposure detected (checked ${checked} paths and indicators)|Infrastructure details properly hidden|INFO|"
    elif [[ "$severity" == "CRITICAL" ]]; then
        local exposed_str=$(IFS="; "; echo "${exposed[*]}")
        echo "FAIL|CRITICAL infrastructure exposed: $exposed_str|Remove/protect sensitive infrastructure files and configuration|CRITICAL|SEC-INFRA-003"
    elif [[ "$severity" == "HIGH" ]]; then
        local exposed_str=$(IFS="; "; echo "${exposed[*]}")
        echo "FAIL|Significant infrastructure exposure: $exposed_str|Remove debug pages and sensitive files|HIGH|SEC-INFRA-002"
    elif [[ "$severity" == "MEDIUM" ]] || [[ ${#exposed[@]} -ge 3 ]]; then
        local exposed_str=$(IFS="; "; echo "${exposed[*]}")
        echo "WARN|Infrastructure details exposed: $exposed_str|Hide server versions and remove unnecessary files|MEDIUM|SEC-INFRA-001"
    else
        local exposed_str=$(IFS="; "; echo "${exposed[*]}")
        echo "PASS|Minor infrastructure indicators: $exposed_str|Consider hiding server details|LOW|"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking infrastructure exposure for $TARGET"
    
    OUTPUT_DIR="$OUT/step6"
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/infra_exposure.json"
    
    result=$(check_infra_exposure "$TARGET")
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
        echo "    {\"name\":\"Infrastructure Exposure\",\"status\":\"$status_esc\",\"found\":\"$found_esc\",\"expected\":\"$expected_esc\",\"severity\":\"$severity_esc\",\"remediation_id\":\"$remediation_id_esc\"}"
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    
    print_status "$status" "Infrastructure exposure check complete"
done
