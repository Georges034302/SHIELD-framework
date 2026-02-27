#!/usr/bin/env bash
# Phase 5 - Sensitive File Exposure
# Probes .env, .git, private keys, config files, logs, and known secret paths.
# Reports exact credential patterns found, not just HTTP 200.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step5_env_exposure"

# Path : severity : description
SENSITIVE_PATHS=(
    "/.env:CRITICAL:Environment file (API keys, DB passwords, app secrets)"
    "/.env.local:CRITICAL:Local environment overrides"
    "/.env.production:CRITICAL:Production environment file"
    "/.env.backup:CRITICAL:Environment file backup"
    "/.git/config:HIGH:Git repository config (may contain credentials in remote URL)"
    "/.git/HEAD:HIGH:Git HEAD reference (confirms full git repo exposure)"
    "/.git/COMMIT_EDITMSG:HIGH:Last git commit message (code enumeration possible)"
    "/.git/logs/HEAD:HIGH:Git commit history (full source extractable)"
    "/composer.lock:MEDIUM:Exact PHP dependency versions (attack surface mapping)"
    "/composer.json:MEDIUM:PHP project structure and dependencies"
    "/package.json:MEDIUM:Node.js project structure"
    "/package-lock.json:MEDIUM:Exact Node.js dependency versions"
    "/Dockerfile:MEDIUM:Docker build instructions (infrastructure disclosure)"
    "/docker-compose.yml:HIGH:Docker compose config (may contain credentials)"
    "/.htpasswd:CRITICAL:HTTP Basic Auth hashed credentials"
    "/web.config:HIGH:IIS configuration (connection strings, app settings)"
    "/server.key:CRITICAL:Private SSL/TLS key"
    "/private.key:CRITICAL:Private key file"
    "/id_rsa:CRITICAL:SSH private key"
    "/.ssh/id_rsa:CRITICAL:SSH private key in .ssh directory"
    "/id_ecdsa:CRITICAL:ECDSA SSH private key"
    "/error_log:MEDIUM:Server error log (paths, credentials in errors)"
    "/errors.log:MEDIUM:Application error log"
    "/debug.log:MEDIUM:Debug log file"
    "/storage/logs/laravel.log:MEDIUM:Laravel application log"
    "/wp-content/debug.log:HIGH:WordPress debug log"
    "/application.log:MEDIUM:Generic application log"
    "/.DS_Store:LOW:macOS directory metadata (file structure enumeration)"
    "/thumbs.db:LOW:Windows thumbnail cache (directory structure leak)"
    "/config.php:HIGH:PHP configuration file"
    "/config.inc.php:HIGH:PHP config include file"
    "/config.yml:HIGH:YAML config (may contain secrets)"
    "/config.yaml:HIGH:YAML config (may contain secrets)"
    "/settings.py:HIGH:Django settings (SECRET_KEY, databases)"
    "/application.properties:HIGH:Spring Boot/Java config"
    "/appsettings.json:HIGH:.NET application settings"
    "/database.yml:CRITICAL:Rails database config (credentials)"
    "/secrets.yml:CRITICAL:Rails secrets file"
    "/sftp-config.json:CRITICAL:SFTP/FTP connection credentials (editor config)"
    "/.ftpconfig:CRITICAL:FTP client configuration with credentials"
)

# Credential patterns to scan in response body
CRED_PATTERNS=(
    'DB_PASSWORD\s*='
    'DATABASE_URL\s*='
    'API_KEY\s*='
    'SECRET_KEY\s*='
    'AWS_SECRET'
    'STRIPE_SECRET'
    'TWILIO_AUTH'
    'MAIL_PASSWORD\s*='
    'SMTP_PASS\s*='
    'password\s*=\s*["\'"'"'][^"'"'"']{4,}'
    'private_key'
    '-----BEGIN.*PRIVATE KEY-----'
    '-----BEGIN RSA PRIVATE KEY-----'
    '[a-z0-9]{32}:[a-z0-9A-Z+/]{32,}'
)

check_env_exposure() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    local findings=()
    local crit_findings=()

    for entry in "${SENSITIVE_PATHS[@]}"; do
        local path="${entry%%:*}"
        local rest="${entry#*:}"
        local severity="${rest%%:*}"
        local description="${rest#*:}"

        local url="${base_url}${path}"
        local http_code
        http_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-8}" "$url" 2>/dev/null || echo "000")

        if [[ "$http_code" == "200" ]]; then
            local content
            content=$(curl -sS -L --max-time "${TIMEOUT:-8}" "$url" 2>/dev/null | head -c 8192 || echo "")

            # Skip if response is just an HTML page (not the actual file)
            local content_len=${#content}
            if [[ $content_len -lt 10 ]]; then
                continue
            fi

            # Check if it's a redirect to login page / error page (false positive)
            if echo "$content" | grep -qiE '<!DOCTYPE html|<html|wp-login|Sign In|403 Forbidden' && \
               ! echo "$content" | grep -qiE '(DB_|API_|SECRET|password|private_key|BEGIN.*PRIVATE)'; then
                # Looks like an HTML error page, not the real file
                continue
            fi

            # Scan for credential patterns
            local cred_hit=""
            for pattern in "${CRED_PATTERNS[@]}"; do
                if echo "$content" | grep -qiE "$pattern"; then
                    cred_hit="$pattern"
                    break
                fi
            done

            if [[ -n "$cred_hit" ]]; then
                crit_findings+=("CREDENTIALS EXPOSED: $path ($description) — matched pattern: $cred_hit")
                severity="CRITICAL"
            else
                findings+=("$severity: $path accessible — $description (HTTP 200, ${content_len}B)")
            fi
        elif [[ "$http_code" == "403" ]]; then
            # 403 means file exists but blocked — still worth noting for git
            if [[ "$path" == "/.git/config" ]]; then
                findings+=("MEDIUM: /.git/config returns 403 — git repo present, access blocked (consider full removal)")
            fi
        fi
    done

    # ── Git repo full extraction check ───────────────────────────────────────
    local git_objects
    git_objects=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-5}" "${base_url}/.git/objects/" 2>/dev/null || echo "000")
    if [[ "$git_objects" == "200" ]]; then
        crit_findings+=("FULL SOURCE EXTRACTABLE: /.git/objects/ directory listing open — entire git history downloadable")
    fi

    local OUTPUT_DIR="$OUT/step5"
    mkdir -p "$OUTPUT_DIR"
    local OUTPUT_FILE="$OUTPUT_DIR/env_exposure.json"

    {
        echo "{"
        echo "  \"step\": \"$STEP_NAME\","
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"target\": \"$target\","
        echo "  \"checks\": ["

        local first=true

        if [[ ${#crit_findings[@]} -gt 0 ]]; then
            local cf_str; cf_str=$(IFS="; "; printf '%s' "${crit_findings[*]}")
            local cf_e; cf_e=$(json_escape "$cf_str")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"Credential/Key Exposure\",\"status\":\"FAIL\",\"found\":\"$cf_e\",\"expected\":\"Sensitive files blocked or absent\",\"severity\":\"CRITICAL\",\"remediation_id\":\"SEC-ENV-001\"}"
        fi

        if [[ ${#findings[@]} -gt 0 ]]; then
            local f_str; f_str=$(IFS="; "; printf '%s' "${findings[*]}")
            local f_e; f_e=$(json_escape "$f_str")
            local sev="MEDIUM"
            echo "$f_str" | grep -qiE '^HIGH:|CRITICAL:' && sev="HIGH"
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"Sensitive File Exposure\",\"status\":\"FAIL\",\"found\":\"$f_e\",\"expected\":\"Sensitive files blocked or absent\",\"severity\":\"$sev\",\"remediation_id\":\"SEC-ENV-002\"}"
        fi

        if [[ ${#crit_findings[@]} -eq 0 && ${#findings[@]} -eq 0 ]]; then
            echo "    {\"name\":\"Sensitive File Exposure\",\"status\":\"PASS\",\"found\":\"No sensitive files accessible at ${#SENSITIVE_PATHS[@]} probed paths\",\"expected\":\"Sensitive files blocked\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
        fi

        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    local total_issues=$(( ${#crit_findings[@]} + ${#findings[@]} ))
    if [[ $total_issues -eq 0 ]]; then
        print_status "PASS" "Sensitive file exposure: none found"
    elif [[ ${#crit_findings[@]} -gt 0 ]]; then
        print_status "FAIL" "Sensitive file exposure: ${#crit_findings[@]} CRITICAL findings (credentials exposed)"
    else
        print_status "FAIL" "Sensitive file exposure: ${#findings[@]} files accessible"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Probing sensitive file paths: $TARGET"
    check_env_exposure "$TARGET"
done
