#!/usr/bin/env bash
# Shared WordPress detection helper — sourced by all WP-specific scripts.
# Returns: "wordpress" or "unknown"
# Sets global: WP_DETECTED=true/false, WP_CONFIDENCE=HIGH/MEDIUM/LOW/NONE

detect_wordpress() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    WP_DETECTED=false
    WP_CONFIDENCE="NONE"
    WP_VERSION=""

    local signals=0

    # Signal 1: wp-login.php returns 200
    local login_code
    login_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-8}" \
        "${base_url}/wp-login.php" 2>/dev/null || echo "000")
    [[ "$login_code" == "200" || "$login_code" == "302" ]] && (( signals++ ))

    # Signal 2: wp-admin redirects (302 → wp-login.php is WP)
    local admin_code
    admin_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-5}" \
        "${base_url}/wp-admin/" 2>/dev/null || echo "000")
    [[ "$admin_code" == "302" || "$admin_code" == "200" ]] && (( signals++ ))

    # Signal 3: generator meta tag
    local html
    html=$(curl -sS -L --max-time "${TIMEOUT:-8}" "$base_url/" 2>/dev/null | head -c 20000 || echo "")
    if echo "$html" | grep -qiE 'name=["\'"'"']generator["\'"'"'][^>]+WordPress|WordPress\s+[0-9]'; then
        (( signals += 2 ))
        # Extract version from generator
        WP_VERSION=$(echo "$html" | grep -ioE 'WordPress\s+[0-9]+\.[0-9]+(\.[0-9]+)?' | \
            grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || echo "")
    fi

    # Signal 4: /wp-content/ path in HTML
    echo "$html" | grep -qiE '/wp-content/(themes|plugins|uploads)/' && (( signals++ ))

    # Signal 5: wp-includes in HTML
    echo "$html" | grep -qiE '/wp-includes/' && (( signals++ ))

    # Signal 6: readme.html
    local readme_code
    readme_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-5}" \
        "${base_url}/readme.html" 2>/dev/null || echo "000")
    if [[ "$readme_code" == "200" ]]; then
        local readme_content
        readme_content=$(curl -sS --max-time "${TIMEOUT:-5}" "${base_url}/readme.html" 2>/dev/null | head -c 1024 || echo "")
        if echo "$readme_content" | grep -qi "WordPress"; then
            (( signals += 2 ))
            # Version from readme
            if [[ -z "$WP_VERSION" ]]; then
                WP_VERSION=$(echo "$readme_content" | grep -oE '[Vv]ersion\s+[0-9]+\.[0-9]+(\.[0-9]+)?' | \
                    grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || echo "")
            fi
        fi
    fi

    # Determine confidence
    if [[ $signals -ge 4 ]]; then
        WP_DETECTED=true
        WP_CONFIDENCE="HIGH"
    elif [[ $signals -ge 2 ]]; then
        WP_DETECTED=true
        WP_CONFIDENCE="MEDIUM"
    elif [[ $signals -ge 1 ]]; then
        WP_DETECTED=true
        WP_CONFIDENCE="LOW"
    fi

    export WP_DETECTED WP_CONFIDENCE WP_VERSION
}

# Check if WP version is EOL (< 6.0 is very old; < 6.4 is no longer supported)
# Returns: "EOL", "OUTDATED", "CURRENT", or "UNKNOWN"
classify_wp_version() {
    local version="$1"
    [[ -z "$version" ]] && echo "UNKNOWN" && return

    local major minor
    major=$(echo "$version" | cut -d. -f1)
    minor=$(echo "$version" | cut -d. -f2)

    # WordPress currently on 6.x series; < 6.0 = end of life
    if [[ $major -le 4 ]]; then
        echo "EOL"
    elif [[ $major -eq 5 ]]; then
        echo "EOL"
    elif [[ $major -eq 6 && $minor -le 3 ]]; then
        echo "OUTDATED"
    else
        echo "CURRENT"
    fi
}
