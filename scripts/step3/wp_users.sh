#!/usr/bin/env bash
# Phase 5 - WordPress User Enumeration
# Tests /?author= redirect, /wp-json/wp/v2/users API, and login error differentiation.
# Reports actual exposed usernames for specific reporting.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"
source "$SCRIPT_DIR/lib/wp_detect.sh"

STEP_NAME="step3_wp_users"

check_wp_users() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    local OUTPUT_DIR="$OUT/step3"
    mkdir -p "$OUTPUT_DIR"
    local OUTPUT_FILE="$OUTPUT_DIR/wp_users.json"

    detect_wordpress "$target"

    if [[ "$WP_DETECTED" != "true" ]]; then
        {
            echo "{"
            echo "  \"step\": \"$STEP_NAME\","
            echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
            echo "  \"target\": \"$target\","
            echo "  \"checks\": ["
            echo "    {\"name\":\"WP User Enumeration\",\"status\":\"INFO\",\"found\":\"WordPress not detected\",\"expected\":\"N/A\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
            echo "  ]"
            echo "}"
        } > "$OUTPUT_FILE"
        print_status "INFO" "WP users: WordPress not detected — skipped"
        return
    fi

    local checks=()
    local exposed_users=()

    # ── 1. REST API user endpoint /wp-json/wp/v2/users ───────────────────────
    local rest_code
    rest_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-8}" \
        "${base_url}/wp-json/wp/v2/users" 2>/dev/null || echo "000")

    if [[ "$rest_code" == "200" ]]; then
        local rest_body
        rest_body=$(curl -sS --max-time "${TIMEOUT:-8}" "${base_url}/wp-json/wp/v2/users" 2>/dev/null || echo "[]")
        # Extract usernames and display names
        local usernames
        usernames=$(echo "$rest_body" | python3 -c "
import sys, json
try:
    users = json.load(sys.stdin)
    for u in users:
        slug = u.get('slug','')
        name = u.get('name','')
        uid  = u.get('id','')
        if slug or name:
            print(f'id={uid} slug={slug} name={name}')
except: pass
" 2>/dev/null || echo "")

        if [[ -n "$usernames" ]]; then
            local user_count; user_count=$(echo "$usernames" | grep -c '\S' || echo "0")
            while IFS= read -r u; do [[ -n "$u" ]] && exposed_users+=("$u"); done <<< "$usernames"
            local users_str; users_str=$(IFS="; "; printf '%s' "${exposed_users[@]:0:10}")
            checks+=("FAIL|REST API /wp-json/wp/v2/users exposes $user_count user(s): $users_str|REST API user listing disabled|HIGH|SEC-WPUSR-001")
        else
            checks+=("WARN|REST API /wp-json/wp/v2/users returns HTTP 200 but no user data parsed|Disable user REST endpoint|MEDIUM|SEC-WPUSR-001")
        fi
    elif [[ "$rest_code" == "401" || "$rest_code" == "403" ]]; then
        checks+=("PASS|REST API user endpoint requires authentication (HTTP $rest_code)|N/A|INFO|")
    else
        checks+=("INFO|REST API user endpoint returned HTTP $rest_code|N/A|INFO|")
    fi

    # ── 2. Author archive enumeration /?author=N → redirect reveals username ─
    local author_users=()
    for i in 1 2 3 4 5; do
        local author_url="${base_url}/?author=${i}"
        local author_resp
        author_resp=$(curl -sS -I --max-time "${TIMEOUT:-8}" "$author_url" 2>/dev/null || echo "")
        local author_code; author_code=$(echo "$author_resp" | head -1 | grep -oE '[0-9]{3}' | head -1 || echo "000")
        local location; location=$(echo "$author_resp" | grep -i "^Location:" | sed 's/Location: //i' | tr -d '\r' || echo "")

        if [[ "$author_code" =~ ^30[127]$ && -n "$location" ]]; then
            # Extract username from redirect URL: /author/username/
            local username
            username=$(echo "$location" | grep -oE '/author/([^/]+)/' | sed 's|/author/||;s|/||' || echo "")
            if [[ -n "$username" ]]; then
                author_users+=("id=$i username=$username")
                [[ "${exposed_users[*]}" != *"$username"* ]] && exposed_users+=("id=$i slug=$username")
            fi
        elif [[ "$author_code" == "200" ]]; then
            # Author page served directly — check if it reveals username in URL or body
            local author_body
            author_body=$(curl -sS --max-time "${TIMEOUT:-8}" "$author_url" 2>/dev/null | head -c 4096 || echo "")
            local username
            username=$(echo "$author_body" | grep -ioE 'author/([a-zA-Z0-9_-]+)' | head -1 | sed 's|author/||' || echo "")
            if [[ -n "$username" ]]; then
                author_users+=("id=$i username=$username (from page body)")
            fi
        fi
    done

    if [[ ${#author_users[@]} -gt 0 ]]; then
        local au_str; au_str=$(IFS="; "; printf '%s' "${author_users[*]}")
        checks+=("FAIL|Author enumeration via /?author=N reveals usernames: $au_str|Block ?author= redirects (return 404)|HIGH|SEC-WPUSR-002")
    else
        checks+=("PASS|/?author=N enumeration blocked — no username leakage via author redirects|N/A|INFO|")
    fi

    # ── 3. Login error differentiation ───────────────────────────────────────
    # Test with known invalid user vs known invalid password for existing user
    local invalid_user_resp
    invalid_user_resp=$(curl -sS -L --max-time "${TIMEOUT:-8}" \
        -c /dev/null \
        -d "log=nonexistentuserxyz999&pwd=wrongpassword&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1" \
        -H "Cookie: wordpress_test_cookie=WP+Cookie+check" \
        "${base_url}/wp-login.php" 2>/dev/null | head -c 4096 || echo "")

    # WordPress leaks "Invalid username" vs "incorrect password" by default
    if echo "$invalid_user_resp" | grep -qi "Invalid username"; then
        checks+=("FAIL|Login page reveals 'Invalid username' error — allows username enumeration via login|Generic error only: 'Invalid credentials'|MEDIUM|SEC-WPUSR-003")
    elif echo "$invalid_user_resp" | grep -qi "The password you entered"; then
        checks+=("FAIL|Login page reveals password-specific error — confirms valid username existence|Generic error only|MEDIUM|SEC-WPUSR-003")
    else
        checks+=("PASS|Login error message does not differentiate invalid user from wrong password|N/A|INFO|")
    fi

    # ── 4. Summarise all exposed users ───────────────────────────────────────
    if [[ ${#exposed_users[@]} -gt 0 ]]; then
        local unique_users
        unique_users=$(printf '%s\n' "${exposed_users[@]}" | sort -u)
        local eu_count; eu_count=$(echo "$unique_users" | grep -c '\S' || echo "0")
        local eu_str; eu_str=$(echo "$unique_users" | tr '\n' '; ' | sed 's/; $//')
        local eu_e; eu_e=$(json_escape "$eu_str")
        {
            echo "{"
            echo "  \"step\": \"$STEP_NAME\","
            echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
            echo "  \"target\": \"$target\","
            echo "  \"checks\": ["
            local check_names=("REST API Users" "Author Enumeration" "Login Error Disclosure" "Exposed Users Summary")
            local first=true; local i=0
            for check in "${checks[@]}"; do
                IFS='|' read -r st fd ex sv rm <<< "$check"
                local st_e fd_e ex_e sv_e rm_e name_e
                st_e=$(json_escape "$st"); fd_e=$(json_escape "$fd")
                ex_e=$(json_escape "$ex"); sv_e=$(json_escape "$sv"); rm_e=$(json_escape "$rm")
                name_e=$(json_escape "${check_names[$i]:-WP Check}")
                [[ "$first" == "true" ]] && first=false || echo "    ,"
                echo "    {\"name\":\"$name_e\",\"status\":\"$st_e\",\"found\":\"$fd_e\",\"expected\":\"$ex_e\",\"severity\":\"$sv_e\",\"remediation_id\":\"$rm_e\"}"
                (( i++ )) || true
            done
            echo "    ,"
            echo "    {\"name\":\"Exposed Users Summary\",\"status\":\"FAIL\",\"found\":\"$eu_count unique user(s) enumerated: $eu_e\",\"expected\":\"No usernames discoverable\",\"severity\":\"HIGH\",\"remediation_id\":\"SEC-WPUSR-001\"}"
            echo "  ]"
            echo "}"
        } > "$OUTPUT_FILE"
        print_status "FAIL" "WP users: $eu_count user(s) exposed"
        return
    fi

    {
        echo "{"
        echo "  \"step\": \"$STEP_NAME\","
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"target\": \"$target\","
        echo "  \"checks\": ["
        local check_names=("REST API Users" "Author Enumeration" "Login Error Disclosure")
        local first=true; local i=0
        for check in "${checks[@]}"; do
            IFS='|' read -r st fd ex sv rm <<< "$check"
            local st_e fd_e ex_e sv_e rm_e name_e
            st_e=$(json_escape "$st"); fd_e=$(json_escape "$fd")
            ex_e=$(json_escape "$ex"); sv_e=$(json_escape "$sv"); rm_e=$(json_escape "$rm")
            name_e=$(json_escape "${check_names[$i]:-WP Check}")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"$name_e\",\"status\":\"$st_e\",\"found\":\"$fd_e\",\"expected\":\"$ex_e\",\"severity\":\"$sv_e\",\"remediation_id\":\"$rm_e\"}"
            (( i++ )) || true
        done
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"
    print_status "PASS" "WP user enumeration: no usernames exposed"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking WordPress user enumeration: $TARGET"
    check_wp_users "$TARGET"
done
