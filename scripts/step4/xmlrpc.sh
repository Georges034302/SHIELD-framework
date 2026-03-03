#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

# Phase 5 - WordPress XMLRPC Exploitation Check
# Tests if xmlrpc.php is accessible, accepts method calls, allows credential
# stuffing via system.multicall (1 request = N login attempts).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"
source "$SCRIPT_DIR/lib/wp_detect.sh"

STEP_NAME="step4_xmlrpc"

check_xmlrpc() {
    local target="$1"
    local base_url
    base_url=$(echo "$target" | sed 's|/$||')

    local OUTPUT_DIR="$OUT/step4"
    mkdir -p "$OUTPUT_DIR"
    local OUTPUT_FILE="$OUTPUT_DIR/xmlrpc.json"

    detect_wordpress "$target"

    if [[ "$WP_DETECTED" != "true" ]]; then
        {
            echo "{"
            echo "  \"step\": \"$STEP_NAME\","
            echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
            echo "  \"target\": \"$target\","
            echo "  \"checks\": ["
            echo "    {\"name\":\"XMLRPC Check\",\"status\":\"INFO\",\"found\":\"WordPress not detected\",\"expected\":\"N/A\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
            echo "  ]"
            echo "}"
        } > "$OUTPUT_FILE"
        print_status "INFO" "XMLRPC: WordPress not detected — skipped"
        return
    fi

    local checks=()
    local xmlrpc_url="${base_url}/xmlrpc.php"

    # ── 1. Basic accessibility (HEAD) ─────────────────────────────────────────
    local head_code
    head_code=$(curl -sS -o /dev/null -w "%{http_code}" --max-time "${TIMEOUT:-8}" \
        -X HEAD "$xmlrpc_url" 2>/dev/null || echo "000")

    if [[ "$head_code" == "200" || "$head_code" == "405" ]]; then
        # ── 2. POST system.listMethods ─────────────────────────────────────────
        local list_resp
        list_resp=$(curl -sS -L --max-time "${TIMEOUT:-8}" \
            -H "Content-Type: text/xml" \
            -d '<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>' \
            "$xmlrpc_url" 2>/dev/null || echo "")

        if echo "$list_resp" | grep -q '<methodResponse>'; then
            # Extract method list
            local methods
            methods=$(echo "$list_resp" | grep -oE '<string>[^<]+</string>' | sed 's|<[^>]*>||g' | tr '\n' ', ' | sed 's/, $//' || echo "")
            local method_count; method_count=$(echo "$list_resp" | grep -c '<string>' || echo "0")

            checks+=("FAIL|xmlrpc.php active and responding to system.listMethods — $method_count methods available|xmlrpc.php blocked or disabled|HIGH|SEC-XMLRPC-001")

            # ── 3. Multicall amplification test ───────────────────────────────
            # system.multicall allows batching N login attempts in 1 HTTP request
            if echo "$methods" | grep -q "wp.getUsersBlogs\|system.multicall"; then
                local multicall_resp
                multicall_resp=$(curl -sS -L --max-time "${TIMEOUT:-8}" \
                    -H "Content-Type: text/xml" \
                    -d '<?xml version="1.0" encoding="UTF-8"?><methodCall><methodName>system.multicall</methodName><params><param><value><array><data>
<value><struct><member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
<member><name>params</name><value><array><data>
<value><array><data><value><string>admin</string></value><value><string>password1</string></value></data></array></value>
</data></array></value></member></struct></value>
</data></array></value></param></params></methodCall>' \
                    "$xmlrpc_url" 2>/dev/null || echo "")

                if echo "$multicall_resp" | grep -q '<methodResponse>'; then
                    checks+=("FAIL|system.multicall enabled — allows batching 100+ credential attempts per HTTP request (brute force amplification)|Disable xmlrpc.php entirely|CRITICAL|SEC-XMLRPC-002")
                fi
            fi

            # ── 4. Pingback SSRF ──────────────────────────────────────────────
            if echo "$methods" | grep -q "pingback.ping"; then
                checks+=("WARN|pingback.ping method available — can be used for SSRF and DDoS amplification|Disable xmlrpc.php or block pingback.ping|HIGH|SEC-XMLRPC-003")
            fi

        else
            checks+=("WARN|xmlrpc.php accessible (HTTP $head_code) but did not respond to method call — may be partially disabled|Block xmlrpc.php entirely|MEDIUM|SEC-XMLRPC-001")
        fi
    elif [[ "$head_code" == "403" || "$head_code" == "404" ]]; then
        checks+=("PASS|xmlrpc.php blocked or removed (HTTP $head_code)|N/A|INFO|")
    elif [[ "$head_code" == "301" || "$head_code" == "302" ]]; then
        checks+=("INFO|xmlrpc.php redirects (HTTP $head_code) — verify redirection target is not accessible|N/A|LOW|")
    else
        checks+=("INFO|xmlrpc.php returned HTTP $head_code|N/A|INFO|")
    fi

    {
        echo "{"
        echo "  \"step\": \"$STEP_NAME\","
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"target\": \"$target\","
        echo "  \"checks\": ["
        local check_names=("XMLRPC Accessibility" "Method Enumeration" "Multicall Amplification" "Pingback SSRF")
        local first=true
        local i=0
        for check in "${checks[@]}"; do
            IFS='|' read -r st fd ex sv rm <<< "$check"
            local st_e fd_e ex_e sv_e rm_e name_e
            st_e=$(json_escape "$st"); fd_e=$(json_escape "$fd")
            ex_e=$(json_escape "$ex"); sv_e=$(json_escape "$sv"); rm_e=$(json_escape "$rm")
            name_e=$(json_escape "${check_names[$i]:-XMLRPC Check}")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"$name_e\",\"status\":\"$st_e\",\"found\":\"$fd_e\",\"expected\":\"$ex_e\",\"severity\":\"$sv_e\",\"remediation_id\":\"$rm_e\"}"
            (( i++ )) || true
        done
        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    local has_crit=false
    for c in "${checks[@]}"; do [[ "$c" =~ CRITICAL ]] && has_crit=true; done
    $has_crit && print_status "FAIL" "XMLRPC: CRITICAL — multicall brute force amplification active" && return

    local has_fail=false
    for c in "${checks[@]}"; do [[ "$c" == FAIL* ]] && has_fail=true; done
    $has_fail && print_status "FAIL" "XMLRPC: active and potentially exploitable" && return
    print_status "PASS" "XMLRPC check complete"
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Checking XMLRPC: $TARGET"
    check_xmlrpc "$TARGET"
done
