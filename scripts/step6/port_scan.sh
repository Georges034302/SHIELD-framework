#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

# Phase 5 - Port Scan
# TCP probes on backdoor ports, exposed DB/admin service ports, and panel ports.
# Uses /dev/tcp for portability — no nmap/nc required.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"
source "$SCRIPT_DIR/lib/output.sh"

STEP_NAME="step6_port_scan"

# Port : description : severity_if_open
PORTS=(
    "21:FTP server:MEDIUM"
    "22:SSH server:MEDIUM"
    "23:Telnet open (unencrypted remote access):HIGH"
    "25:SMTP relay:MEDIUM"
    "110:POP3 mail:LOW"
    "143:IMAP mail:LOW"
    "445:SMB/Windows file sharing (worm vector):HIGH"
    "3306:MySQL database publicly exposed:CRITICAL"
    "5432:PostgreSQL database publicly exposed:CRITICAL"
    "6379:Redis — typically unauthenticated:CRITICAL"
    "27017:MongoDB — typically unauthenticated:CRITICAL"
    "11211:Memcached — typically unauthenticated:CRITICAL"
    "9200:Elasticsearch — no auth by default:CRITICAL"
    "5984:CouchDB — check for _config exposure:HIGH"
    "2082:cPanel HTTP control panel:HIGH"
    "2083:cPanel HTTPS control panel:HIGH"
    "2086:WHM HTTP web host manager:HIGH"
    "2087:WHM HTTPS web host manager:HIGH"
    "8443:Plesk HTTPS control panel:HIGH"
    "8880:Plesk HTTP control panel:HIGH"
    "10000:Webmin control panel:HIGH"
    "8080:HTTP proxy / alternate web server:MEDIUM"
    "8888:Jupyter Notebook (often unauthenticated):CRITICAL"
    "4444:Metasploit default listener (backdoor):CRITICAL"
    "1337:Common backdoor/hacker port:HIGH"
    "31337:Back Orifice backdoor port:CRITICAL"
    "9090:Common reverse shell / web shell port:HIGH"
    "4545:Common reverse shell port:HIGH"
    "5555:ADB Android debug bridge / backdoor:HIGH"
    "7777:Known RAT/backdoor port:HIGH"
)

tcp_probe() {
    local host="$1"
    local port="$2"
    local timeout="${3:-3}"
    # Use bash /dev/tcp; suppress all stderr
    (timeout "$timeout" bash -c "echo >/dev/tcp/$host/$port" 2>/dev/null) && echo "open" || echo "closed"
}

check_ports() {
    local target="$1"
    local hostname
    hostname=$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##' | sed 's/:.*$//')

    local open_critical=() open_high=() open_medium=() open_low=()

    for entry in "${PORTS[@]}"; do
        local port="${entry%%:*}"
        local rest="${entry#*:}"
        local desc="${rest%:*}"
        local sev="${rest##*:}"

        local state
        state=$(tcp_probe "$hostname" "$port" 3)

        if [[ "$state" == "open" ]]; then
            case "$sev" in
                CRITICAL) open_critical+=("$port/tcp OPEN: $desc") ;;
                HIGH)     open_high+=("$port/tcp OPEN: $desc") ;;
                MEDIUM)   open_medium+=("$port/tcp OPEN: $desc") ;;
                LOW)      open_low+=("$port/tcp OPEN: $desc") ;;
            esac
        fi
    done

    local OUTPUT_DIR="$OUT/step6"
    mkdir -p "$OUTPUT_DIR"
    local OUTPUT_FILE="$OUTPUT_DIR/port_scan.json"

    local total=$(( ${#open_critical[@]} + ${#open_high[@]} + ${#open_medium[@]} + ${#open_low[@]} ))

    {
        echo "{"
        echo "  \"step\": \"$STEP_NAME\","
        echo "  \"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\","
        echo "  \"target\": \"$target\","
        echo "  \"checks\": ["
        local first=true

        if [[ ${#open_critical[@]} -gt 0 ]]; then
            local c_str; c_str=$(IFS="; "; printf '%s' "${open_critical[*]}")
            local c_e; c_e=$(json_escape "$c_str")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"Critical Ports Open\",\"status\":\"FAIL\",\"found\":\"$c_e\",\"expected\":\"No database/backdoor ports accessible from internet\",\"severity\":\"CRITICAL\",\"remediation_id\":\"SEC-PORT-001\"}"
        fi

        if [[ ${#open_high[@]} -gt 0 ]]; then
            local h_str; h_str=$(IFS="; "; printf '%s' "${open_high[*]}")
            local h_e; h_e=$(json_escape "$h_str")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"High-Risk Ports Open\",\"status\":\"FAIL\",\"found\":\"$h_e\",\"expected\":\"Admin/panel ports restricted to known IPs\",\"severity\":\"HIGH\",\"remediation_id\":\"SEC-PORT-001\"}"
        fi

        if [[ ${#open_medium[@]} -gt 0 ]]; then
            local m_str; m_str=$(IFS="; "; printf '%s' "${open_medium[*]}")
            local m_e; m_e=$(json_escape "$m_str")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"Medium-Risk Ports Open\",\"status\":\"WARN\",\"found\":\"$m_e\",\"expected\":\"Limit service exposure\",\"severity\":\"MEDIUM\",\"remediation_id\":\"SEC-PORT-002\"}"
        fi

        if [[ ${#open_low[@]} -gt 0 ]]; then
            local l_str; l_str=$(IFS="; "; printf '%s' "${open_low[*]}")
            local l_e; l_e=$(json_escape "$l_str")
            [[ "$first" == "true" ]] && first=false || echo "    ,"
            echo "    {\"name\":\"Low-Risk Ports Open\",\"status\":\"INFO\",\"found\":\"$l_e\",\"expected\":\"Review open services\",\"severity\":\"LOW\",\"remediation_id\":\"\"}"
        fi

        if [[ $total -eq 0 ]]; then
            echo "    {\"name\":\"Port Scan\",\"status\":\"PASS\",\"found\":\"No unexpected ports open across ${#PORTS[@]} probed ports\",\"expected\":\"Only 80/443 accessible\",\"severity\":\"INFO\",\"remediation_id\":\"\"}"
        fi

        echo "  ]"
        echo "}"
    } > "$OUTPUT_FILE"

    if [[ ${#open_critical[@]} -gt 0 ]]; then
        print_status "FAIL" "Port scan: ${#open_critical[@]} CRITICAL ports open"
    elif [[ ${#open_high[@]} -gt 0 ]]; then
        print_status "FAIL" "Port scan: ${#open_high[@]} high-risk ports open"
    elif [[ $total -gt 0 ]]; then
        print_status "WARN" "Port scan: $total ports open (review)"
    else
        print_status "PASS" "Port scan: no unexpected ports open"
    fi
}

for TARGET in "${ARGS[@]}"; do
    print_status "INFO" "Scanning ports: $TARGET"
    check_ports "$TARGET"
done
