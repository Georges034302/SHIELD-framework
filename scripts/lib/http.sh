#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

# HTTP utilities for making requests and parsing responses

# Fetch HTTP headers
fetch_headers() {
    local url="$1"
    local timeout="${2:-10}"
    
    curl -sS -I --max-time "$timeout" --location "$url" 2>/dev/null
}

# Fetch full response with headers
fetch_full() {
    local url="$1"
    local timeout="${2:-10}"
    
    curl -sS -i --max-time "$timeout" --location "$url" 2>/dev/null
}

# Get specific header value (case-insensitive)
get_header() {
    local headers="$1"
    local header_name="$2"
    
    echo "$headers" | grep -i "^${header_name}:" | cut -d: -f2- | sed 's/^[[:space:]]*//' | tr -d '\r' || true
}

# Check if header exists
has_header() {
    local headers="$1"
    local header_name="$2"
    
    echo "$headers" | grep -qi "^${header_name}:" && return 0 || return 1
}

# Get HTTP status code
get_status_code() {
    local headers="$1"
    
    echo "$headers" | head -n1 | grep -oE '[0-9]{3}' | head -n1
}

# Check if URL redirects to HTTPS
check_https_redirect() {
    local url="$1"
    
    # Make request without following redirects
    local response=$(curl -sS -I --max-time 10 "$url" 2>/dev/null)
    local status=$(echo "$response" | head -n1 | grep -oE '[0-9]{3}')
    local location=$(get_header "$response" "Location")
    
    if [[ "$status" =~ ^30[1237]$ ]] && [[ "$location" =~ ^https:// ]]; then
        echo "true"
    else
        echo "false"
    fi
}

# Parse cookies from Set-Cookie headers
parse_cookies() {
    local headers="$1"
    
    echo "$headers" | grep -i "^Set-Cookie:" | sed 's/^Set-Cookie: //i'
}

# Check cookie flags
check_cookie_flags() {
    local cookie="$1"
    local flag="$2"
    
    if echo "$cookie" | grep -qi "[;[:space:]]${flag}"; then
        echo "true"
    else
        echo "false"
    fi
}
