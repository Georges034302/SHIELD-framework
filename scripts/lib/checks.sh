#!/usr/bin/env bash
# Common security check functions

# Check if HSTS header is present and valid
check_hsts() {
    local headers="$1"
    local hsts=$(get_header "$headers" "Strict-Transport-Security")
    
    if [ -z "$hsts" ]; then
        echo "FAIL|missing|max-age >= 31536000"
        return 1
    fi
    
    # Extract max-age value
    local max_age=$(echo "$hsts" | grep -oE 'max-age=([0-9]+)' | cut -d= -f2 || true)
    
    if [ -z "$max_age" ]; then
        echo "FAIL|$hsts|max-age >= 31536000"
        return 1
    fi
    
    if [ "$max_age" -ge 31536000 ]; then
        echo "PASS|$hsts|max-age >= 31536000"
        return 0
    else
        echo "WARN|$hsts|max-age >= 31536000"
        return 2
    fi
}

# Check X-Frame-Options or CSP frame-ancestors
check_clickjacking() {
    local headers="$1"
    local xfo=$(get_header "$headers" "X-Frame-Options")
    local csp=$(get_header "$headers" "Content-Security-Policy")
    
    if [ -n "$xfo" ] && [[ "$xfo" =~ (DENY|SAMEORIGIN) ]]; then
        echo "PASS|X-Frame-Options: $xfo|DENY or SAMEORIGIN"
        return 0
    fi
    
    if [ -n "$csp" ] && echo "$csp" | grep -q "frame-ancestors"; then
        echo "PASS|CSP frame-ancestors present|frame-ancestors directive"
        return 0
    fi
    
    echo "FAIL|missing|X-Frame-Options: DENY/SAMEORIGIN or CSP frame-ancestors"
    return 1
}

# Check X-Content-Type-Options
check_content_type_options() {
    local headers="$1"
    local xcto=$(get_header "$headers" "X-Content-Type-Options")
    
    if [ -n "$xcto" ] && [[ "$xcto" =~ nosniff ]]; then
        echo "PASS|$xcto|nosniff"
        return 0
    else
        echo "FAIL|${xcto:-missing}|nosniff"
        return 1
    fi
}

# Check Referrer-Policy
check_referrer_policy() {
    local headers="$1"
    local rp=$(get_header "$headers" "Referrer-Policy")
    
    if [ -z "$rp" ]; then
        echo "WARN|missing|strict-origin-when-cross-origin or stricter"
        return 2
    fi
    
    # Good policies
    if [[ "$rp" =~ (no-referrer|strict-origin|strict-origin-when-cross-origin|same-origin) ]]; then
        echo "PASS|$rp|restrictive policy"
        return 0
    else
        echo "WARN|$rp|consider stricter policy"
        return 2
    fi
}

# Check for security.txt
check_security_txt() {
    local url="$1"
    local base_url=$(echo "$url" | sed -E 's#(https?://[^/]+).*#\1#')
    
    # Check /.well-known/security.txt
    local status=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 5 "${base_url}/.well-known/security.txt" 2>/dev/null)
    
    if [ "$status" = "200" ]; then
        echo "PASS|found at /.well-known/security.txt|security.txt present"
        return 0
    fi
    
    echo "INFO|not found|optional but recommended"
    return 3
}
