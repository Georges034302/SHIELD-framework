#!/usr/bin/env bash
# SHIELD Rate-Aware Mode
# Respectful scanning that avoids WAF blacklisting

# Configuration (can be overridden by policy or CLI)
RATE_AWARE="${RATE_AWARE:-false}"
ROTATE_UA="${ROTATE_UA:-false}"
DELAY_MIN_MS="${DELAY_MIN_MS:-500}"
DELAY_MAX_MS="${DELAY_MAX_MS:-2000}"

# Handle Retry-After header
handle_retry_after() {
    local headers="$1"
    
    # Extract Retry-After header value (case-insensitive)
    local retry_after
    retry_after=$(echo "$headers" | grep -i "^Retry-After:" | head -n1 | cut -d: -f2 | tr -d ' \r\n')
    
    if [[ -n "$retry_after" ]]; then
        # Could be seconds or HTTP date - we'll handle seconds only for simplicity
        if [[ "$retry_after" =~ ^[0-9]+$ ]]; then
            if [[ "$retry_after" -gt 300 ]]; then
                # Cap at 5 minutes to avoid indefinite hanging
                retry_after=300
            fi
            
            echo "⏳ Server requested delay: ${retry_after}s (Retry-After header)" >&2
            
            # Log to stability events if available
            if declare -f log_stability_event >/dev/null 2>&1; then
                log_stability_event "retry_after" "Honoring Retry-After: ${retry_after}s"
            fi
            
            sleep "$retry_after"
            return 0
        fi
    fi
    
    return 1
}

# Handle rate limiting with exponential backoff
handle_rate_limit() {
    local attempt="${1:-1}"
    local max_delay=60
    
    # Exponential backoff: 2^attempt seconds (2, 4, 8, 16, 32, 60)
    local delay=$((2 ** attempt))
    
    if [[ $delay -gt $max_delay ]]; then
        delay=$max_delay
    fi
    
    echo "⏳ Rate limited, backing off for ${delay}s (attempt $attempt)..." >&2
    
    # Log to stability events if available
    if declare -f log_stability_event >/dev/null 2>&1; then
        log_stability_event "rate_limit_backoff" "Exponential backoff: ${delay}s (attempt $attempt)"
    fi
    
    sleep "$delay"
}

# Add rate-aware delay between requests
add_rate_aware_delay() {
    if [[ "$RATE_AWARE" != "true" ]]; then
        return
    fi
    
    # Random delay between DELAY_MIN_MS and DELAY_MAX_MS
    local range=$((DELAY_MAX_MS - DELAY_MIN_MS))
    local random_ms=$((DELAY_MIN_MS + (RANDOM % range)))
    
    # Convert milliseconds to seconds (bash sleep accepts fractional seconds)
    local delay_seconds=$(awk "BEGIN {printf \"%.3f\", $random_ms / 1000}")
    
    sleep "$delay_seconds"
}

# Get appropriate User-Agent for request
get_user_agent() {
    if [[ "$ROTATE_UA" == "true" ]]; then
        # Array of common browser User-Agents
        local user_agents=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0"
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2.1 Safari/605.1.15"
        )
        
        # Select random User-Agent
        local random_index=$((RANDOM % ${#user_agents[@]}))
        echo "${user_agents[$random_index]}"
    else
        # Default SHIELD User-Agent (identifies the scanner)
        echo "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 SHIELD-Security-Scanner/2.0"
    fi
}

# Perform rate-aware HTTP request with retry logic
rate_aware_curl() {
    local url="$1"
    shift
    local max_retries=3
    local attempt=1
    
    while [[ $attempt -le $max_retries ]]; do
        # Add rate-aware delay before request (except first attempt)
        if [[ $attempt -gt 1 ]] || [[ "$RATE_AWARE" == "true" ]]; then
            add_rate_aware_delay
        fi
        
        # Get User-Agent
        local ua
        ua=$(get_user_agent)
        
        # Perform request and capture both headers and body
        local response
        local http_code
        
        response=$(curl -sS -D - --user-agent "$ua" --max-time "${TIMEOUT:-15}" "$@" "$url" 2>&1)
        http_code=$(echo "$response" | grep -i "^HTTP/" | tail -n1 | awk '{print $2}')
        
        # Track response for stability monitoring
        if declare -f track_response_code >/dev/null 2>&1; then
            track_response_code "$http_code" "$url"
        fi
        
        # Handle rate limiting
        if [[ "$http_code" == "429" ]] || [[ "$http_code" == "503" ]]; then
            # Try to honor Retry-After header
            if ! handle_retry_after "$response"; then
                # Fall back to exponential backoff
                handle_rate_limit "$attempt"
            fi
            
            ((attempt++))
            continue
        fi
        
        # Success or non-retryable error
        echo "$response"
        return 0
    done
    
    # Max retries exceeded
    echo "⚠️  Max retries exceeded for: $url" >&2
    return 1
}

# Display rate-aware mode info
display_rate_aware_info() {
    if [[ "$RATE_AWARE" == "true" ]]; then
        echo "Rate-Aware Mode: enabled"
        echo "  Delay range: ${DELAY_MIN_MS}ms - ${DELAY_MAX_MS}ms"
        echo "  Retry-After: honored"
        echo "  Exponential backoff: enabled"
        if [[ "$ROTATE_UA" == "true" ]]; then
            echo "  User-Agent: rotating"
        else
            echo "  User-Agent: SHIELD identifier"
        fi
    fi
}

# Export functions
export -f handle_retry_after
export -f handle_rate_limit
export -f add_rate_aware_delay
export -f get_user_agent
export -f rate_aware_curl
export -f display_rate_aware_info
