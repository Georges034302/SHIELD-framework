#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

# SHIELD Stability Monitoring System
# Prevents damage to unstable targets by monitoring error rates

# Global stability tracking
declare -A STABILITY_COUNTERS=(
    [total_requests]=0
    [successful_requests]=0
    [failed_requests]=0
    [rate_limited_requests]=0
    [server_error_requests]=0
)

declare -a STABILITY_EVENTS=()

# Track a response code
track_response_code() {
    local code="$1"
    local url="${2:-unknown}"
    
    ((STABILITY_COUNTERS[total_requests]++))
    
    if [[ "$code" == "200" ]] || [[ "$code" == "301" ]] || [[ "$code" == "302" ]] || [[ "$code" == "304" ]]; then
        ((STABILITY_COUNTERS[successful_requests]++))
    elif [[ "$code" == "429" ]]; then
        ((STABILITY_COUNTERS[rate_limited_requests]++))
        log_stability_event "rate_limit" "Rate limit hit (429) for $url"
    elif [[ "$code" =~ ^5[0-9]{2}$ ]]; then
        ((STABILITY_COUNTERS[server_error_requests]++))
        ((STABILITY_COUNTERS[failed_requests]++))
        log_stability_event "server_error" "Server error (${code}) for $url"
    else
        ((STABILITY_COUNTERS[failed_requests]++))
    fi
}

# Log a stability event
log_stability_event() {
    local event_type="$1"
    local message="$2"
    local timestamp
    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    local event="{\"timestamp\": \"$timestamp\", \"type\": \"$event_type\", \"message\": \"$message\"}"
    STABILITY_EVENTS+=("$event")
    
    # Also log to stderr for immediate visibility
    if [[ "$event_type" == "server_error" ]] || [[ "$event_type" == "abort" ]]; then
        echo "⚠️  STABILITY: $message" >&2
    fi
}

# Check if we should abort due to instability
should_abort() {
    local total=${STABILITY_COUNTERS[total_requests]}
    
    # Need at least 10 requests to assess stability
    if [[ $total -lt 10 ]]; then
        return 1  # Don't abort yet
    fi
    
    local server_errors=${STABILITY_COUNTERS[server_error_requests]}
    local error_percentage=$((server_errors * 100 / total))
    
    # Abort if >10% 5xx errors
    if [[ $error_percentage -gt 10 ]]; then
        log_stability_event "abort" "Server error rate too high (${error_percentage}%, threshold: 10%). Aborting to prevent damage."
        echo "" >&2
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
        echo "🛑 SCAN ABORTED: Target Instability Detected" >&2
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
        echo "" >&2
        echo "Server error rate: ${error_percentage}% (threshold: 10%)" >&2
        echo "Total requests: $total" >&2
        echo "Server errors (5xx): $server_errors" >&2
        echo "" >&2
        echo "Possible causes:" >&2
        echo "  • Target is under high load" >&2
        echo "  • Target is experiencing technical issues" >&2
        echo "  • WAF/rate limiting is being triggered" >&2
        echo "  • Scan rate is too aggressive" >&2
        echo "" >&2
        echo "Recommendations:" >&2
        echo "  • Wait and retry later" >&2
        echo "  • Use --rate-aware mode to slow down requests" >&2
        echo "  • Contact system administrator" >&2
        echo "" >&2
        echo "Partial results have been saved to output directory." >&2
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >&2
        return 0  # Should abort
    fi
    
    return 1  # Don't abort
}

# Check stability before continuing
check_stability() {
    if should_abort; then
        # Return error code to trigger script exit
        return 1
    fi
    return 0
}

# Get stability summary for JSON output
get_stability_summary() {
    local total=${STABILITY_COUNTERS[total_requests]}
    local successful=${STABILITY_COUNTERS[successful_requests]}
    local failed=${STABILITY_COUNTERS[failed_requests]}
    local rate_limited=${STABILITY_COUNTERS[rate_limited_requests]}
    local server_errors=${STABILITY_COUNTERS[server_error_requests]}
    
    local events_json=""
    if [[ ${#STABILITY_EVENTS[@]} -gt 0 ]]; then
        events_json=$(printf '%s\n' "${STABILITY_EVENTS[@]}" | paste -sd, -)
    fi
    
    cat <<EOF
"stability": {
  "total_requests": $total,
  "successful_requests": $successful,
  "failed_requests": $failed,
  "rate_limited_requests": $rate_limited,
  "server_error_requests": $server_errors,
  "events": [$events_json]
}
EOF
}

# Reset stability counters (useful for multi-target scans)
reset_stability_counters() {
    STABILITY_COUNTERS=(
        [total_requests]=0
        [successful_requests]=0
        [failed_requests]=0
        [rate_limited_requests]=0
        [server_error_requests]=0
    )
    STABILITY_EVENTS=()
}

# Display stability statistics
display_stability_stats() {
    local total=${STABILITY_COUNTERS[total_requests]}
    if [[ $total -eq 0 ]]; then
        return
    fi
    
    local successful=${STABILITY_COUNTERS[successful_requests]}
    local rate_limited=${STABILITY_COUNTERS[rate_limited_requests]}
    local server_errors=${STABILITY_COUNTERS[server_error_requests]}
    
    echo ""
    echo "Stability Summary:"
    echo "  Total requests: $total"
    echo "  Successful: $successful"
    echo "  Rate limited (429): $rate_limited"
    echo "  Server errors (5xx): $server_errors"
    
    if [[ ${#STABILITY_EVENTS[@]} -gt 0 ]]; then
        echo "  Events logged: ${#STABILITY_EVENTS[@]}"
    fi
}

# Export functions
export -f track_response_code
export -f log_stability_event
export -f should_abort
export -f check_stability
export -f get_stability_summary
export -f reset_stability_counters
export -f display_stability_stats
