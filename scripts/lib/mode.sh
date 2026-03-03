#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

# SHIELD Mode Management System
# Enforces dual-mode architecture (posture vs authorized)

# Global mode state (set by CLI parser)
SCAN_MODE="${SCAN_MODE:-posture}"  # Default: posture
ACCEPT_RISK="${ACCEPT_RISK:-false}"
AUTHORIZATION_REF="${AUTHORIZATION_REF:-}"

# Validate that authorized mode has required flags
validate_mode() {
    if [[ "$SCAN_MODE" == "authorized" ]]; then
        # Check for explicit risk acceptance
        if [[ "$ACCEPT_RISK" != "true" ]]; then
            echo "❌ ERROR: Authorized mode requires --i-accept-risk flag" >&2
            echo "" >&2
            echo "Authorized mode enables active security testing which may:" >&2
            echo "  • Trigger security alerts" >&2
            echo "  • Temporarily disrupt services" >&2
            echo "  • Create test resources (automatically cleaned up)" >&2
            echo "" >&2
            echo "Only use authorized mode against systems you own or have" >&2
            echo "written permission to test." >&2
            echo "" >&2
            echo "To proceed, add: --i-accept-risk" >&2
            return 1
        fi
        
        # Recommend authorization reference (not required, but best practice)
        if [[ -z "$AUTHORIZATION_REF" ]]; then
            echo "⚠️  WARNING: No authorization reference provided" >&2
            echo "   Consider using: --authorization-ref /path/to/authorization.pdf" >&2
            echo "   This creates an audit trail linking scans to written permission." >&2
            echo "" >&2
            sleep 2
        else
            # Verify authorization file exists
            if [[ ! -f "$AUTHORIZATION_REF" ]]; then
                echo "⚠️  WARNING: Authorization file not found: $AUTHORIZATION_REF" >&2
                echo "   File will be logged but cannot be verified." >&2
                sleep 1
            fi
        fi
        
        # Display authorization banner
        display_authorized_banner
    fi
    
    return 0
}

# Display banner for authorized mode
display_authorized_banner() {
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "🔒 AUTHORIZED SECURITY ASSESSMENT MODE"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "This mode enables controlled active security testing including:"
    echo "  • Write operation tests (auto-cleanup enabled)"
    echo "  • Authentication bypass probes"
    echo "  • Rate limit threshold measurement"
    echo "  • Session manipulation tests"
    echo ""
    echo "All active tests are:"
    echo "  ✓ Logged in audit trail"
    echo "  ✓ Rate-limited and stability-monitored"
    echo "  ✓ Non-exploitative (detection-based only)"
    echo "  ✓ Automatically cleaned up"
    echo ""
    if [[ -n "$AUTHORIZATION_REF" ]]; then
        echo "Authorization reference: $AUTHORIZATION_REF"
        echo ""
    fi
    echo "Legal Requirement: Written authorization from system owner required."
    echo "Unauthorized testing may violate computer fraud and abuse laws."
    echo ""
    echo "Press Ctrl+C within 5 seconds to abort..."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    sleep 5
    echo ""
}

# Check if a specific operation is allowed in current mode
is_operation_allowed() {
    local operation="$1"
    
    case "$operation" in
        # Operations allowed in both modes
        "passive_check"|"header_analysis"|"tls_check"|"content_scan"|"dns_query")
            return 0
            ;;
        
        # Operations only allowed in authorized mode
        "write_test"|"brute_force"|"jwt_manipulation"|"sql_injection_probe"|"active_probe")
            if [[ "$SCAN_MODE" == "authorized" ]]; then
                return 0
            else
                return 1
            fi
            ;;
        
        *)
            # Unknown operation - err on side of caution
            echo "⚠️  WARNING: Unknown operation type: $operation (defaulting to posture)" >&2
            return 1
            ;;
    esac
}

# Log mode decision in JSON output
get_mode_metadata() {
    local metadata="\"scan_mode\": \"$SCAN_MODE\""
    
    if [[ "$SCAN_MODE" == "authorized" ]]; then
        metadata="$metadata, \"authorization_ref\": \"${AUTHORIZATION_REF:-none}\""
        metadata="$metadata, \"risk_acceptance\": true"
    fi
    
    echo "$metadata"
}

# Display mode info for user
display_mode_info() {
    echo "Scan Mode: $SCAN_MODE"
    if [[ "$SCAN_MODE" == "authorized" ]]; then
        echo "  ⚠️  Active testing enabled"
        echo "  ⚠️  Audit trail: enhanced"
        echo "  ⚠️  Rate limits: enforced"
        if [[ -n "$AUTHORIZATION_REF" ]]; then
            echo "  ✓  Authorization: $AUTHORIZATION_REF"
        fi
    else
        echo "  ✓  Passive checks only"
        echo "  ✓  Safe for production"
        echo "  ✓  No authorization required"
    fi
    echo ""
}

# Export functions for use in step scripts
export -f validate_mode
export -f is_operation_allowed
export -f get_mode_metadata
export -f display_mode_info
