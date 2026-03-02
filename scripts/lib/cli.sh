#!/usr/bin/env bash
set -uo pipefail

_CLI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$_CLI_DIR/../../test_output"
TIMEOUT=10

usage() {
  echo "Usage: $0 [options] <url1> [url2 ...]"
  echo ""
  echo "Basic Options:"
  echo "  -o <dir>                  Output directory (default: ./test_output)"
  echo "  -t <sec>                  Timeout seconds (default: 10)"
  echo "  -h, --help                Print this help message"
  echo ""
  echo "Scan Mode (Phase 6):"
  echo "  --mode <posture|authorized>   Scan mode (default: posture)"
  echo "    posture    = Passive checks only (safe for production)"
  echo "    authorized = Active testing (requires --i-accept-risk)"
  echo ""
  echo "Authorized Mode Flags:"
  echo "  --i-accept-risk           Required for authorized mode"
  echo "  --authorization-ref <file>   Path to authorization document (recommended)"
  echo ""
  echo "WordPress Testing:"
  echo "  --user <name>             WordPress admin username (enables authenticated tests)"
  echo "  --pass <pass>             WordPress admin password (required with --user)"
  echo "  --brute-force             Enable brute force lockout testing (authorized mode)"
  echo ""
  echo "Rate Control:"
  echo "  --rate-aware              Enable respectful scanning with delays"
  echo "  --rotate-ua               Rotate User-Agent strings (optional)"
  echo "  --delay-min <ms>          Minimum delay between requests (default: 500)"
  echo "  --delay-max <ms>          Maximum delay between requests (default: 2000)"
  echo "  --max-requests <n>        Max requests per minute (default: 60)"
  echo ""
  echo "Examples:"
  echo "  # Basic posture scan (safe for production)"
  echo "  $0 https://example.com"
  echo ""
  echo "  # With rate-aware mode"
  echo "  $0 --rate-aware https://example.com"
  echo ""
  echo "  # Authorized security assessment"
  echo "  $0 --mode authorized --i-accept-risk --authorization-ref auth.pdf https://example.com"
}

# Default values
ARGS=()
BRUTE_FORCE=false
WP_USER=""
WP_PASS=""

# Phase 6A: Mode management
SCAN_MODE="posture"
ACCEPT_RISK=false
AUTHORIZATION_REF=""

# Phase 6A: Rate control
RATE_AWARE=false
ROTATE_UA=false
DELAY_MIN_MS=500
DELAY_MAX_MS=2000
MAX_REQUESTS_PER_MINUTE=60

while [[ $# -gt 0 ]]; do
  case "$1" in
    # Basic options
    -o) OUT="$2"; shift 2 ;;
    -t) TIMEOUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    
    # Mode management
    --mode) SCAN_MODE="$2"; shift 2 ;;
    --i-accept-risk) ACCEPT_RISK=true; shift ;;
    --authorization-ref) AUTHORIZATION_REF="$2"; shift 2 ;;
    
    # WordPress testing
    --user) WP_USER="$2"; shift 2 ;;
    --pass) WP_PASS="$2"; shift 2 ;;
    --brute-force) BRUTE_FORCE=true; shift ;;
    
    # Rate control
    --rate-aware) RATE_AWARE=true; shift ;;
    --rotate-ua) ROTATE_UA=true; shift ;;
    --delay-min) DELAY_MIN_MS="$2"; shift 2 ;;
    --delay-max) DELAY_MAX_MS="$2"; shift 2 ;;
    --max-requests) MAX_REQUESTS_PER_MINUTE="$2"; shift 2 ;;
    
    # Targets
    *) ARGS+=("$1"); shift ;;
  esac
done

# Validate mode
if [[ "$SCAN_MODE" != "posture" && "$SCAN_MODE" != "authorized" ]]; then
  echo "ERROR: Invalid mode '$SCAN_MODE'. Must be 'posture' or 'authorized'." >&2
  usage
  exit 2
fi

# Export all variables for use in step scripts
export OUT
export TIMEOUT
export BRUTE_FORCE
export WP_USER
export WP_PASS
export SCAN_MODE
export ACCEPT_RISK
export AUTHORIZATION_REF
export RATE_AWARE
export ROTATE_UA
export DELAY_MIN_MS
export DELAY_MAX_MS
export MAX_REQUESTS_PER_MINUTE

# Source Phase 6A libraries
source "$_CLI_DIR/mode.sh"
source "$_CLI_DIR/stability.sh"
source "$_CLI_DIR/rate_aware.sh"

# Validate mode requirements
if ! validate_mode; then
  exit 2
fi

# Mode validation complete - all authorized mode checks done in validate_mode()

if [[ ${#ARGS[@]} -lt 1 ]]; then
  echo "ERROR: Provide at least one target URL."
  usage
  exit 2
fi

mkdir -p "$OUT"
