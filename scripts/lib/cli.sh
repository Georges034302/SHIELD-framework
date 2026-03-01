#!/usr/bin/env bash
set -uo pipefail

_CLI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$_CLI_DIR/../../test_output"
TIMEOUT=10

usage() {
  echo "Usage: $0 [options] <url1> [url2 ...]"
  echo "Options:"
  echo "  -o <dir>         Output directory (default: ./test_output)"
  echo "  -t <sec>         Timeout seconds (default: 10)"
  echo "  --brute-force    Enable brute force lockout testing"
  echo "  --user <name>    WordPress admin username (enables authenticated tests)"
  echo "  --pass <pass>    WordPress admin password (required with --user)"
}

ARGS=()
BRUTE_FORCE=false
WP_USER=""
WP_PASS=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) OUT="$2"; shift 2 ;;
    -t) TIMEOUT="$2"; shift 2 ;;
    --brute-force) BRUTE_FORCE=true; shift ;;
    --user) WP_USER="$2"; shift 2 ;;
    --pass) WP_PASS="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

export BRUTE_FORCE
export WP_USER
export WP_PASS

if [[ ${#ARGS[@]} -lt 1 ]]; then
  echo "ERROR: Provide at least one target URL."
  usage
  exit 2
fi

mkdir -p "$OUT"
