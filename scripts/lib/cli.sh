#!/usr/bin/env bash
set -uo pipefail

_CLI_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="$_CLI_DIR/../../test_output"
TIMEOUT=10

usage() {
  echo "Usage: $0 [options] <url1> [url2 ...]"
  echo "Options:"
  echo "  -o <dir>     Output directory (default: ./test_output)"
  echo "  -t <sec>     Timeout seconds (default: 10)"
}

ARGS=()
BRUTE_FORCE=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o) OUT="$2"; shift 2 ;;
    -t) TIMEOUT="$2"; shift 2 ;;
    --brute-force) BRUTE_FORCE=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

export BRUTE_FORCE

if [[ ${#ARGS[@]} -lt 1 ]]; then
  echo "ERROR: Provide at least one target URL."
  usage
  exit 2
fi

mkdir -p "$OUT"
