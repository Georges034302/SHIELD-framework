#!/usr/bin/env bash
source "$(dirname "$0")/lib/cli.sh"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

for script in "$SCRIPT_DIR"/shield_step*.sh; do
  if [[ -f "$script" ]]; then
    bash "$script" "${ARGS[@]}" -o "$OUT"
  fi
done

echo "SHIELD run complete. Results in $OUT"
