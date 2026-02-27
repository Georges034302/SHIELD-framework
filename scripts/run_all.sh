#!/usr/bin/env bash
source "$(dirname "$0")/lib/cli.sh"

for script in shield_step*.sh; do
  if [[ "$script" != "run_all.sh" ]]; then
    bash "$(dirname "$0")/$script" "${ARGS[@]}" -o "$OUT"
  fi
done

echo "SHIELD run complete. Results in $OUT"
