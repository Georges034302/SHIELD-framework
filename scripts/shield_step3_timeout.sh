#!/usr/bin/env bash
source "$(dirname "$0")/lib/cli.sh"

for TARGET in "${ARGS[@]}"; do
  echo "Running SHIELD step on $TARGET"
  curl -I --max-time "$TIMEOUT" "$TARGET" > "$OUT/$(basename "$0")_$(echo $TARGET | sed 's#https://##; s#/#_#g').txt"
done
