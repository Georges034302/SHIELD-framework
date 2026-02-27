#!/usr/bin/env bash
# SHIELD Framework - Run All Security Checks
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/lib/cli.sh"

echo "================================================"
echo "  SHIELD Security Assessment Framework"
echo "================================================"
echo ""
echo "Target(s): ${ARGS[*]}"
echo "Output directory: $OUT"
echo ""

# Create output directory structure
mkdir -p "$OUT"/{step1,step2,step3,step4,step5,step6}

# Run all step scripts
STEPS=(
    "step1/scope.sh"
    "step2/headers.sh"
    "step2/https.sh"
    "step2/tls.sh"
    "step2/exposure.sh"
    "step3/cookie_flags.sh"
    "step3/discover.sh"
    "step3/logout.sh"
    "step3/ratelimit.sh"
    "step3/session_rotation.sh"
    "step3/timeout.sh"
    "step4/access_control.sh"
    "step5/owasp_defensive.sh"
    "step6/infra_exposure.sh"
)

for script in "${STEPS[@]}"; do
    script_path="$SCRIPT_DIR/$script"
    if [[ -f "$script_path" ]]; then
        echo "▶ Running $(basename "$script" .sh)..."
        bash "$script_path" "${ARGS[@]}" -o "$OUT" || echo "  ⚠ Warning: $script had errors"
        echo ""
    fi
done

echo "================================================"
echo "  Assessment Complete"
echo "================================================"
echo "Results saved to: $OUT"
echo ""
echo "Generating consolidated report..."
"$SCRIPT_DIR/generate_report.sh" -i "$OUT" -o "$OUT/report.md"
echo ""
echo "✓ Full report available at: $OUT/report.md"
echo ""
