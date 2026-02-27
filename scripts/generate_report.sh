#!/usr/bin/env bash
# SHIELD Report Generator - Consolidate JSON outputs into final report
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INPUT_DIR=""
OUTPUT_FILE="shield_report.md"

usage() {
    echo "Usage: $0 -i <input_directory> [-o <output_file>]"
    echo "Options:"
    echo "  -i <dir>     Input directory containing step*/ JSON files"
    echo "  -o <file>    Output markdown file (default: shield_report.md)"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -i) INPUT_DIR="$2"; shift 2 ;;
        -o) OUTPUT_FILE="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1"; usage; exit 1 ;;
    esac
done

if [ -z "$INPUT_DIR" ]; then
    echo "Error: Input directory required"
    usage
    exit 1
fi

if [ ! -d "$INPUT_DIR" ]; then
    echo "Error: Input directory does not exist: $INPUT_DIR"
    exit 1
fi

REMEDIATION_DB="$SCRIPT_DIR/../data/remediation.json"

echo "Generating SHIELD Security Assessment Report..."
echo "Input: $INPUT_DIR"
echo "Output: $OUTPUT_FILE"
echo ""

# Function to count issues by severity
count_by_severity() {
    local severity="$1"
    local count=0
    
    for json_file in "$INPUT_DIR"/step*/*.json; do
        if [ -f "$json_file" ]; then
            local file_count=$(jq -r "[.checks[] | select(.severity == \"$severity\" and .status != \"PASS\")] | length" "$json_file" 2>/dev/null || echo "0")
            count=$((count + file_count))
        fi
    done
    
    echo "$count"
}

# Get target URL from first available report
TARGET=$(jq -r '.target' "$(find "$INPUT_DIR" -name '*.json' -type f | head -n1)" 2>/dev/null || echo "Unknown")
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

# Count issues
CRITICAL_COUNT=$(count_by_severity "CRITICAL")
HIGH_COUNT=$(count_by_severity "HIGH")
MEDIUM_COUNT=$(count_by_severity "MEDIUM")
LOW_COUNT=$(count_by_severity "LOW")
TOTAL_ISSUES=$((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT))

# Generate report
cat > "$OUTPUT_FILE" <<EOF
# SHIELD Security Assessment Report

**Target:** $TARGET  
**Assessment Date:** $TIMESTAMP  
**Framework Version:** 1.0.0

---

## Executive Summary

This report presents the findings from a comprehensive security assessment conducted using the SHIELD (Structured Website Security & Resilience Assessment Framework) methodology.

### Overview

| Risk Level | Count |
|------------|-------|
| 🔴 Critical | $CRITICAL_COUNT |
| 🟠 High | $HIGH_COUNT |
| 🟡 Medium | $MEDIUM_COUNT |
| 🔵 Low | $LOW_COUNT |
| **Total Issues** | **$TOTAL_ISSUES** |

### Risk Assessment

EOF

if [ "$CRITICAL_COUNT" -gt 0 ] || [ "$HIGH_COUNT" -gt 0 ]; then
    cat >> "$OUTPUT_FILE" <<EOF
**⚠️ IMMEDIATE ACTION REQUIRED**

Critical and/or high-severity security issues were identified that require immediate remediation. These vulnerabilities could lead to data breaches, unauthorized access, or other significant security incidents.

EOF
elif [ "$MEDIUM_COUNT" -gt 0 ]; then
    cat >> "$OUTPUT_FILE" <<EOF
**Moderate Risk**

Medium-severity issues were identified that should be addressed in the near term to improve security posture.

EOF
else
    cat >> "$OUTPUT_FILE" <<EOF
**Low Risk**

The target demonstrates good security practices with only minor or informational findings.

EOF
fi

cat >> "$OUTPUT_FILE" <<EOF

---

## Detailed Findings

EOF

# Process each step
for step_num in {1..6}; do
    STEP_DIR="$INPUT_DIR/step$step_num"
    
    if [ ! -d "$STEP_DIR" ]; then
        continue
    fi
    
    # Get step name
    case $step_num in
        1) STEP_TITLE="Step 1: Scope & Authorization" ;;
        2) STEP_TITLE="Step 2: External Hardening" ;;
        3) STEP_TITLE="Step 3: Authentication & Session Controls" ;;
        4) STEP_TITLE="Step 4: Authorization Review" ;;
        5) STEP_TITLE="Step 5: OWASP Defensive Controls" ;;
        6) STEP_TITLE="Step 6: Infrastructure & Exposure Surface" ;;
    esac
    
    cat >> "$OUTPUT_FILE" <<EOF

### $STEP_TITLE

EOF
    
    # Process each JSON file in the step
    for json_file in "$STEP_DIR"/*.json; do
        if [ ! -f "$json_file" ]; then
            continue
        fi
        
        CHECK_NAME=$(basename "$json_file" .json)
        
        # Get failed/warned checks
        FAILED_CHECKS=$(jq -r '.checks[] | select(.status == "FAIL" or .status == "WARN")' "$json_file" 2>/dev/null)
        
        if [ -n "$FAILED_CHECKS" ]; then
            cat >> "$OUTPUT_FILE" <<EOF

#### $(echo "$CHECK_NAME" | tr '_' ' ' | sed 's/\b\(.\)/\u\1/g')

| Check | Status | Severity | Finding |
|-------|--------|----------|---------|
EOF
            
            echo "$FAILED_CHECKS" | jq -r '. | "| \(.name) | \(.status) | \(.severity) | \(.found) |"' >> "$OUTPUT_FILE"
            
            echo "" >> "$OUTPUT_FILE"
        fi
    done
done

cat >> "$OUTPUT_FILE" <<EOF

---

## Remediation Guidance

This section provides detailed remediation steps for each identified issue.

EOF

# Generate remediation section for each unique remediation ID
REMEDIATION_IDS=()

for json_file in "$INPUT_DIR"/step*/*.json; do
    if [ -f "$json_file" ]; then
        ids=$(jq -r '.checks[] | select(.remediation_id != "" and (.status == "FAIL" or .status == "WARN")) | .remediation_id' "$json_file" 2>/dev/null || true)
        for id in $ids; do
            if [[ ! " ${REMEDIATION_IDS[@]} " =~ " ${id} " ]]; then
                REMEDIATION_IDS+=("$id")
            fi
        done
    fi
done

for rem_id in "${REMEDIATION_IDS[@]}"; do
    if [ -f "$REMEDIATION_DB" ]; then
        TITLE=$(jq -r ".\"$rem_id\".title // \"Unknown\"" "$REMEDIATION_DB")
        DESC=$(jq -r ".\"$rem_id\".description // \"No description available\"" "$REMEDIATION_DB")
        RISK=$(jq -r ".\"$rem_id\".risk // \"UNKNOWN\"" "$REMEDIATION_DB")
        IMPACT=$(jq -r ".\"$rem_id\".impact // \"Unknown impact\"" "$REMEDIATION_DB")
        REMEDY=$(jq -r ".\"$rem_id\".remediation // \"No remediation available\"" "$REMEDIATION_DB")
        REFS=$(jq -r ".\"$rem_id\".references[]? // empty" "$REMEDIATION_DB")
        
        cat >> "$OUTPUT_FILE" <<EOF

### $rem_id: $TITLE

**Risk Level:** $RISK

**Description:**  
$DESC

**Impact:**  
$IMPACT

**Remediation:**  
\`\`\`
$REMEDY
\`\`\`

EOF
        
        if [ -n "$REFS" ]; then
            echo "**References:**" >> "$OUTPUT_FILE"
            while IFS= read -r ref; do
                echo "- $ref" >> "$OUTPUT_FILE"
            done <<< "$REFS"
            echo "" >> "$OUTPUT_FILE"
        fi
    fi
done

cat >> "$OUTPUT_FILE" <<EOF

---

## Conclusion

This assessment identified **$TOTAL_ISSUES** security issues across multiple categories. Please review the detailed findings and implement the recommended remediation steps in order of severity (Critical → High → Medium → Low).

### Next Steps

1. **Immediate (24-48 hours):** Address all Critical and High severity issues
2. **Short-term (1-2 weeks):** Resolve Medium severity issues
3. **Medium-term (1 month):** Fix Low severity findings
4. **Ongoing:** Re-run SHIELD assessment monthly to verify fixes and detect new issues

### Additional Recommendations

- Implement a Web Application Firewall (WAF) for additional protection
- Enable security monitoring and logging
- Conduct regular security awareness training for development teams
- Consider professional penetration testing for comprehensive validation

---

**Report Generated:** $TIMESTAMP  
**Framework:** SHIELD v1.0.0  
**Documentation:** https://github.com/Georges034302/SHIELD-framework

EOF

echo "✓ Report generated: $OUTPUT_FILE"
echo ""
echo "Summary: $TOTAL_ISSUES issues found ($CRITICAL_COUNT critical, $HIGH_COUNT high, $MEDIUM_COUNT medium, $LOW_COUNT low)"
