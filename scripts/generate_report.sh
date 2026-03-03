#!/usr/bin/env bash
# Copyright © 2026 Georges Bou Ghantous. All Rights Reserved.
# SHIELD® — Structured Website Security & Resilience Assessment Framework
# This file is part of SHIELD Framework and is subject to the terms of the
# All Rights Reserved license included in the LICENSE file.

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

# Function to count issues by severity (excludes PASS, SKIP, INFO)
count_by_severity() {
    local severity="$1"
    local count=0
    
    for json_file in "$INPUT_DIR"/step*/*.json; do
        if [ -f "$json_file" ]; then
            local file_count=$(jq -r "[.checks[] | select(.severity == \"$severity\" and (.status == \"FAIL\" or .status == \"WARN\"))] | length" "$json_file" 2>/dev/null || echo "0")
            count=$((count + file_count))
        fi
    done
    
    echo "$count"
}

# Function to count checks by status
count_by_status() {
    local status="$1"
    local count=0
    for json_file in "$INPUT_DIR"/step*/*.json; do
        if [ -f "$json_file" ]; then
            local c=$(jq -r "[.checks[] | select(.status == \"$status\")] | length" "$json_file" 2>/dev/null || echo "0")
            count=$((count + c))
        fi
    done
    echo "$count"
}

# Detect if target is WordPress
is_wordpress() {
    if [ -f "$INPUT_DIR/step1/wp_version.json" ]; then
        local wp_status
        wp_status=$(jq -r '.checks[0].status // "SKIP"' "$INPUT_DIR/step1/wp_version.json" 2>/dev/null || echo "SKIP")
        [[ "$wp_status" != "SKIP" ]] && return 0
    fi
    return 1
}

# Compute letter grade A-F from issue counts
compute_grade() {
    local crit=$1 high=$2 med=$3
    if   [ "$crit" -ge 1 ];                        then echo "F"
    elif [ "$high" -ge 5 ];                        then echo "D"
    elif [ "$high" -ge 1 ] && [ "$med" -ge 3 ];   then echo "D"
    elif [ "$high" -ge 3 ];                        then echo "D"
    elif [ "$high" -ge 1 ];                        then echo "C"
    elif [ "$med"  -ge 5 ];                        then echo "C"
    elif [ "$med"  -ge 2 ];                        then echo "B"
    elif [ "$med"  -ge 1 ];                        then echo "B+"
    else                                                echo "A"
    fi
}

# Get target URL and metadata - prefer step1/scope.json, fall back to first sorted JSON
if [[ -f "$INPUT_DIR/step1/scope.json" ]]; then
    TARGET=$(jq -r '.target' "$INPUT_DIR/step1/scope.json" 2>/dev/null || echo "Unknown")
    SCAN_MODE=$(jq -r '.metadata.mode // "posture"' "$INPUT_DIR/step1/scope.json" 2>/dev/null || echo "posture")
else
    TARGET=$(jq -r '.target' "$(find "$INPUT_DIR" -name '*.json' -type f | sort | head -n1)" 2>/dev/null || echo "Unknown")
    SCAN_MODE="posture"
fi
TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M:%S UTC")

# Count issues
CRITICAL_COUNT=$(count_by_severity "CRITICAL")
HIGH_COUNT=$(count_by_severity "HIGH")
MEDIUM_COUNT=$(count_by_severity "MEDIUM")
LOW_COUNT=$(count_by_severity "LOW")
TOTAL_ISSUES=$((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT))
PASS_COUNT=$(count_by_status "PASS")
SKIP_COUNT=$(count_by_status "SKIP")
INFO_COUNT=$(count_by_status "INFO")
FAIL_COUNT=$(count_by_status "FAIL")
WARN_COUNT=$(count_by_status "WARN")
TOTAL_CHECKS=$((PASS_COUNT + SKIP_COUNT + INFO_COUNT + FAIL_COUNT + WARN_COUNT))
GRADE=$(compute_grade "$CRITICAL_COUNT" "$HIGH_COUNT" "$MEDIUM_COUNT")

# Generate summary report (concise overview)
SUMMARY_FILE="${OUTPUT_FILE%/*}/summary_report.md"
if [[ "$OUTPUT_FILE" != */* ]]; then
    SUMMARY_FILE="summary_report.md"
fi

cat > "$SUMMARY_FILE" <<EOF
# 🛡️ SHIELD Security Assessment Summary

**Target:** $TARGET  
**Scan Date:** $TIMESTAMP  
**Mode:** $SCAN_MODE

---

## Security Grade

<div align="center">
  <h1 style="font-size: 72px; margin: 20px 0;">$GRADE</h1>
  <p><i>Graded on: Critical (F) → High (C–D) → Medium (B–B+) → Clean (A)</i></p>
</div>

---

## Issue Overview

| Severity | Count |
|----------|-------|
| 🔴 **Critical** | **$CRITICAL_COUNT** |
| 🟠 **High** | **$HIGH_COUNT** |
| 🟡 **Medium** | **$MEDIUM_COUNT** |
| 🔵 **Low** | **$LOW_COUNT** |
| ✅ **Passed** | **$PASS_COUNT** |

**Total Issues:** $TOTAL_ISSUES | **Total Checks:** $TOTAL_CHECKS

---

## Risk Status

EOF

if [ "$CRITICAL_COUNT" -gt 0 ]; then
    cat >> "$SUMMARY_FILE" <<EOF
### ⚠️ IMMEDIATE ACTION REQUIRED

**$CRITICAL_COUNT critical vulnerabilities** detected that could lead to complete system compromise. Remediation required within 24-48 hours.

EOF
elif [ "$HIGH_COUNT" -ge 5 ]; then
    cat >> "$SUMMARY_FILE" <<EOF
### 🔶 HIGH RISK

**$HIGH_COUNT high-severity issues** identified. These vulnerabilities require immediate attention to prevent potential compromise.

EOF
elif [ "$HIGH_COUNT" -ge 1 ]; then
    cat >> "$SUMMARY_FILE" <<EOF
### 🟠 ELEVATED RISK

**$HIGH_COUNT high-severity issues** detected. Address within 1-2 weeks to maintain security posture.

EOF
elif [ "$MEDIUM_COUNT" -ge 3 ]; then
    cat >> "$SUMMARY_FILE" <<EOF
### 🟡 MODERATE RISK

**$MEDIUM_COUNT medium-severity issues** identified. Plan remediation within 2-4 weeks.

EOF
else
    cat >> "$SUMMARY_FILE" <<EOF
### ✅ LOW RISK

Security posture is generally good with only minor findings. Continue monitoring and address remaining issues as part of regular maintenance.

EOF
fi

# Build top 5 priority list from CRITICAL + HIGH findings
PRIORITY_ITEMS=""
PRIORITY_COUNT=0
for json_file in "$INPUT_DIR"/step*/*.json; do
    if [ -f "$json_file" ] && [ "$PRIORITY_COUNT" -lt 5 ]; then
        items=$(jq -r '.checks[] | select((.status == "FAIL" or .status == "WARN") and (.severity == "CRITICAL" or .severity == "HIGH")) | "**[\(.severity)]** \(.name)\n- \(.found)\n"' "$json_file" 2>/dev/null || true)
        if [ -n "$items" ]; then
            while IFS= read -r line && [ "$PRIORITY_COUNT" -lt 5 ]; do
                if [[ "$line" =~ ^\*\*\[.*\]\*\* ]]; then
                    PRIORITY_COUNT=$((PRIORITY_COUNT + 1))
                fi
                PRIORITY_ITEMS="$PRIORITY_ITEMS
$line"
            done <<< "$items"
        fi
    fi
done

if [ -n "$PRIORITY_ITEMS" ]; then
    cat >> "$SUMMARY_FILE" <<EOF

---

## Top Priority Findings

$PRIORITY_ITEMS

EOF
fi

cat >> "$SUMMARY_FILE" <<EOF

---

## Next Steps

### Immediate (24-48 hours)
- Review all **Critical** and **High** severity findings below
- Implement emergency patches for critical vulnerabilities
- Verify no active exploitation is occurring

### Short-term (1-2 weeks)
- Address remaining high-severity issues
- Implement medium-severity fixes
- Deploy security monitoring

### Ongoing
- Re-scan weekly during remediation
- Monthly scans after all issues resolved
- Implement security awareness training

---

## 📄 Full Report

For detailed technical findings, remediation guidance, OWASP mappings, and CWE references:

**➡️ [View Complete Report](./report.md)**

---

<sub>Generated by **SHIELD Framework v2.0** | $(date -u +"%Y-%m-%d %H:%M:%S UTC")</sub>
EOF

echo "✓ Summary report generated: $SUMMARY_FILE"

# Generate detailed report
cat > "$OUTPUT_FILE" <<EOF
# SHIELD Security Assessment Report

**Target:** $TARGET  
**Assessment Date:** $TIMESTAMP  
**Framework Version:** 2.0.0  
**Assessment Mode:** $SCAN_MODE

---

## Executive Summary

This report presents the findings from a comprehensive security assessment conducted using the SHIELD (Structured Website Security & Resilience Assessment Framework) methodology.

### Security Grade: **$GRADE**

> Graded on: Critical (F) → High (C–D) → Medium (B–B+) → Clean (A)

### Overview

| Metric | Count |
|--------|-------|
| 🔴 Critical | $CRITICAL_COUNT |
| 🟠 High | $HIGH_COUNT |
| 🟡 Medium | $MEDIUM_COUNT |
| 🔵 Low | $LOW_COUNT |
| ✅ Passed | $PASS_COUNT |
| ⏭ Skipped (N/A) | $SKIP_COUNT |
| **Total Checks Run** | **$TOTAL_CHECKS** |
| **Total Issues Found** | **$TOTAL_ISSUES** |

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

# Build priority action list from CRITICAL + HIGH findings
PRIORITY_ITEMS=""
for json_file in "$INPUT_DIR"/step*/*.json; do
    if [ -f "$json_file" ]; then
        items=$(jq -r '.checks[] | select((.status == "FAIL" or .status == "WARN") and (.severity == "CRITICAL" or .severity == "HIGH")) | "- **[\(.severity)]** \(.name): \(.found)"' "$json_file" 2>/dev/null || true)
        [ -n "$items" ] && PRIORITY_ITEMS="$PRIORITY_ITEMS
$items"
    fi
done

if [ -n "$PRIORITY_ITEMS" ]; then
    cat >> "$OUTPUT_FILE" <<EOF

### Priority Actions

The following Critical/High findings require immediate attention:
$PRIORITY_ITEMS

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
        5) STEP_TITLE="Step 5: Backdoor Detection & Defensive Controls" ;;
        6) STEP_TITLE="Step 6: Infrastructure & Exposure Surface" ;;
    esac
    
    cat >> "$OUTPUT_FILE" <<EOF

### $STEP_TITLE

EOF
    
    # Process each JSON file in the step — show only FAIL/WARN rows
    STEP_HAS_ISSUES=false
    STEP_BLOCK=""
    for json_file in "$STEP_DIR"/*.json; do
        if [ ! -f "$json_file" ]; then
            continue
        fi
        
        CHECK_NAME=$(basename "$json_file" .json)
        ISSUE_ROWS=$(jq -r '.checks[] | select(.status == "FAIL" or .status == "WARN") | "| \(.name) | \(.status) | \(.severity) | \(.found) |"' "$json_file" 2>/dev/null || true)
        
        if [ -n "$ISSUE_ROWS" ]; then
            STEP_HAS_ISSUES=true
            STEP_BLOCK="$STEP_BLOCK
#### ${CHECK_NAME//_/ }

| Check | Status | Severity | Finding |
|-------|--------|----------|---------|
$ISSUE_ROWS
"
        fi
    done
    
    if [ "$STEP_HAS_ISSUES" = true ]; then
        echo "$STEP_BLOCK" >> "$OUTPUT_FILE"
    else
        echo "_No issues found in this step._" >> "$OUTPUT_FILE"
        echo "" >> "$OUTPUT_FILE"
    fi
done

# WordPress-specific section
if is_wordpress; then
    WP_ISSUES=""
    for json_file in "$INPUT_DIR"/step1/wp_version.json \
                     "$INPUT_DIR"/step1/authenticate.json \
                     "$INPUT_DIR"/step3/wp_users.json \
                     "$INPUT_DIR"/step4/wp_plugins.json \
                     "$INPUT_DIR"/step4/xmlrpc.json \
                     "$INPUT_DIR"/step4/wp_debug.json \
                     "$INPUT_DIR"/step4/wp_config_exposure.json \
                     "$INPUT_DIR"/step4/installed_plugins_auth.json \
                     "$INPUT_DIR"/step4/dangerous_plugins_auth.json \
                     "$INPUT_DIR"/step4/file_editors_auth.json; do
        if [ -f "$json_file" ]; then
            rows=$(jq -r '.checks[] | select(.status == "FAIL" or .status == "WARN") | "| \(.name) | \(.status) | \(.severity) | \(.found) |"' "$json_file" 2>/dev/null || true)
            [ -n "$rows" ] && WP_ISSUES="$WP_ISSUES
$(basename "$json_file" .json | tr '_' ' '):
$rows"
        fi
    done
    
    cat >> "$OUTPUT_FILE" <<EOF

---

## WordPress-Specific Findings

WordPress was detected on this target. The following WP-specific checks were performed:

| Check | Status | Severity | Finding |
|-------|--------|----------|---------|
EOF
    for json_file in "$INPUT_DIR"/step1/wp_version.json \
                     "$INPUT_DIR"/step1/authenticate.json \
                     "$INPUT_DIR"/step3/wp_users.json \
                     "$INPUT_DIR"/step4/wp_plugins.json \
                     "$INPUT_DIR"/step4/xmlrpc.json \
                     "$INPUT_DIR"/step4/wp_debug.json \
                     "$INPUT_DIR"/step4/wp_config_exposure.json \
                     "$INPUT_DIR"/step4/installed_plugins_auth.json \
                     "$INPUT_DIR"/step4/dangerous_plugins_auth.json \
                     "$INPUT_DIR"/step4/file_editors_auth.json; do
        [ -f "$json_file" ] && jq -r '.checks[] | select(.status != "SKIP") | "| \(.name) | \(.status) | \(.severity) | \(.found) |"' "$json_file" 2>/dev/null >> "$OUTPUT_FILE" || true
    done
    echo "" >> "$OUTPUT_FILE"
fi

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
        WSTG_ID=$(jq -r ".\"$rem_id\".wstg_id // \"\"" "$REMEDIATION_DB")
        WSTG_URL=$(jq -r ".\"$rem_id\".wstg_url // \"\"" "$REMEDIATION_DB")
        CWE_ID=$(jq -r ".\"$rem_id\".cwe_id // \"\"" "$REMEDIATION_DB")
        CWE_URL=$(jq -r ".\"$rem_id\".cwe_url // \"\"" "$REMEDIATION_DB")
        
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
        
        # Add OWASP WSTG and CWE mappings
        if [ -n "$WSTG_ID" ] || [ -n "$CWE_ID" ]; then
            echo "**Standards Mapping:**" >> "$OUTPUT_FILE"
            if [ -n "$WSTG_ID" ]; then
                echo "- OWASP WSTG: [$WSTG_ID]($WSTG_URL)" >> "$OUTPUT_FILE"
            fi
            if [ -n "$CWE_ID" ]; then
                echo "- CWE: [$CWE_ID]($CWE_URL)" >> "$OUTPUT_FILE"
            fi
            echo "" >> "$OUTPUT_FILE"
        fi
        
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

## Out of Scope

The following security concerns are **outside the scope** of this black-box assessment and require direct server/infrastructure access to evaluate:

| Area | Why Out of Scope | Recommended Tool |
|------|-----------------|------------------|
| Server-side file integrity (webshell scan on disk) | Requires SSH/filesystem access | WP-CLI verify-checksums, Wordfence, Maldet |
| Server privilege escalation paths | Requires OS-level access | Linux Exploit Suggester, Lynis |
| Database content inspection | Requires DB credentials | wp-cli, MySQL direct access |
| Internal network / SSRF reachability | Requires server execution context | Manual pentest |
| Memory / process inspection | Requires server access | sysdig, auditd |

For a complete assessment including the above areas, a **professional penetration test with server access** is recommended.

---

**Report Generated:** $TIMESTAMP  
**Framework:** SHIELD v1.0.0  
**Total Checks:** $TOTAL_CHECKS | **Issues Found:** $TOTAL_ISSUES | **Grade:** $GRADE  
**Documentation:** https://github.com/Georges034302/SHIELD-framework

EOF

echo "✓ Summary report generated: $SUMMARY_FILE"
echo "✓ Detailed report generated: $OUTPUT_FILE"
echo ""
echo "Grade: $GRADE | $TOTAL_ISSUES issues ($CRITICAL_COUNT critical, $HIGH_COUNT high, $MEDIUM_COUNT medium, $LOW_COUNT low) | $PASS_COUNT passed"
echo ""
echo "📄 Quick view: $SUMMARY_FILE"
echo "📋 Full report: $OUTPUT_FILE"
