# SHIELD Scoring Methodology

## Overview

SHIELD assigns a letter grade (A through F) based on the severity and quantity of security issues detected during assessment. This document defines the scoring algorithm, weights, and decision logic to ensure reproducibility and academic rigor.

---

## Grade Scale

| Grade | Meaning | Threshold |
|-------|---------|-----------|
| **A** | Excellent security posture | Zero MEDIUM/HIGH/CRITICAL issues |
| **B+** | Strong posture with minor issues | 1 MEDIUM issue |
| **B** | Good posture with some concerns | 2-4 MEDIUM issues |
| **C** | Significant concerns | 1 HIGH or 5+ MEDIUM issues |
| **D** | Major security gaps | 3+ HIGH or (1 HIGH + 3+ MEDIUM) or 5+ HIGH |
| **F** | Critical vulnerabilities present | 1+ CRITICAL issue |

---

## Scoring Algorithm

The grading algorithm is implemented in [`scripts/generate_report.sh`](../scripts/generate_report.sh):

```bash
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
```

---

## Severity Definitions

### CRITICAL
**Impact:** Immediate risk of compromise, data breach, or complete system takeover

**Examples:**
- Unauthenticated remote code execution
- SQL injection allowing data extraction
- Authentication bypass
- Exposed admin credentials
- Active backdoor/webshell detected

**Scoring Weight:** ∞ (any CRITICAL issue results in grade F)

---

### HIGH
**Impact:** Significant security weakness that can lead to compromise with moderate effort

**Examples:**
- Missing HSTS header (protocol downgrade attacks)
- Weak TLS configuration (vulnerable ciphers/protocols)
- Directory listing enabled
- Sensitive file exposure (backups, configs)
- Session management flaws
- WordPress plugin with known RCE vulnerability

**Scoring Weight:** 5 points per issue

**Grade Impact:**
- 1 issue = C
- 3 issues = D
- 5 issues = D

---

### MEDIUM
**Impact:** Security best practice violation that increases attack surface

**Examples:**
- Missing X-Frame-Options (clickjacking risk)
- Weak CSP policy
- Server version disclosure
- Cookies without Secure/HttpOnly flags
- robots.txt disclosing sensitive paths
- Open ports (non-critical services)

**Scoring Weight:** 2 points per issue

**Grade Impact:**
- 1 issue = B+
- 2-4 issues = B
- 5+ issues = C

---

### LOW
**Impact:** Informational finding or minor security weakness

**Examples:**
- Missing Referrer-Policy header
- Suboptimal cache-control headers
- Long certificate expiry
- DNS record recommendations

**Scoring Weight:** 1 point per issue (informational, does not affect letter grade)

---

## Confidence Levels (Phase 6)

Each check includes a confidence level that indicates the likelihood of false positives:

| Confidence | Criteria | Scoring Weight |
|------------|----------|----------------|
| **HIGH** | Direct evidence (header present/absent, file returns 200, exact match) | 100% |
| **MEDIUM** | Indirect evidence (timing-based detection, probabilistic analysis) | 75% |
| **LOW** | Heuristic-based (pattern matching, multiple interpretations possible) | 50% |

### Weighted Scoring Formula

```
Effective Severity = Base Severity × (Confidence Weight)
```

**Example:**
- HIGH severity check with LOW confidence = weighted as MEDIUM
- CRITICAL severity check always counted as CRITICAL (regardless of confidence)

---

## Layer Weighting

Currently, all assessment layers have **equal weight**. Future versions may introduce configurable layer weighting.

| Layer | Current Weight | Future Plans |
|-------|----------------|--------------|
| Step 1 — Scope | 1.0 | Policy-configurable |
| Step 2 — External Hardening | 1.0 | Policy-configurable |
| Step 3 — Auth & Session | 1.0 | Policy-configurable |
| Step 4 — Authorization | 1.0 | Policy-configurable |
| Step 5 — Backdoor Detection | 1.0 | Policy-configurable |
| Step 6 — Infrastructure | 1.0 | Policy-configurable |

---

## Check Status Types

| Status | Meaning | Impact on Grade |
|--------|---------|-----------------|
| **PASS** | Check passed | ✅ Positive signal (no deduction) |
| **FAIL** | Check failed | ❌ Counted toward grade (uses severity) |
| **WARN** | Potential issue, unclear | ⚠️ Counted toward grade (uses severity) |
| **INFO** | Informational only | ℹ️ Not counted (no impact) |
| **SKIP** | Check not applicable | ⏭ Not counted (no impact) |

---

## Grade Improvement Calculation

For "Quick Wins" recommendations, grade improvement is estimated by:

1. Calculate current grade
2. Remove the specific finding(s)
3. Recalculate grade
4. Report delta

**Example:**
```
Current: 1 CRITICAL, 2 HIGH, 5 MEDIUM = F
Remove CRITICAL issue:
New:     0 CRITICAL, 2 HIGH, 5 MEDIUM = D
Improvement: F → D (2 letter grades)
```

---

## Reproducibility Guarantees

SHIELD scoring is reproducible when:

1. ✅ Same target URL
2. ✅ Same scan mode (posture vs authorized)
3. ✅ Same timeout values
4. ✅ Same policy file (if used)
5. ✅ Scanned within same time window (certificates, DNS records may change)

**Known Variability Sources:**
- Network conditions (timeouts, connectivity)
- Target state changes (content updates, config changes)
- Third-party services (threat intel APIs, DNS resolvers)
- Timing-based checks (race conditions)

To minimize variability:
- Use `--rate-aware` mode for consistent timing
- Run multiple scans and compare median results
- Use policy file to lock expected values

---

## Research & Academic Use

For publications, cite the scoring methodology as:

> SHIELD Framework employs a severity-weighted scoring system where findings are categorized as CRITICAL (∞), HIGH (5 points), MEDIUM (2 points), or LOW (1 point). Letter grades (A-F) are assigned based on thresholds defined in the scoring methodology document, with confidence-weighted adjustments for probabilistic checks. All findings map to OWASP Web Security Testing Guide (WSTG) identifiers for standards alignment.

**Methodology Validation:**
- Algorithm is deterministic (no randomness)
- Thresholds are justified by industry standards (OWASP, NIST)
- Confidence weighting reduces false positive impact
- Policy suppressions provide context-aware adjustments

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-03-02 | Initial scoring methodology |
| 2.0.0 | 2026-03-02 | Phase 6: Added confidence weighting, policy suppressions |

---

## See Also

- [Methodology](./methodology.md) — Threat model and assessment boundaries
- [Modes](./modes.md) — Posture vs Authorized scanning
- [Remediation Database](../data/remediation.json) — Detailed fix guidance per finding
