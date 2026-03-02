# Final Report Model — `report.md`

## Purpose

`report.md` is the consolidated security assessment report produced by `generate_report.sh` after all 69 step scripts have run. It aggregates every `FAIL` and `WARN` across all six steps into a single graded Markdown document with executive summary, per-step findings tables, a WordPress section (when applicable), detailed remediation guidance keyed to `data/remediation.json`, an out-of-scope declaration, and a conclusion with prioritised next steps.

**Location:** `<output_dir>/report.md` (default: `test_output/report.md`)

**Produced by:** `bash scripts/generate_report.sh -i <output_dir> -o <output_dir>/report.md`

---

## Report Sections

| Section | Content |
|---------|---------|
| Header | Target URL, assessment timestamp, framework version |
| Executive Summary | Grade (A–F), issue counts by severity, total checks run |
| Issue Summary | Full findings table — all FAIL/WARN across all steps |
| Per-Step Findings | One subsection per step (1–6), FAIL/WARN only |
| WordPress Findings | WP-specific issues grouped (shown only when WP detected) |
| Remediation Guidance | Detailed fix instructions per SEC ID from remediation DB |
| Conclusion | Next steps prioritised by severity timeline |
| Out of Scope | Server-side checks outside black-box scope |
| Footer | Total checks, issues found, grade |

---

## Report Structure (Annotated)

```markdown
# SHIELD Security Assessment Report

**Target:** https://example.com
**Date:** 2026-02-27 10:30:00 UTC
**Framework:** SHIELD v1.0.0

---

## Executive Summary

| Metric | Value |
|--------|-------|
| Grade | C |               ← A / B+ / B / C / D / F (see grading scale below)
| Critical Issues | 0 |
| High Issues | 2 |
| Medium Issues | 4 |
| Low Issues | 1 |
| Total Issues | 7 |
| Checks Passed | 48 |
| Checks Skipped | 9 |      ← WP-only checks on non-WP target, or optional flags
| Total Checks Run | 69 |

---

## Issue Summary

All FAIL and WARN findings across all steps:

| Step | Check | Status | Severity | Finding |
|------|-------|--------|----------|---------|
| Step 2 | TLS Protocols | FAIL | HIGH | TLS 1.0, TLS 1.1 enabled |
| Step 2 | Server Version | WARN | MEDIUM | Apache/2.4.51 version exposed |
| Step 3 | Login Rate Limiting | FAIL | HIGH | No 429 or lockout after 20 requests |
| Step 3 | Cookie Security | WARN | MEDIUM | PHPSESSID missing SameSite flag |
| Step 4 | Admin Paths | WARN | MEDIUM | /phpmyadmin accessible (HTTP 200) |
| Step 5 | Verbose Errors | WARN | MEDIUM | Stack trace in 500 response |
| Step 6 | WAF / CDN | WARN | MEDIUM | No WAF fingerprint detected |

---

## Detailed Findings

### Step 1: Scope & Authorization

_No issues found in this step._

---

### Step 2: External Hardening

#### tls protocols

| Check | Status | Severity | Finding |
|-------|--------|----------|---------|
| Legacy TLS Protocols | FAIL | HIGH | TLS 1.0, TLS 1.1 enabled |

#### server version

| Check | Status | Severity | Finding |
|-------|--------|----------|---------|
| Server Version Exposure | WARN | MEDIUM | Apache/2.4.51 — version exposed |

---

### Step 3: Authentication & Session Controls

#### ratelimit

| Check | Status | Severity | Finding |
|-------|--------|----------|---------|
| Login Rate Limiting | FAIL | HIGH | No 429 or lockout after 20 requests |

...

---

## WordPress-Specific Findings

*(Shown only when WordPress is detected in step1/wp_version.json)*

WordPress was detected on this target. The following WP-specific checks were performed:

| Check | Status | Severity | Finding |
|-------|--------|----------|---------|
| WordPress Version | WARN | MEDIUM | WordPress 6.3.2 is outdated |
| REST API User Exposure | FAIL | HIGH | 3 users exposed: admin, editor, author1 |
| xmlrpc.php Active | FAIL | HIGH | 42 methods available |
| Multicall Brute Force | FAIL | CRITICAL | system.multicall enabled |

---

## Remediation Guidance

One subsection per unique SEC ID found in FAIL/WARN state, pulled from
data/remediation.json:

### SEC-TLS-001: Disable Legacy TLS Protocols

**Risk Level:** HIGH

**Description:**
TLS 1.0 and TLS 1.1 are deprecated protocols with known vulnerabilities
(BEAST, POODLE, downgrade attacks). All modern clients support TLS 1.2+.

**Impact:**
Attackers on the network path can downgrade connections and decrypt traffic.

**Remediation:**
```
# Nginx
ssl_protocols TLSv1.2 TLSv1.3;

# Apache
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
```

**References:**
- https://www.rfc-editor.org/rfc/rfc8996
- https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cheat_Sheet.html

---

## Conclusion

This assessment identified **7** security issues across multiple categories.
Please review the detailed findings and implement the recommended remediation
steps in order of severity (Critical → High → Medium → Low).

### Next Steps

1. **Immediate (24-48 hours):** Address all Critical and High severity issues
2. **Short-term (1-2 weeks):** Resolve Medium severity issues
3. **Medium-term (1 month):** Fix Low severity findings
4. **Ongoing:** Re-run SHIELD assessment monthly to verify fixes and detect new issues

---

## Out of Scope

The following security concerns are outside the scope of this black-box assessment:

| Area | Why Out of Scope | Recommended Tool |
|------|-----------------|------------------|
| Server-side file integrity (webshell scan on disk) | Requires SSH/filesystem access | WP-CLI verify-checksums, Wordfence, Maldet |
| Server privilege escalation paths | Requires OS-level access | Linux Exploit Suggester, Lynis |
| Database content inspection | Requires DB credentials | wp-cli, MySQL direct access |
| Internal network / SSRF reachability | Requires server execution context | Manual pentest |
| Memory / process inspection | Requires server access | sysdig, auditd |

---

**Report Generated:** 2026-02-27 10:30:00 UTC
**Framework:** SHIELD v1.0.0
**Total Checks:** 69 | **Issues Found:** 7 | **Grade:** C
**Documentation:** https://github.com/Georges034302/SHIELD-framework
```

---

## Grading Scale

The grade is computed from CRITICAL, HIGH, and MEDIUM counts after all checks complete.

| Grade | Criteria |
|-------|----------|
| **A** | No CRITICAL, HIGH, or MEDIUM findings |
| **B+** | No CRITICAL or HIGH; exactly 1 MEDIUM |
| **B** | No CRITICAL or HIGH; 2–4 MEDIUM findings |
| **C** | No CRITICAL; 1 HIGH — or — 5+ MEDIUM findings |
| **D** | No CRITICAL; 3+ HIGH — or — 1+ HIGH with 3+ MEDIUM |
| **F** | Any CRITICAL finding |

> Grade is a triage indicator only. A grade of "B" does not mean the site is safe — it means no critical or high-severity controls are missing. Always review the individual findings.

---

## Remediation Database

Each finding is cross-referenced with `data/remediation.json` by its `remediation_id` (e.g. `SEC-TLS-001`). If a SEC ID appears in a finding but has no entry in the DB, the check is listed in the findings table but the Remediation Guidance section will not include a subsection for it.

The DB entry schema:

```json
"SEC-TLS-001": {
  "title": "Disable Legacy TLS Protocols",
  "description": "TLS 1.0 and 1.1 are deprecated ...",
  "risk": "HIGH",
  "impact": "Attackers can downgrade connections ...",
  "remediation": "# Nginx\nssl_protocols TLSv1.2 TLSv1.3;\n...",
  "references": [
    "https://www.rfc-editor.org/rfc/rfc8996"
  ]
}
```

---

## What to Look For in the Report

### Red flags requiring immediate attention

| Signal | Where in Report | Action |
|--------|----------------|--------|
| Grade **F** | Executive Summary | Stop — address CRITICAL finding before anything else |
| Grade **D** | Executive Summary | Escalate — multiple HIGH issues indicate systematic weakness |
| Any `CRITICAL` in Issue Summary | Issue Summary table | Fix within 24 hours; consider taking affected service offline |
| `SEC-SHELL-001` FAIL | Step 5 findings | Server is compromised — incident response, not just remediation |
| `SEC-BACKDOOR-002` FAIL | Step 5 findings | Active SEO spam injection — forensic investigation required |
| `SEC-THREAT-003` FAIL | Step 5 findings | Google Safe Browsing flag — user-facing warning active now |
| `SEC-BRUTE-003` FAIL | Step 3 findings | Default credentials accepted — immediate password change |

### Review even on good grades

| Area | Why |
|------|-----|
| WordPress Findings section | WP issues inflate attack surface even without app vulnerabilities |
| All MEDIUM findings | A grade of B can still mean 4 medium issues — check they are genuinely low-risk |
| Out of Scope section | Server-side scans may reveal compromise missed entirely by black-box testing |
| Skipped checks (`SKIP_COUNT`) | High skip count with a WP target may mean WP detection failed — re-run with debug flag |
