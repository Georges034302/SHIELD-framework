# SHIELD®
### Structured Website Security & Resilience Assessment Framework

> **SAFE-by-default · Non-destructive · Actionable**  
> A systematic black-box security assessment toolkit for web applications and WordPress sites.

---

## What is SHIELD?

SHIELD is an automated, command-line security assessment framework that evaluates a website's security posture across six structured layers — from HTTP headers and TLS configuration through to active backdoor detection and infrastructure exposure.

It is designed for security professionals, DevOps engineers, and site owners who need to:

- Run repeatable, evidence-based security health checks
- Identify configuration gaps before attackers do
- Generate structured, client-ready reports with graded findings
- Validate security hardening measures over time
- Detect active compromises: injected malware, webshells, SEO spam, cloaking

SHIELD produces a graded Markdown report (A–F) with per-finding severity, remediation code examples, and OWASP references.

---

## Assessment Methodology

SHIELD follows a six-step structured methodology. Each step targets a distinct security layer and outputs machine-readable JSON consumed by the report generator.

```
┌─────────────────────────────────────────────────────────────┐
│  Step 1 │ Scope & Target Validation                         │
│  Step 2 │ External Hardening                                │
│  Step 3 │ Authentication & Session Controls                 │
│  Step 4 │ Authorization & Access Control                    │
│  Step 5 │ Defensive Controls & Backdoor Detection           │
│  Step 6 │ Infrastructure & Exposure Surface                 │
└─────────────────────────────────────────────────────────────┘
```

### Step 1 — Scope & Target Validation
Confirms reachability of the target, resolves the canonical URL, detects the technology stack (including WordPress), and establishes the assessment baseline. WordPress detection gates all WP-specific checks in later steps.

### Step 2 — External Hardening
Evaluates everything visible from the outside before any login: HTTP security headers (CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy), TLS protocol version and cipher strength, certificate validity and expiry, OCSP stapling, HTTP-to-HTTPS redirect enforcement, and server/PHP version disclosure in response headers.

### Step 3 — Authentication & Session Controls
Tests the login surface and session lifecycle: rate limiting and account lockout on login endpoints, brute force protection (opt-in active test via `--brute-force`), CAPTCHA presence, session cookie security flags (Secure, HttpOnly, SameSite), session fixation, session rotation after authentication, timeout enforcement, and username enumeration via login error differentiation.

### Step 4 — Authorization & Access Control
Probes what authenticated and unauthenticated users can reach: admin path exposure, API authentication enforcement, CORS policy correctness, directory listing, GraphQL introspection, cloud storage bucket access, file upload type validation, backup and archive file exposure, path traversal, dangerous HTTP method availability (PUT, DELETE, TRACE), and WordPress-specific checks — wp-config exposure, debug log accessibility, plugin vulnerability detection, and XML-RPC attack surface.

### Step 5 — Defensive Controls & Backdoor Detection
Validates implementation of OWASP-recommended controls (open redirect prevention, verbose error suppression, Subresource Integrity, third-party script auditing, phpinfo exposure) and performs active backdoor detection: obfuscated JavaScript scanning, hidden iframe detection, cryptominer fingerprinting, SEO spam cloaking (Googlebot vs normal UA diff), known webshell path probing with timing analysis, sensitive file exposure (`.env`, `.git`, private keys, credentials), and threat intelligence lookups (Spamhaus ZEN/DBL, AbuseIPDB, Google Safe Browsing).

### Step 6 — Infrastructure & Exposure Surface
Maps the external attack surface beyond the web application: DNS integrity (SPF, DMARC, MX hijack, wildcard DNS, suspicious TXT records), certificate transparency log analysis (unexpected SANs, recently issued certs), subdomain enumeration, WAF fingerprinting, shared hosting detection, open port scanning (backdoor listener ports, internet-exposed databases, admin panels), and DNS resolution consistency checks.

---

## Quick Start

```bash
git clone https://github.com/Georges034302/SHIELD-framework.git
cd shield-framework

# Run full assessment
./scripts/run_all.sh https://example.com

# With brute force lockout test (only on sites you own or have written authorisation for)
./scripts/run_all.sh https://example.com --brute-force

# Report is generated automatically at:
# test_output/report.md
```

---

## Output

```
================================================
  SHIELD Security Assessment Framework
================================================
Target: https://example.com
▶ Running scope...
▶ Running headers...
▶ Running tls...
...
▶ Running cert_transparency...
================================================
  Assessment Complete
================================================
Grade: C | 14 issues (2 critical, 5 high, 7 medium, 0 low) | 48 passed
✓ Full report: test_output/report.md
```

The report includes:
- **Security grade** (A–F)
- **Priority actions** — Critical and High findings at a glance
- **Per-step findings table** — only FAIL/WARN entries, clean and focused
- **WordPress findings section** — dedicated table when WP is detected
- **Remediation guidance** — per-finding code examples for Apache, Nginx, PHP, WP
- **Out of Scope notice** — explicit boundary between black-box and server-access testing

---

## What SHIELD Does NOT Do

- Exploit vulnerabilities or deliver payloads
- Perform destructive or denial-of-service testing
- Replace professional penetration testing (server access, internal network, code review)
- Scan inside the filesystem or database (requires server-side tools: WP-CLI, Wordfence, Maldet)

---

## Requirements

| Dependency | Purpose |
|------------|---------|
| `bash` 4+ | Script execution |
| `curl` | HTTP requests |
| `jq` | JSON parsing and output |
| `dig` / `nslookup` | DNS lookups |
| `openssl` | TLS certificate inspection |
| `nc` (netcat) | Port scanning |
| `python3` *(optional)* | WP plugin version parsing |

---

## Authorization

⚠️ **Only test systems you own or have explicit written authorisation to assess.**  
Unauthorised scanning may violate computer misuse laws in your jurisdiction.

---

## License

MIT License — see [LICENSE](LICENSE)

<sub><i>© 2026 SHIELD®. All rights reserved. &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<a href="https://github.com/Georges034302"><i>Georges Bou Ghantous</i></a></i></sub>

---
