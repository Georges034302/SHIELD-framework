# SHIELD®
### Security Hardening & Infrastructure Exposure Lifecycle Diagnostics Framework

> A systematic black-box security assessment toolkit for web applications.

---

## What is SHIELD?

SHIELD is a black-box, command-line security assessment framework for web applications and WordPress sites. It systematically executes **69 security checks** across six security layers — from TLS and HTTP headers through to active backdoor detection and infrastructure exposure — then produces a graded, client-ready Markdown report (A–F) with per-finding severity, remediation code, and OWASP references.

No server access required. No exploitation. No destructive testing.

---

## Assessment Methodology

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

<table>
  <thead>
    <tr>
      <th width="220">Step</th>
      <th>Focus</th>
    </tr>
  </thead>
  <tbody>
    <tr><td><b>1 — Scope</b> (3 checks)</td><td>Resolves target, detects WordPress, establishes baseline. If credentials provided, authenticates and establishes session for deeper testing.</td></tr>
    <tr><td><b>2 — External Hardening</b> (16 checks)</td><td>HTTP security headers (HSTS, CSP, X-Frame-Options), TLS protocols/ciphers, certificate validity and expiry, OCSP stapling, HTTPS enforcement, cache controls, server version disclosure</td></tr>
    <tr><td><b>3 — Auth &amp; Session</b> (11 checks)</td><td>Login rate limiting, brute force lockout (opt-in), CAPTCHA presence, cookie security flags (Secure/HttpOnly/SameSite), session fixation/rotation, idle timeout, logout invalidation, username enumeration via REST API and timing attacks</td></tr>
    <tr><td><b>4 — Authorization</b> (19 checks)</td><td>Admin paths exposure, API authentication, CORS misconfig, directory listing, file upload validation, backup file exposure, path traversal, dangerous HTTP methods, cloud storage ACLs. <b>WordPress:</b> config exposure, debug mode, plugin vulnerabilities, XML-RPC. <b>Authenticated:</b> enumerates installed plugins, detects code execution plugins (WPCode, file managers), tests theme/plugin editor access.</td></tr>
    <tr><td><b>5 — Backdoor Detection</b> (12 checks)</td><td>Obfuscated JavaScript (eval/atob), hidden iframes, cryptominers, SEO spam cloaking, webshell path probing (c99/r57/wso), exposed credentials (.env/.git/keys), threat intel (Spamhaus, AbuseIPDB, Google Safe Browsing), verbose error pages, open redirects, SRI enforcement</td></tr>
    <tr><td><b>6 — Infrastructure</b> (8 checks)</td><td>Open port scanning (databases/backdoors/admin panels), DNS security (SPF/DMARC/DNSSEC/CAA), certificate transparency logs, subdomain enumeration, WAF fingerprinting, shared hosting indicators</td></tr>
  </tbody>
</table>

---

## Detailed Assessment Coverage

SHIELD performs **69 individual security checks** organized across 6 steps:

- **Step 1**: 3 checks (scope validation, WordPress detection, optional authentication)
- **Step 2**: 16 checks (TLS/headers/certificates)
- **Step 3**: 11 checks (authentication/session controls)
- **Step 4**: 19 checks (authorization/access control + WordPress + authenticated tests)
- **Step 5**: 12 checks (defensive controls + backdoor detection)
- **Step 6**: 8 checks (infrastructure/DNS/network)

### Authenticated Testing (Optional)

When WordPress credentials are provided via `--user` and `--pass`, SHIELD performs additional authenticated checks:

- **Installed Plugin Enumeration**: Lists all active plugins with versions
- **Dangerous Plugin Detection**: Flags code execution plugins (WPCode, Insert Headers & Footers, file managers)
- **File Editor Access Test**: Verifies if theme/plugin editors are accessible (DISALLOW_FILE_EDIT check)

These tests provide deeper security analysis but are completely optional — SHIELD works as a black-box tool without credentials.

---

## Quick Start

```bash
git clone https://github.com/Georges034302/SHIELD-framework.git
cd shield-framework

# Run full assessment (69 security checks)
bash scripts/run_all.sh https://example.com

# Custom output directory and timeout
bash scripts/run_all.sh -o /tmp/results -t 15 https://example.com

# With brute force lockout test (only on authorized sites)
bash scripts/run_all.sh --brute-force https://example.com

# With authenticated testing (WordPress deeper analysis)
bash scripts/run_all.sh --user admin --pass 'your-password' https://example.com

# Combined: brute force + authenticated testing
bash scripts/run_all.sh --brute-force --user admin --pass 'your-password' https://example.com

# Report generated at: test_output/report.md
```

---

## Output

```
================================================
  SHIELD Security Assessment Framework
================================================
Target(s): https://example.com
Output directory: ./test_output

▶ Running scope...
▶ Running wp_version...
▶ Running authenticate...
▶ Running headers...
▶ Running tls...
▶ Running tls_ciphers...
...
▶ Running cert_transparency...
================================================
  Assessment Complete
================================================
Results saved to: ./test_output

Generating consolidated report...
✓ Report generated: test_output/report.md

Grade: C | 14 issues (2 critical, 5 high, 7 medium, 0 low) | 55 passed
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

Copyright © 2026 Georges Bou Ghantous®. All Rights Reserved. — see [LICENSE](LICENSE) \
<sub>Use, reproduction, modification, and distribution require explicit written permission from the copyright holder.</sub>

---

<br>
<sub><i> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;© 2026 SHIELD &nbsp; <a href="https://github.com/Georges034302"><i>Georges Bou Ghantous</i></a></i></sub>

