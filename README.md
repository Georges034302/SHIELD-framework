# SHIELD®
### Security Hardening & Infrastructure Exposure Lifecycle Diagnostics Framework

> A systematic black-box security assessment toolkit for web applications.

---

## What is SHIELD?

SHIELD is a black-box, command-line security assessment framework for web applications and WordPress sites. It systematically probes a target across six security layers — from TLS and HTTP headers through to active backdoor detection and infrastructure exposure — then produces a graded, client-ready Markdown report (A–F) with per-finding severity, remediation code, and OWASP references.

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

| Step                        | Focus |
|-----------------------------|-------|
| **1 — Scope**               | Resolves target, detects WordPress, establishes baseline |
| **2 — External Hardening**  | HTTP security headers, TLS/cipher strength, certificate validity, HTTPS enforcement, server version disclosure |
| **3 — Auth & Session**      | Login rate limiting, brute force lockout, CAPTCHA, cookie flags, session fixation/rotation, timeout, username enumeration |
| **4 — Authorization**       | Admin paths, API auth, CORS, directory listing, file upload, backup exposure, path traversal, HTTP methods, WP config/plugins/XML-RPC |
| **5 — Backdoor Detection**  | Obfuscated JS, hidden iframes, cryptominers, SEO spam cloaking, webshell probing, exposed credentials/keys, threat intel (Spamhaus, AbuseIPDB, Google Safe Browsing) |
| **6 — Infrastructure**      | Open ports, DNS integrity (SPF/DMARC/MX), certificate transparency, subdomain enumeration, WAF fingerprinting, shared hosting |

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

Copyright © 2026 Georges Bou Ghantous®. All Rights Reserved. — see [LICENSE](LICENSE) \
<sub>Use, reproduction, modification, and distribution require explicit written permission from the copyright holder.</sub>

<br>
<sub><i> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;© 2026 SHIELD &nbsp; <a href="https://github.com/Georges034302"><i>Georges Bou Ghantous</i></a></i></sub>

