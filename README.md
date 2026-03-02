<h1>
  <img src="logos/shield.png" alt="SHIELD Logo" width="70" align="middle"/> 
  <span style="vertical-align: middle; display: inline-block;">SHIELD®</span>
</h1>

### Security Hardening & Infrastructure Exposure Lifecycle Diagnostics Framework

> SHIELD is a dual-mode black-box security assessment framework, stability monitoring, OWASP WSTG alignment, and reproducible grading across 69 structured web security checks.

---

## Overview

**69 security checks** across 6 assessment layers producing graded reports (A–F) with severity ratings, OWASP WSTG mappings, CWE references, and actionable remediation guidance.

**Key Features:**
- 🛡️ **Dual-mode architecture:** Safe posture scanning (CI/CD) + authorized active testing (pentesting)
- 🎯 **OWASP standards:** WSTG 4.2, ASVS 4.0.3, CWE 4.13, Mozilla TLS 5.7
- 🔄 **Stability monitoring:** Auto-abort on instability (>10% 5xx errors)
- 🤝 **Rate-aware scanning:** Respects Retry-After headers, exponential backoff

**No server access. No exploitation. No disruption.**

---

## Assessment Methodology

<table>
  <thead>
    <tr>
      <th width="220">Step</th>
      <th>Security Domain</th>
    </tr>
  </thead>
  <tbody>
    <tr><td><b>1 — Scope</b> (3 checks)</td><td>Target resolution, WordPress detection, authorization validation</td></tr>
    <tr><td><b>2 — External Hardening</b> (16 checks)</td><td>Security headers (HSTS, CSP, X-Frame), TLS 1.2/1.3, cipher suites, certificate expiry/CT, OCSP stapling, HTTP→HTTPS redirect, server/PHP version disclosure</td></tr>
    <tr><td><b>3 — Auth &amp; Session</b> (11 checks)</td><td>Login rate limiting, brute force protection, cookie security (Secure/HttpOnly/SameSite), session rotation, timeout enforcement, logout validation, username enumeration (REST API + timing attacks)</td></tr>
    <tr><td><b>4 — Authorization</b> (19 checks)</td><td>Admin path access control (20+ paths), API authentication, CORS policies, directory listing, file upload validation, backup exposure (.sql/.zip), path traversal, dangerous HTTP methods, GraphQL introspection, cloud storage ACLs, WordPress security (wp-config, debug mode, plugin CVEs, XML-RPC, file editors)</td></tr>
    <tr><td><b>5 — Backdoor Detection</b> (12 checks)</td><td>Malicious JavaScript (obfuscation, cryptominers, hidden iframes), SEO cloaking, webshell signatures (c99/r57/wso), credential exposure (.env/.git), phpinfo, threat intelligence (Spamhaus/AbuseIPDB/Safe Browsing), verbose errors, open redirects, SRI enforcement, OWASP defensive headers</td></tr>
    <tr><td><b>6 — Infrastructure</b> (8 checks)</td><td>Port scanning (37 ports), DNS security (SPF/DMARC/DNSSEC/CAA), certificate transparency logs, subdomain enumeration, WAF fingerprinting, shared hosting detection, infrastructure file exposure (.git/.docker)</td></tr>
  </tbody>
</table>

---

## Dual-Mode Architecture

SHIELD operates in two modes for different use cases:

### 🔵 Posture Mode (Default) — **Safe for CI/CD**
```bash
bash scripts/run_all.sh https://example.com
```
- Passive reconnaissance only
- No active testing (brute force, authentication probing)
- Safe for continuous monitoring
- No risk of triggering security controls

### 🔴 Authorized Mode — **Active Testing**
```bash
bash scripts/run_all.sh --mode authorized --i-accept-risk https://example.com
```
- Enables brute force lockout testing (10 attempts max)
- Active authentication probing
- Requires `--i-accept-risk` flag (legal acknowledgment)
- **Only use with written authorization**

See [docs/modes.md](docs/modes.md) for complete mode documentation.

---

## Quick Start

```bash
git clone https://github.com/Georges034302/SHIELD-framework.git
cd shield-framework

# Basic posture scan (safe for CI/CD)
bash scripts/run_all.sh https://example.com

# Posture scan with custom output directory
bash scripts/run_all.sh -o /tmp/scan_results https://example.com

# WordPress authenticated scan (posture mode)
bash scripts/run_all.sh --user admin --pass 'password' https://example.com

# Authorized mode with brute force testing (requires written authorization)
bash scripts/run_all.sh --mode authorized --i-accept-risk --brute-force https://example.com

# Rate-aware scanning (respect Retry-After, exponential backoff)
bash scripts/run_all.sh --rate-aware https://example.com
```

### Key Command-Line Flags

| Flag | Description |
|------|-------------|
| `--mode <posture\|authorized>` | Assessment mode (default: posture) |
| `--i-accept-risk` | Required for authorized mode (legal acknowledgment) |
| `--rate-aware` | Enable rate limiting and Retry-After handling |
| `--brute-force` | Enable brute force testing (authorized mode only) |
| `--user <username>` | WordPress authentication username |
| `--pass <password>` | WordPress authentication password |
| `--authorization-ref <id>` | Authorization reference (audit trail) |
| `-o <directory>` | Output directory (default: test_output) |
| `-t <seconds>` | HTTP timeout (default: 10) |

See [docs/usage.md](docs/usage.md) for complete flag documentation.

---

## Report Output

Generates structured output in `test_output/`:

1. **Summary report** `summary_report.md` - Quick overview with grade, key metrics, and top 5 findings
2. **Detailed report** `report.md` - Complete findings with remediation guidance, OWASP mappings, and CWE references
3. **Per-check JSON files** in `step{1-6}/` (69 total checks)

---

## Assessment Boundaries

**SHIELD does NOT scan:**
- Server filesystem (requires SSH/filesystem access → use WP-CLI, Wordfence, Maldet)
- Database content (requires DB credentials → use manual SQL audits)
- Internal networks/SSRF targets (requires server execution context)
- Memory/running processes (requires OS-level access → use Lynis, auditd)
- Source code analysis (use SAST tools)

**For comprehensive coverage:** Combine SHIELD (black-box) with server-side tools and professional penetration testing.

---

## Requirements

- `bash` 4+
- `curl`
- `jq`
- `dig` or `nslookup`
- `openssl`
- `nc` (netcat)
- `python3` (optional, for enhanced parsing)

---

## Documentation

| Document | Purpose |
|----------|---------|
| [docs/modes.md](docs/modes.md) | Dual-mode architecture guide |
| [docs/scoring.md](docs/scoring.md) | Grading methodology (A-F algorithm) |
| [docs/methodology.md](docs/methodology.md) | Threat model and assessment boundaries |
| [docs/usage.md](docs/usage.md) | Complete command-line reference |

---

## Authorization & Legal

⚠️ **Only scan systems you own or have explicit written authorization to test.**

Unauthorized security testing may violate:
- Computer Fraud and Abuse Act (CFAA) - United States
- Computer Misuse Act - United Kingdom  
- Cybercrime laws in your jurisdiction

**Authorized mode** (`--i-accept-risk`) performs active testing that may trigger security controls. Ensure proper authorization before use.

---

## Contributing

This is a research framework. For bug reports or feature requests, please open an issue with detailed reproduction steps.

---

## License

Copyright © 2026 Georges Bou Ghantous®. All Rights Reserved. — see [LICENSE](LICENSE)

<sub>Use, reproduction, modification, and distribution require explicit written permission from the copyright holder.</sub>

---

<br>
<sub><i>© 2026 SHIELD Framework v2.0 &nbsp;|&nbsp; <a href="https://github.com/Georges034302">Georges Bou Ghantous</a></i></sub>

