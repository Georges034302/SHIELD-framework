# SHIELD®
### Security Hardening & Infrastructure Exposure Lifecycle Diagnostics Framework

> A systematic black-box security assessment toolkit for web applications.

---

## What is SHIELD?

Black-box security assessment framework that executes **69 checks** across 6 layers — from TLS/headers to backdoor detection and infrastructure exposure. Produces graded reports (A–F) with severity ratings, remediation code, and OWASP references.

No server access. No exploitation. No disruption.

---

## Assessment Steps

<table>
  <thead>
    <tr>
      <th width="220">Step</th>
      <th>What We Test</th>
    </tr>
  </thead>
  <tbody>
    <tr><td><b>1 — Scope</b> (3 checks)</td><td>Target resolution, WordPress detection, authentication validation</td></tr>
    <tr><td><b>2 — External Hardening</b> (16 checks)</td><td>Security headers (HSTS, CSP, X-Frame, X-Content-Type), TLS versions/protocols/ciphers, certificate expiry/transparency, OCSP stapling, HTTP→HTTPS redirect, cache controls, server/technology disclosure, PHP version exposure</td></tr>
    <tr><td><b>3 — Auth &amp; Session</b> (11 checks)</td><td>Endpoint discovery, login rate limiting, brute force lockout (opt-in), CAPTCHA detection, cookie flags (Secure/HttpOnly/SameSite), session rotation on login, 3-minute timeout test, logout invalidation, username enumeration (REST API + timing), WordPress user exposure</td></tr>
    <tr><td><b>4 — Authorization</b> (19 checks)</td><td>Unauthenticated admin path access (20+ paths), API authentication, CORS misconfiguration, directory listing, file upload validation, backup file exposure (.sql/.zip), path traversal, dangerous HTTP methods, GraphQL introspection, cloud storage ACLs. <b>WordPress:</b> wp-config exposure, debug mode, plugin CVEs, XML-RPC, installed plugins, dangerous plugins (code execution), file editor access</td></tr>
    <tr><td><b>5 — Backdoor Detection</b> (12 checks)</td><td>Obfuscated JavaScript (eval/atob/String.fromCharCode), hidden iframes, cryptominers, SEO spam cloaking, webshell path probing (c99/r57/wso/shell), exposed credentials (.env/.git/id_rsa), phpinfo exposure, threat intel (Spamhaus/AbuseIPDB/Google Safe Browsing), verbose error pages, open redirects, SRI enforcement, OWASP defensive controls (10+ checks)</td></tr>
    <tr><td><b>6 — Infrastructure</b> (8 checks)</td><td>Open port scan (37 ports: databases, control panels, backdoor ports), DNS security (SPF/DMARC/DNSSEC/CAA records), certificate transparency logs, subdomain enumeration, WAF detection (Cloudflare/AWS/Akamai), shared hosting indicators, infrastructure file exposure (.git/.docker/composer.json)</td></tr>
  </tbody>
</table>

### Authenticated Tests (WordPress)

Pass `--user` and `--pass` to enable deeper testing:
- **Session timeout:** 3-minute wait to verify session expiration
- **Logout security:** Validates session invalidation after logout
- **Session rotation:** Confirms session ID changes on login
- **Plugin enumeration:** Lists all installed plugins with versions
- **Code execution detection:** Flags dangerous plugins (WPCode, Insert Headers, file managers)
- **File editor access:** Tests if theme/plugin editors are accessible (DISALLOW_FILE_EDIT check)

---

## Quick Start

```bash
git clone https://github.com/Georges034302/SHIELD-framework.git
cd shield-framework

# Basic scan
bash scripts/run_all.sh https://example.com

# With options
bash scripts/run_all.sh -o /tmp/results -t 15 https://example.com

# WordPress authenticated scan
bash scripts/run_all.sh --user admin --pass 'password' https://example.com

# Brute force lockout test (requires authorization)
bash scripts/run_all.sh --brute-force https://example.com
```

---

## Output

Scan progress with final summary:
```
▶ Running scope...
▶ Running headers...
...
================================================
  Assessment Complete
================================================
✓ Report generated: test_output/report.md
Grade: C | 14 issues (2 critical, 5 high, 7 medium) | 55 passed
```

**Report includes:**
- **Executive Summary** — Security grade (A–F), issue count metrics, risk assessment
- **Priority Actions** — Critical/High findings listed at top for immediate attention
- **Detailed Findings** — Per-step tables showing only FAIL/WARN checks with severity
- **WordPress-Specific Section** — Dedicated findings table when WordPress detected
- **Remediation Guidance** — Step-by-step fix instructions with code (Apache/Nginx/PHP/WordPress)
- **Conclusion** — Next steps timeline (24-48 hrs for Critical → 1 month for Low)
- **Out of Scope Table** — Clear boundaries of black-box vs server-access testing

---

## What SHIELD Does NOT Scan

- Server filesystem (webshells on disk, file integrity)
- Database content (SQL injection payloads, stored XSS)
- Internal networks (SSRF targets, private services)
- Memory/processes (running backdoors, privilege escalation)
- Source code (code review, SAST analysis)

**For these:** Use server-side tools (WP-CLI, Wordfence, Maldet, Lynis) or penetration testing with infrastructure access.

---

## Requirements

`bash` 4+, `curl`, `jq`, `dig`/`nslookup`, `openssl`, `nc` (netcat), `python3` (optional)

---

## Authorization

⚠️ **Only scan systems you own or have explicit written authorization to test.**

---

## License

Copyright © 2026 Georges Bou Ghantous®. All Rights Reserved. — see [LICENSE](LICENSE) \
<sub>Use, reproduction, modification, and distribution require explicit written permission from the copyright holder.</sub>

---

<br>
<sub><i> &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;© 2026 SHIELD &nbsp; <a href="https://github.com/Georges034302"><i>Georges Bou Ghantous</i></a></i></sub>

