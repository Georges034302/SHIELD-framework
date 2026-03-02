# SHIELD Assessment Methodology

## Overview

This document defines the threat model, attack surface scope, ethical boundaries, and evidence collection procedures for the SHIELD (Security Hardening & Infrastructure Exposure Lifecycle Diagnostics) framework.

**Purpose:** Establish clear theoretical foundations and practical limits for security assessments conducted with SHIELD.

---

## Threat Model

### Attacker Profile

SHIELD assesses defenses against the following threat actors:

| Actor Type | Capabilities | Motivation | Typical Attacks |
|------------|--------------|------------|-----------------|
| **External Opportunist** | Low skill, automated tools | Financial gain, defacement | SQLi, XSS, brute force, known CVE exploitation |
| **Targeted Attacker** | Medium-high skill, custom tools | Espionage, data theft, disruption | Advanced phishing, supply chain attacks, zero-days |
| **Malicious Insider** | Privileged access, deep knowledge | Revenge, financial gain, ideological | Privilege escalation, data exfiltration, backdoor planting |
| **Automated Bot/Worm** | Pattern-based scanning | Mass exploitation, botnet building | Port scanning, vulnerability probing, credential stuffing |

### Attacker Assumptions

1. **Black-box context** — Attacker has no prior access to infrastructure
2. **Public internet access** — Attacker can reach any publicly exposed service
3. **Standard tooling** — Uses common scanners, exploit frameworks (Metasploit, SQLmap, etc.)
4. **Time constraints** — Will move to easier targets if defenses are strong
5. **Persistence** — May return multiple times if initial access is gained

### Threat Scenarios Modeled

✅ **In-Scope Threats:**
- Protocol downgrade attacks (HTTP → HTTPS interception)
- Man-in-the-middle (MITM) via weak TLS/missing HSTS
- Session hijacking via insecure cookies
- Clickjacking via missing frame protection
- Cross-site scripting (XSS) via weak CSP
- Authentication bypass via broken logic
- Authorization bypass via path traversal, IDOR
- Credential stuffing/brute force
- Information disclosure via verbose errors, exposed files
- Supply chain compromise via dependency vulnerabilities
- Subdomain takeover via dangling DNS
- Backdoor injection via compromised plugins/themes (WordPress)

❌ **Out-of-Scope Threats:**
- Advanced persistent threats (APT) with zero-day exploits
- Physical access attacks
- Social engineering (phishing, pretexting)
- Denial-of-service (DoS/DDoS)
- Insider threats with elevated privileges
- Client-side attacks beyond the web layer (malware, ransomware)

---

## Attack Surface Scope

### What SHIELD Assesses

SHIELD performs **black-box testing** of the **web application layer** accessible via HTTP/HTTPS:

```
┌─────────────────────────────────────────────────────────┐
│                     IN SCOPE                            │
├─────────────────────────────────────────────────────────┤
│  • HTTP/HTTPS responses (headers, body, redirects)     │
│  • TLS/SSL configuration (versions, ciphers, certs)    │
│  • DNS records (SPF, DMARC, DNSSEC, CAA)               │
│  • Publicly accessible URLs/endpoints                   │
│  • Web application content (HTML, JS, CSS)             │
│  • Exposed files (backups, configs, source maps)       │
│  • API endpoints (REST, GraphQL, XML-RPC)              │
│  • Third-party resource loading (CDNs, analytics)      │
│  • Certificate transparency logs (public data)          │
│  • Subdomain enumeration (DNS queries only)            │
│  • Open port detection (standard web/database ports)   │
│  • WAF/CDN fingerprinting (passive detection)          │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│                   OUT OF SCOPE                          │
├─────────────────────────────────────────────────────────┤
│  ✗ Server filesystem (no SSH/RDP access)               │
│  ✗ Database content (no direct DB queries)             │
│  ✗ Internal networks (no SSRF exploitation)            │
│  ✗ Memory/processes (no runtime analysis)              │
│  ✗ Source code (no SAST, no repository access)         │
│  ✗ Email infrastructure (no mail server testing)       │
│  ✗ Mobile apps (no APK/IPA analysis)                   │
│  ✗ Desktop applications                                 │
│  ✗ Network-layer attacks (no packet injection)         │
└─────────────────────────────────────────────────────────┘
```

---

## Assessment Layers

SHIELD's 6-step methodology maps to standard security assessment phases:

| Step | Layer | OWASP WSTG Mapping | Attack Phase Modeled |
|------|-------|--------------------|----------------------|
| **1** | Scope | WSTG-INFO | Reconnaissance |
| **2** | External Hardening | WSTG-CONF | Initial Access → Transport Security |
| **3** | Auth & Session | WSTG-ATHN, WSTG-SESS | Credential Access |
| **4** | Authorization | WSTG-ATHZ | Privilege Escalation, Lateral Movement |
| **5** | Backdoor Detection | WSTG-INPV, WSTG-CLNT | Persistence, Defense Evasion |
| **6** | Infrastructure | WSTG-CONF | Reconnaissance (external), Exfiltration prep |

---

## Evidence Collection Procedures

### Request/Response Capture

**What is logged:**
- Full HTTP request (method, URL, headers, body)
- Full HTTP response (status code, headers, body)
- Resolved IP addresses (A/AAAA records)
- Redirect chains (all intermediate steps)
- TLS negotiation details (protocol, cipher suite)
- Certificate chain (full X.509 details)
- Response timing (milliseconds)
- User-Agent used
- Timestamp (UTC)

**What is NOT logged:**
- Credentials (never stored, even for authorized testing)
- Session tokens (redacted in logs)
- Personal data from responses (sanitized if detected)

### Non-Destructive Testing (Posture Mode)

In **posture mode** (default), SHIELD:
- ✅ Reads public data only
- ✅ Follows redirects
- ✅ Parses HTML/JS/CSS content
- ✅ Queries DNS records
- ✅ Checks certificate validity
- ❌ Never writes data
- ❌ Never submits forms (except login in authorized mode)
- ❌ Never uploads files
- ❌ Never attempts exploitation

### Controlled Active Testing (Authorized Mode)

In **authorized mode** (requires `--i-accept-risk` + written permission):
- ✅ Minimal write operations (immediately cleaned up)
- ✅ Authentication tests (with valid credentials provided)
- ✅ Rate limit threshold measurement
- ✅ JWT manipulation tests (detection-based)
- ✅ SQL injection probes (error-based, no extraction)
- ✅ Session validation tests
- ⚠️ All actions logged in audit trail
- ⚠️ Stability monitoring (aborts if target unstable)
- ⚠️ Rate-limited to prevent disruption
- ❌ No exploitation (detection only)

---

## Ethical Boundaries

### Authorization Requirements

| Scan Mode | Authorization Required | Use Case |
|-----------|------------------------|----------|
| **Posture** | ❌ No (passive only) | CI/CD, compliance monitoring, public reconnaissance |
| **Authorized** | ✅ Yes (written permission) | Pre-production audits, penetration testing, vulnerability assessment |

### Legal Compliance

SHIELD users must comply with:

1. **Computer Fraud and Abuse Act (CFAA)** — U.S. federal law prohibiting unauthorized computer access
2. **Computer Misuse Act** — U.K. equivalent to CFAA
3. **General Data Protection Regulation (GDPR)** — EU data protection law (if processing personal data)
4. **Relevant local laws** — Varies by jurisdiction

**Authorized mode requirements:**
- Written authorization from system owner
- Defined scope (specific URLs/domains)
- Time window (start/end dates)
- Acceptable test types (which checks are allowed)
- Liability acknowledgment
- Incident response contact

**Unauthorized testing may result in:**
- Criminal prosecution
- Civil lawsuits
- Professional sanctions
- Reputational damage

### Responsible Disclosure

If SHIELD detects critical vulnerabilities:

1. **Do not exploit** — Document finding, do not extract data
2. **Notify owner** — Contact via security@domain or abuse contact
3. **Allow remediation time** — 90 days standard disclosure timeline
4. **Coordinate disclosure** — Work with owner on public disclosure timing
5. **Publish responsibly** — Redact sensitive details in public reports

---

## Data Handling & Privacy

### Scan Results

**Storage:**
- Report files stored locally only (default: `./test_output/`)
- User controls retention policy
- No automatic cloud upload

**Sensitive Data:**
- Credentials never logged
- Session tokens redacted
- Personal data sanitized
- IP addresses may be logged (necessary for DNS analysis)

**Sharing:**
- Reports may contain sensitive security findings
- Share only with authorized stakeholders
- Encrypt in transit (HTTPS, SFTP, etc.)
- Use access controls if storing in shared environments

### Target Privacy

SHIELD respects target privacy by:
- Using standard HTTP/HTTPS (no packet injection)
- Identifying as `SHIELD-Security-Scanner/2.0` in User-Agent (unless `--rotate-ua`)
- Respecting `robots.txt` (informational, not enforced)
- Not performing OSINT beyond public DNS/certificate logs

---

## Limitations & Known Blind Spots

### What SHIELD Cannot Detect

1. **Logic flaws** — Application-specific business logic vulnerabilities
2. **Race conditions** — Time-of-check/time-of-use vulnerabilities
3. **Advanced obfuscation** — Heavily obfuscated malware may evade detection
4. **Zero-day exploits** — Unknown vulnerabilities not in CVE databases
5. **Social engineering vectors** — Human factors outside technical scope
6. **Encrypted traffic analysis** — Cannot inspect HTTPS payload (by design)
7. **Client-side malware** — No browser-based execution environment

### False Positives

SHIELD aims for **<5% false positive rate** via:
- Confidence levels (HIGH/MEDIUM/LOW)
- Policy suppressions (justification required)
- Multiple detection signals per check
- Conservative thresholds

**Known false positive sources:**
- Headless CMS/WordPress (detected as WordPress but missing login page)
- WAF responses (may block legitimate checks, appear as failures)
- CDN interference (cached responses, edge behavior differs from origin)
- Timing-based checks (network latency variability)

### False Negatives

**Known limitations:**
- Cannot detect server-side backdoors without filesystem access
- Cannot detect SQL injection if WAF blocks payloads
- Cannot detect XSS if CSP is properly configured (design goal)
- May miss subdirectories if not listed in `robots.txt` or sitemap

---

## Standards Alignment

SHIELD maps checks to established frameworks:

| Standard | Coverage | Mapping |
|----------|----------|---------|
| **OWASP WSTG 4.2** | Web application testing | `wstg_id` in remediation.json |
| **OWASP ASVS 4.0** | Verification requirements | Planned (Phase 6B) |
| **CWE Top 25** | Common weaknesses | `cwe_id` in remediation.json |
| **NIST CSF** | Cybersecurity framework | Planned (Phase 6B) |
| **PCI DSS 4.0** | Payment card industry | Partial (TLS, headers) |
| **ISO 27001** | Information security | Partial (controls in Step 2-4) |

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-03-02 | Initial methodology |
| 2.0.0 | 2026-03-02 | Phase 6: Added dual-mode, ethical boundaries, evidence procedures |

---

## See Also

- [Scoring](./scoring.md) — Grading algorithm and severity definitions
- [Modes](./modes.md) — Posture vs Authorized scanning details
- [Usage](./usage.md) — Practical command-line examples
