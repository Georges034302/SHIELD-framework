# Step 2 — Transport & Headers: JSON Report Model

## Purpose

Step 2 is the largest step. It audits the entire transport security stack: HTTPS enforcement, TLS version/cipher configuration, certificate validity and OCSP status, all security response headers, header information disclosure, and cache policy on authenticated paths. Sixteen JSON files are produced.

---

## Output Files

| File | SEC IDs | What It Checks |
|------|---------|----------------|
| `step2/headers.json` | SEC-HSTS-001, SEC-FRAME-001, SEC-XCTO-001, SEC-RP-001 | Core security headers: HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| `step2/advanced_headers.json` | SEC-HEADERS-001/002/003 | Modern headers: Permissions-Policy, Cross-Origin-*-Policy, NEL |
| `step2/hsts_advanced.json` | SEC-HSTS-001/002/003 | HSTS depth: includeSubDomains, preload, max-age adequacy |
| `step2/https.json` | — | HTTPS availability and TLS handshake confirmation |
| `step2/http_redirect.json` | SEC-REDIR-001/002/003/004 | HTTP→HTTPS redirect presence, type (301/308), and target |
| `step2/tls.json` | — | TLS handshake result and negotiated protocol |
| `step2/tls_protocols.json` | SEC-TLS-001/002/003 | Legacy protocol detection (SSLv3, TLS 1.0, TLS 1.1) |
| `step2/tls_ciphers.json` | SEC-TLS-001/002/003 | Weak/export cipher suite detection |
| `step2/csp_quality.json` | SEC-CSP-001/002/003 | CSP presence and quality: unsafe-inline, unsafe-eval, wildcard sources |
| `step2/cert_expiry.json` | SEC-CERT-001 through 006 | Certificate expiry timeline and parseability |
| `step2/ocsp_stapling.json` | SEC-OCSP-001/002 | OCSP stapling and certificate revocation status |
| `step2/cache_control.json` | SEC-CACHE-001/002 | Cache-Control: no-store on authenticated/sensitive paths |
| `step2/exposure.json` | — | Generic information disclosure in headers |
| `step2/server_leakage.json` | SEC-INFO-001 | Information-disclosing headers: Via, X-Powered-By, X-AspNet-Version |
| `step2/server_version.json` | SEC-SRVVER-001/002 | Server header: version exposure, EOL software |
| `step2/php_version.json` | SEC-PHP-001/002 | PHP version in X-Powered-By: EOL, version exposure |

---

## JSON Structure

### Representative example — `headers.json`

```json
{
  "step": "step2/headers",
  "timestamp": "2026-02-27T10:01:00Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-HSTS-001",
      "name": "Strict-Transport-Security",
      "status": "PASS",
      "severity": "HIGH",
      "found": "max-age=31536000; includeSubDomains; preload",
      "expected": "max-age >= 31536000",
      "detail": "HSTS header present and valid"
    },
    {
      "id": "SEC-FRAME-001",
      "name": "X-Frame-Options",
      "status": "FAIL",
      "severity": "MEDIUM",
      "found": "missing",
      "expected": "DENY or SAMEORIGIN",
      "detail": "X-Frame-Options not set — clickjacking possible"
    },
    {
      "id": "SEC-XCTO-001",
      "name": "X-Content-Type-Options",
      "status": "PASS",
      "severity": "MEDIUM",
      "found": "nosniff",
      "expected": "nosniff",
      "detail": "MIME sniffing protection enabled"
    },
    {
      "id": "SEC-RP-001",
      "name": "Referrer-Policy",
      "status": "WARN",
      "severity": "LOW",
      "found": "no-referrer-when-downgrade",
      "expected": "strict-origin-when-cross-origin or stricter",
      "detail": "Referrer policy is permissive"
    }
  ]
}
```

### `tls_protocols.json` — legacy protocol found

```json
{
  "step": "step2/tls_protocols",
  "timestamp": "2026-02-27T10:01:30Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-TLS-001",
      "name": "Legacy TLS Protocols",
      "status": "FAIL",
      "severity": "HIGH",
      "found": "TLS 1.0, TLS 1.1 enabled",
      "expected": "TLS 1.2+ only",
      "detail": "Legacy TLS protocols enabled: TLS1.0, TLS1.1"
    }
  ]
}
```

### `server_version.json` — EOL server

```json
{
  "step": "step2/server_version",
  "timestamp": "2026-02-27T10:02:00Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-SRVVER-001",
      "name": "Server Version Exposure",
      "status": "FAIL",
      "severity": "CRITICAL",
      "found": "Apache/2.2.34",
      "expected": "Suppress version with ServerTokens Prod",
      "detail": "End-of-life Apache version exposed"
    }
  ]
}
```

---

## Status Values

| Status | Meaning |
|--------|---------|
| `PASS` | Check satisfied — no action needed |
| `WARN` | Suboptimal configuration — should be improved |
| `FAIL` | Misconfiguration or absent control — remediation required |
| `SKIP` | Check not applicable (e.g. HTTPS check on HTTP-only target) |

---

## What to Look For

| Priority | Finding | Risk |
|----------|---------|------|
| 🔴 CRITICAL | `SEC-SRVVER-001` EOL server version | Known unpatched CVEs |
| 🔴 CRITICAL | `SEC-PHP-001` EOL PHP version (5.x, 7.x) | Remote code execution risk |
| 🔴 CRITICAL | `SEC-OCSP-002` Certificate revoked | Active MITM risk |
| 🔴 HIGH | `SEC-CERT-004/005` Certificate expired or expiring | Imminent service disruption + warnings |
| 🔴 HIGH | `SEC-TLS-001` TLS 1.0/1.1 active | BEAST / POODLE / downgrade attacks |
| 🔴 HIGH | `SEC-HSTS-001` HSTS missing | MITM on first visit |
| 🔴 HIGH | `SEC-REDIR-003/004` No HTTPS redirect | Cleartext credential exposure |
| 🟡 MEDIUM | `SEC-CSP-001` CSP missing | XSS impact amplified |
| 🟡 MEDIUM | `SEC-CSP-002/003` unsafe-inline / unsafe-eval / wildcard | CSP bypassed |
| 🟡 MEDIUM | `SEC-FRAME-001` X-Frame-Options missing | Clickjacking |
| 🟡 MEDIUM | `SEC-SRVVER-002` Server product name visible | Aids fingerprinting |
| 🟡 MEDIUM | `SEC-PHP-002` PHP version in X-Powered-By | Aids targeted exploitation |
| 🟢 LOW | `SEC-INFO-001` Via / X-AspNet-Version headers | Minor recon data |
| 🟢 LOW | `SEC-CACHE-001` Missing no-store on one path | Potential auth token in cache |
