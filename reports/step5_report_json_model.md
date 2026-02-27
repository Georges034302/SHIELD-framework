# Step 5 — Defensive Controls & Backdoor Detection: JSON Report Model

## Purpose

Step 5 has two complementary purposes. The first half validates OWASP-recommended defensive controls — error handling, open redirects, SRI, third-party scripts, and PHP debug exposure. The second half performs active black-box compromise detection — scanning for injected malware, content cloaking, webshell paths, credential file leakage, and threat intelligence flags. Twelve JSON files are produced.

---

## Output Files

### OWASP Defensive Controls

| File | SEC IDs | What It Checks |
|------|---------|----------------|
| `step5/owasp_defensive.json` | SEC-OWASP-* | Aggregate signal check for OWASP Top 10 defensive controls |
| `step5/verbose_errors.json` | SEC-ERROR-001/002 | Stack traces, file paths, SQL errors visible in HTTP responses |
| `step5/error_pages.json` | SEC-ERRPAGE-001 | Custom 404/500 pages; framework/version info in error output |
| `step5/open_redirect.json` | SEC-REDIRECT-001/002 | Open redirect via URL parameters (`?redirect=`, `?url=`, `?next=`) |
| `step5/php_info.json` | SEC-PHPINFO-001 | phpinfo() pages, Apache server-status, exposed PHP configuration |
| `step5/sri_check.json` | SEC-SRI-001/002 | Subresource Integrity `integrity=` attribute on external scripts/styles |
| `step5/third_party_scripts.json` | SEC-3P-001/002 | Inventory of external script origins; flags unknown CDNs |

### Backdoor & Compromise Detection

| File | SEC IDs | What It Checks |
|------|---------|----------------|
| `step5/malicious_content.json` | SEC-MALJS-001/002, SEC-BACKDOOR-001/002/003, SEC-MINER-001, SEC-CLOAK-001 | Obfuscated JS, hidden iframes, cryptominers, SEO spam, meta-refresh redirect |
| `step5/cloaking_check.json` | SEC-CLOAK-001, SEC-BACKDOOR-002 | Googlebot/Bingbot vs normal UA response size diff; pharma keyword injection to bots only |
| `step5/webshell_paths.json` | SEC-SHELL-001 | ~30 known webshell paths (c99, r57, wso, alfa, cmd, shell); timing-based confirmation |
| `step5/env_exposure.json` | SEC-ENV-001/002 | `.env`, `.git/config`, `.htpasswd`, `id_rsa`, `server.key`, `Dockerfile`, `composer.lock` |
| `step5/threat_intel.json` | SEC-THREAT-001/002/003 | Spamhaus ZEN/DBL, AbuseIPDB confidence score, Google Safe Browsing |

---

## JSON Structure

### `cloaking_check.json` — active SEO spam cloaking

```json
{
  "step": "step5/cloaking_check",
  "timestamp": "2026-02-27T10:10:00Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-CLOAK-001",
      "name": "Googlebot Content Cloaking",
      "status": "FAIL",
      "severity": "CRITICAL",
      "found": "Googlebot response is ~340% different in size vs normal UA (normal: 12,400B, bot: 54,800B)",
      "expected": "Consistent content for all user agents",
      "detail": "Strong cloaking indicator — site likely compromised with SEO spam backdoor"
    },
    {
      "id": "SEC-BACKDOOR-002",
      "name": "Pharma Keyword Injection",
      "status": "FAIL",
      "severity": "CRITICAL",
      "found": "Pharma/spam keywords visible to Googlebot but NOT to normal visitors: 'cheap viagra', 'buy cialis'",
      "expected": "No spam content in any view",
      "detail": "Active SEO spam backdoor confirmed — keywords injected for search engines only"
    }
  ]
}
```

### `webshell_paths.json` — shell accessible

```json
{
  "step": "step5/webshell_paths",
  "timestamp": "2026-02-27T10:11:00Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-SHELL-001",
      "name": "Webshell Path Probe",
      "status": "FAIL",
      "severity": "CRITICAL",
      "found": "/uploads/c99.php (HTTP 200, 42KB, execution confirmed via timing probe)",
      "expected": "No accessible shell paths",
      "detail": "Webshell confirmed accessible — server is compromised"
    }
  ]
}
```

### `threat_intel.json` — blocked IP and domain

```json
{
  "step": "step5/threat_intel",
  "timestamp": "2026-02-27T10:12:00Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-THREAT-001",
      "name": "Spamhaus ZEN Blocklist",
      "status": "FAIL",
      "severity": "HIGH",
      "found": "IP 198.51.100.1 listed on Spamhaus ZEN (zen.spamhaus.org)",
      "expected": "IP not on any blocklist",
      "detail": "Server IP is actively blocklisted — email and reputation impact"
    },
    {
      "id": "SEC-THREAT-003",
      "name": "Google Safe Browsing",
      "status": "FAIL",
      "severity": "CRITICAL",
      "found": "https://example.com flagged as MALWARE by Google Safe Browsing",
      "expected": "Not flagged by Google",
      "detail": "Site is flagged in browser safe-browsing feeds — visitors will see warnings"
    }
  ]
}
```

### `env_exposure.json` — credential file accessible

```json
{
  "step": "step5/env_exposure",
  "timestamp": "2026-02-27T10:12:30Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-ENV-001",
      "name": "Credential/Key Exposure",
      "status": "FAIL",
      "severity": "CRITICAL",
      "found": "/.env (HTTP 200, contains DB_PASSWORD and APP_KEY)",
      "expected": "Sensitive files blocked or absent",
      "detail": "Application credentials exposed via .env file"
    }
  ]
}
```

### `sri_check.json` — SRI missing on CDN resources

```json
{
  "step": "step5/sri_check",
  "timestamp": "2026-02-27T10:13:00Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-SRI-002",
      "name": "SRI Missing on External Scripts",
      "status": "FAIL",
      "severity": "HIGH",
      "found": "3 external scripts without integrity=: cdn.jsdelivr.net/jquery.min.js, ...",
      "expected": "integrity + crossorigin attributes on all external resources",
      "detail": "External scripts loaded without integrity verification — CDN compromise goes undetected"
    }
  ]
}
```

---

## Status Values

| Status | Meaning |
|--------|---------|
| `PASS` | Control present and functional |
| `WARN` | Suboptimal control or elevated threshold |
| `FAIL` | Control absent or compromise evidence found |
| `INFO` | Informational — external scripts listed for manual review |
| `SKIP` | Check skipped (target was unreachable or feature absent) |

---

## What to Look For

| Priority | Finding | Risk |
|----------|---------|------|
| 🔴 CRITICAL | `SEC-CLOAK-001` Large bot/UA response size diff | Active SEO spam / malware backdoor |
| 🔴 CRITICAL | `SEC-BACKDOOR-002` Pharma keywords to bots only | Confirmed SEO spam injection |
| 🔴 CRITICAL | `SEC-SHELL-001` Webshell path accessible | Full server compromise |
| 🔴 CRITICAL | `SEC-ENV-001` `.env` with credentials | Total application credential exposure |
| 🔴 CRITICAL | `SEC-THREAT-003` Google Safe Browsing flag | Active user-facing malware warning |
| 🔴 CRITICAL | `SEC-MINER-001` Cryptominer detected | Active compromise, user CPU hijack |
| 🔴 CRITICAL | `SEC-BACKDOOR-001` Hidden iframe | Drive-by malware delivery |
| 🔴 CRITICAL | `SEC-MALJS-001` Obfuscated JS (eval/atob) | Injected malicious payload |
| 🔴 HIGH | `SEC-THREAT-001` IP on Spamhaus ZEN | Server used for spam; deliverability impact |
| 🔴 HIGH | `SEC-SRI-002` No SRI on CDN scripts | Undetectable CDN supply chain attack |
| 🔴 HIGH | `SEC-PHPINFO-001` phpinfo() accessible | Server config, paths, credentials revealed |
| 🟡 MEDIUM | `SEC-REDIRECT-001` Open redirect confirmed | Phishing redirect from trusted domain |
| 🟡 MEDIUM | `SEC-ERROR-001/002` Stack trace / file paths in errors | Internal architecture exposed |
| 🟡 MEDIUM | `SEC-3P-002` Unknown external script CDNs | Unvetted third-party code execution |
| 🟢 LOW | `SEC-ERRPAGE-001` Generic error page missing | Minor info disclosure |
