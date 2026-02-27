# Step 6 — Infrastructure & Exposure Surface: JSON Report Model

## Purpose

Step 6 extends the assessment beyond the web application into the network and DNS layer. It maps the external attack surface: open ports, DNS configuration integrity, certificate transparency anomalies, WAF presence, shared hosting risks, and subdomain enumeration. These findings sit at the boundary of black-box scope — they are infrastructure-level observations that influence remediation prioritisation but do not require application-level authentication. Eight JSON files are produced.

---

## Output Files

| File | SEC IDs | What It Checks |
|------|---------|----------------|
| `step6/infra_exposure.json` | SEC-INFRA-001/002 | Admin interfaces, service banners, management port exposure (Webmin, Plesk, cPanel) |
| `step6/dns_hygiene.json` | SEC-DNS-001/002 | SPF record presence, MX resolution, basic DNS health |
| `step6/dns_integrity.json` | SEC-DNS-001/002/003/004 | SPF hardfail vs softfail, DMARC enforcement level, MX anomalies, wildcard DNS, suspicious TXT records |
| `step6/subdomain_enum.json` | SEC-SUBDOMAIN-001 | Subdomain enumeration via DNS probing; sensitive subdomain exposure |
| `step6/waf_fingerprint.json` | SEC-WAF-001 | WAF/CDN presence detection and product fingerprinting |
| `step6/shared_hosting.json` | SEC-SHARED-001/002 | Shared hosting indicators, cPanel/Plesk port exposure, cross-site contamination risk |
| `step6/port_scan.json` | SEC-PORT-001/002 | Open port sweep — backdoor listeners, database ports, admin panel ports |
| `step6/cert_transparency.json` | SEC-TLS-001/002/003/004 | crt.sh SAN enumeration, recently issued certificates, self-signed detection, HSTS on TLS |

---

## JSON Structure

### `port_scan.json` — database and backdoor ports open

```json
{
  "step": "step6/port_scan",
  "timestamp": "2026-02-27T10:20:00Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-PORT-001",
      "name": "Critical Ports Open",
      "status": "FAIL",
      "severity": "CRITICAL",
      "found": "3306/tcp (MySQL), 27017/tcp (MongoDB) open from internet",
      "expected": "No database/backdoor ports accessible from internet",
      "detail": "Database ports publicly accessible — no firewall in place"
    },
    {
      "id": "SEC-PORT-001",
      "name": "High-Risk Ports Open",
      "status": "FAIL",
      "severity": "HIGH",
      "found": "2082/tcp (cPanel HTTP), 10000/tcp (Webmin) open",
      "expected": "Admin/panel ports restricted to known IPs",
      "detail": "Admin panel ports reachable from any IP"
    }
  ]
}
```

### `dns_integrity.json` — SPF softfail and DMARC not enforced

```json
{
  "step": "step6/dns_integrity",
  "timestamp": "2026-02-27T10:20:30Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-DNS-001",
      "name": "SPF Hard Fail",
      "status": "WARN",
      "severity": "MEDIUM",
      "found": "v=spf1 include:_spf.google.com ~all",
      "expected": "SPF ends with -all (hardfail)",
      "detail": "SPF uses softfail (~all) — spoofed emails may reach inboxes"
    },
    {
      "id": "SEC-DNS-002",
      "name": "DMARC Enforcement",
      "status": "WARN",
      "severity": "MEDIUM",
      "found": "v=DMARC1; p=none; rua=mailto:dmarc@example.com",
      "expected": "p=quarantine or p=reject",
      "detail": "DMARC is in monitor-only mode (p=none) — no enforcement against spoofed mail"
    },
    {
      "id": "SEC-DNS-004",
      "name": "Wildcard DNS",
      "status": "WARN",
      "severity": "MEDIUM",
      "found": "randomxyz.example.com resolves to 198.51.100.1",
      "expected": "Wildcard DNS disabled unless required for service",
      "detail": "Wildcard DNS active — all subdomains resolve, including unregistered ones"
    }
  ]
}
```

### `cert_transparency.json` — unexpected SANs and recent issuance

```json
{
  "step": "step6/cert_transparency",
  "timestamp": "2026-02-27T10:21:00Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-TLS-003",
      "name": "Certificate SAN Coverage",
      "status": "WARN",
      "severity": "MEDIUM",
      "found": "Certificate covers unrelated domains: staging2.otherdomain.net, *.internal-app.com (18 total SANs)",
      "expected": "Certificate should only cover your domains",
      "detail": "Unexpected SANs may indicate certificate sharing or misconfiguration"
    },
    {
      "id": "SEC-TLS-003",
      "name": "Recently Issued Certificates",
      "status": "WARN",
      "severity": "MEDIUM",
      "found": "3 certificates issued in last 7 days for example.com",
      "expected": "Only your team issues certificates for this domain",
      "detail": "Verify all recent certificates — unexpected issuance may indicate domain takeover attempt"
    }
  ]
}
```

### `waf_fingerprint.json` — no WAF detected

```json
{
  "step": "step6/waf_fingerprint",
  "timestamp": "2026-02-27T10:22:00Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-WAF-001",
      "name": "WAF / CDN Detection",
      "status": "WARN",
      "severity": "MEDIUM",
      "found": "No WAF or CDN fingerprint detected",
      "expected": "WAF or CDN in front of origin",
      "detail": "Site appears directly exposed — no WAF blocking malicious requests"
    }
  ]
}
```

### `subdomain_enum.json` — sensitive subdomains discovered

```json
{
  "step": "step6/subdomain_enum",
  "timestamp": "2026-02-27T10:22:30Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-SUBDOMAIN-001",
      "name": "Sensitive Subdomain Exposure",
      "status": "WARN",
      "severity": "HIGH",
      "found": "dev.example.com (HTTP 200), admin.example.com (HTTP 200), staging.example.com (HTTP 200)",
      "expected": "Secure or remove sensitive subdomains; review CT log exposure",
      "detail": "3 sensitive subdomains discovered via DNS probing and CT logs"
    }
  ]
}
```

---

## Status Values

| Status | Meaning |
|--------|---------|
| `PASS` | Infrastructure configuration meets best practice |
| `WARN` | Suboptimal configuration or informational risk |
| `FAIL` | Active misconfiguration or dangerous exposure |
| `INFO` | Informational — not a direct vulnerability but warrants review |
| `SKIP` | Check not applicable (e.g. no TLS for OCSP; non-resolvable host) |

---

## What to Look For

| Priority | Finding | Risk |
|----------|---------|------|
| 🔴 CRITICAL | `SEC-PORT-001` DB ports open (3306, 5432, 27017) | Direct database access from internet |
| 🔴 CRITICAL | `SEC-PORT-001` Backdoor ports (4444, 1337, 31337) | Active implant/RAT listener |
| 🔴 CRITICAL | `SEC-TLS-002` Self-signed certificate | MITM with no UI warning on some clients |
| 🔴 HIGH | `SEC-SUBDOMAIN-001` dev/staging/admin subdomains exposed | Weaker-security environments reachable |
| 🔴 HIGH | `SEC-PORT-001` Admin panel ports accessible (2082, 8443, 10000) | Hosting panel brute-forceable |
| 🔴 HIGH | `SEC-TLS-001` Cert expired or expiring in <7 days | Imminent outage |
| 🔴 HIGH | `SEC-DNS-003` MX anomaly detected | Email routing hijack possible |
| 🟡 MEDIUM | `SEC-DNS-001` SPF softfail (~all) | Email spoofing reaching inboxes |
| 🟡 MEDIUM | `SEC-DNS-002` DMARC p=none | Spoofed email not quarantined |
| 🟡 MEDIUM | `SEC-WAF-001` No WAF/CDN detected | Origin IP directly exposed; no bot filtering |
| 🟡 MEDIUM | `SEC-DNS-004` Wildcard DNS active | Subdomain takeover prerequisite satisfied |
| 🟡 MEDIUM | `SEC-TLS-003` Unexpected SANs or recent cert issuance | Verify no unauthorised cert issued |
| 🟡 MEDIUM | `SEC-SHARED-002` cPanel/Plesk port open | Hosting panel cross-account attack surface |
| 🟢 LOW | `SEC-SHARED-001` Shared hosting indicators | Consider dedicated/isolated hosting |
