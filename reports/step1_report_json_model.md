# Step 1 — Reconnaissance: JSON Report Model

## Purpose

Step 1 establishes the target baseline before any security checks run. It resolves the target URL, detects WordPress and its version, and optionally authenticates if credentials are provided. Findings are used by later steps to gate WP-specific checks and enable authenticated testing. Three JSON files are produced.

---

## Output Files

| File | Script | Description |
|------|--------|-------------|
| `step1/scope.json` | `scope.sh` | Target scope confirmation — resolves URL, HTTP code, final URL after redirects |
| `step1/wp_version.json` | `wp_version.sh` | WordPress detection result and version exposure findings |
| `step1/authenticate.json` | `authenticate.sh` | WordPress authentication result (only produced when --user and --pass provided) |

---

## JSON Structure

### `scope.json`

```json
{
  "step": "step1/scope",
  "timestamp": "2026-02-27T10:00:00Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-SCOPE-001",
      "name": "Target Reachability",
      "status": "PASS",
      "severity": "INFO",
      "found": "HTTP 200 — https://example.com",
      "expected": "Target reachable",
      "detail": "Target confirms reachability"
    }
  ]
}
```

### `wp_version.json` — WordPress NOT detected

```json
{
  "step": "step1/wp_version",
  "timestamp": "2026-02-27T10:00:00Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-WPVER-001",
      "name": "WordPress Detection",
      "status": "SKIP",
      "severity": "INFO",
      "found": "WordPress not detected",
      "expected": "N/A",
      "detail": "WP-specific checks will be skipped in all later steps"
    }
  ]
}
```

### `wp_version.json` — WordPress detected with version exposure

```json
{
  "step": "step1/wp_version",
  "timestamp": "2026-02-27T10:00:00Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-WPVER-001",
      "name": "WordPress Version",
      "status": "WARN",
      "severity": "MEDIUM",
      "found": "WordPress 6.3.2",
      "expected": "Update to current WordPress",
      "detail": "WordPress 6.3.2 is outdated — security patches available for newer 6.x versions"
    },
    {
      "id": "SEC-WPVER-002",
      "name": "Version Metadata Exposure",
      "status": "WARN",
      "severity": "MEDIUM",
      "found": "Version visible in generator tag",
      "expected": "Version metadata removed",
      "detail": "WordPress version 6.3.2 is publicly visible — aids attacker targeting"
    },
    {
      "id": "SEC-WPVER-002",
      "name": "readme.html Exposure",
      "status": "FAIL",
      "severity": "MEDIUM",
      "found": "readme.html accessible, contains version: 6.3.2",
      "expected": "Block or remove readme.html",
      "detail": "readme.html exposes WordPress version publicly"
    }
  ]
}
```

---

## Status Values

| Status | Meaning |
|--------|---------|
| `PASS` | Target reachable, no issues |
| `SKIP` | WordPress not detected — WP checks skipped downstream |
| `WARN` | Outdated WP version or version metadata exposed |
| `FAIL` | EOL WordPress version, readme.html readable with version, wp-includes/version.php exposed |

---

## What to Look For

| Finding | Why It Matters |
|---------|---------------|
| `status: SKIP` in wp_version.json | Confirms non-WP target — all `[WP]` checks in steps 2–5 will be skipped |
| `SEC-WPVER-001 FAIL` | End-of-life WordPress — no security patches available; treat as CRITICAL risk |
| `SEC-WPVER-001 WARN` | Outdated minor version — may have unpatched CVEs; update immediately |
| `SEC-WPVER-002` any FAIL/WARN | Version number visible to attackers — enables targeted CVE exploitation |
| `wp-includes/version.php` accessible | PHP source readable from web — CRITICAL misconfiguration |
| `readme.html` accessible | Confirms WP and version without authentication |

---

## Key Context for Later Steps

- `wp_version.json` status is read by `generate_report.sh` via `is_wordpress()` to toggle the WordPress Findings section in the final report
- If `WP_DETECTED=false`, all scripts in steps 2–5 marked `[WP]` exit with `SKIP` without making any requests
