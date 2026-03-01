# Usage — Running SHIELD

## `run_all.sh`

Orchestrates a full assessment: runs all 69 step scripts in sequence, writes JSON results to the output directory, then automatically invokes `generate_report.sh` to produce the final Markdown report.

### Synopsis

```bash
bash scripts/run_all.sh [options] <url> [url2 ...]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-o <dir>` | `./test_output` | Directory where JSON results and the final report are written |
| `-t <sec>` | `10` | Per-request HTTP timeout in seconds |
| `--brute-force` | off | Enable brute-force login checks in Step 3 (`brute_force_check.sh`). **Only use against targets you own or have written authorisation for.** |
| `--user <name>` | — | WordPress admin username (enables authenticated testing) |
| `--pass <pass>` | — | WordPress admin password (required with `--user`) |
| `-h` / `--help` | — | Print usage and exit |

### Examples

```bash
# Standard assessment (black-box, no credentials)
bash scripts/run_all.sh https://example.com

# Custom output directory and timeout
bash scripts/run_all.sh -o /tmp/shield_out -t 15 https://example.com

# Enable brute-force checks (authorized targets only)
bash scripts/run_all.sh --brute-force https://example.com

# Authenticated testing (deeper plugin and configuration analysis)
bash scripts/run_all.sh --user admin --pass 'SecurePass123!' https://example.com

# Combined: brute-force + authenticated testing
bash scripts/run_all.sh --brute-force --user admin --pass 'SecurePass123!' https://example.com
```

### Authenticated Testing

When `--user` and `--pass` are provided, SHIELD performs **authenticated testing** in addition to standard black-box checks:

**Step 1 — Authentication:**
- Logs into WordPress admin panel
- Establishes session for use in subsequent steps
- Verifies admin access rights

**Step 4 — Authenticated Authorization Checks:**
- Enumerates all installed plugins with versions
- Detects **dangerous code execution plugins** (WPCode, Insert Headers & Footers, file managers)
- Tests theme and plugin file editor accessibility
- Reports as **CRITICAL** if code execution capabilities found

**Security Note:** Credentials are handled securely and only used for the duration of the scan. Session cookies are stored in `$OUT/.session_cookies` and can be deleted after testing.

### Output Structure

After a run, the output directory contains:

```
test_output/
├── step1/   scope.json, wp_version.json, authenticate.json  (3 files)
├── step2/   headers.json, https.json, tls.json, ...  (16 files)
├── step3/   cookie_flags.json, ratelimit.json, ...   (11 files)
├── step4/   access_control.json, cors_check.json, ... (19 files)
├── step5/   owasp_defensive.json, env_exposure.json, ... (12 files)
├── step6/   dns_integrity.json, port_scan.json, ...  (8 files)
└── report.md   ← final consolidated report
```

Each JSON file follows the structure:

```json
{
  "step": "step2/headers",
  "timestamp": "2026-02-27T10:00:00Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-HDR-001",
      "name": "Content-Security-Policy",
      "status": "FAIL",
      "severity": "HIGH",
      "found": "missing",
      "expected": "present",
      "detail": "CSP header not set"
    }
  ]
}
```

---

## `generate_report.sh`

Reads all `step*/*.json` files from a results directory and produces a graded Markdown security report. Called automatically by `run_all.sh`, but can also be run standalone against any saved results.

### Synopsis

```bash
bash scripts/generate_report.sh -i <input_dir> [-o <output_file>]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-i <dir>` | *(required)* | Directory containing `step*/` JSON output folders |
| `-o <file>` | `shield_report.md` | Output path for the generated Markdown report |
| `-h` / `--help` | — | Print usage and exit |

### Examples

```bash
# Re-generate report from a previous scan
bash scripts/generate_report.sh -i ./test_output -o ./test_output/report.md

# Write to a custom path
bash scripts/generate_report.sh -i /tmp/shield_run -o ~/reports/example_com.md
```

### Report Sections

| Section | Contents |
|---------|----------|
| **Executive Summary** | Grade (A–F), issue counts by severity, total checks run |
| **Issue Summary Table** | One row per FAIL/WARN, with severity and SEC ID |
| **Detailed Findings** | Per-check finding: what was found, what was expected, remediation guidance |
| **WordPress Findings** | Shown only when Step 1 detects WordPress; WP-specific issues isolated |
| **Out of Scope** | Server-side / infrastructure controls outside black-box assessment scope |

### Grading Scale

| Grade | Criteria |
|-------|----------|
| A | No CRITICAL, HIGH, or MEDIUM issues |
| B+ | 1 MEDIUM issue |
| B | 2–4 MEDIUM issues |
| C | 1 HIGH **or** 5+ MEDIUM issues |
| D | 3+ HIGH **or** 1 HIGH + 3 MEDIUM |
| F | Any CRITICAL issue |

### Remediation Database

`generate_report.sh` enriches each finding with fix guidance from `data/remediation.json`. Each entry is keyed by SEC ID (e.g. `SEC-HDR-001`) and contains a plain-English remediation step. If a SEC ID has no entry, the check is listed without a remediation note.
