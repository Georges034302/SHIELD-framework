# Usage — Running SHIELD

## `run_all.sh`

Orchestrates a full 69-check assessment, writes JSON results, and auto-generates `report.md`.

### Synopsis

```bash
bash scripts/run_all.sh [options] <url> [url2 ...]
```

### Core Options

| Flag | Default | Description |
|------|---------|-------------|
| `--mode <posture\|authorized>` | `posture` | Assessment mode (see Modes below) |
| `--i-accept-risk` | — | **Required** for authorized mode (legal acknowledgment) |
| `-o <dir>` | `test_output` | Output directory for JSON results and report |
| `-t <sec>` | `10` | HTTP timeout per request |
| `-h` / `--help` | — | Print usage and exit |

### Mode-Specific Options

| Flag | Mode | Description |
|------|------|-------------|
| `--brute-force` | authorized | Enable brute force testing (requires `--i-accept-risk`) |
| `--rate-aware` | both | Respect Retry-After headers, exponential backoff |
| `--authorization-ref <id>` | authorized | Authorization reference for audit trail |

### WordPress Options

| Flag | Description |
|------|-------------|
| `--user <name>` | WordPress admin username (enables authenticated testing) |
| `--pass <pass>` | WordPress admin password (required with `--user`) |

### Examples

**Posture Mode (Default — Safe for CI/CD):**
```bash
# Basic posture scan
bash scripts/run_all.sh https://example.com

# Custom output directory and timeout
bash scripts/run_all.sh -o /tmp/shield_out -t 15 https://example.com

# Rate-aware scanning (respects Retry-After headers)
bash scripts/run_all.sh --rate-aware https://example.com

# WordPress authenticated posture scan
bash scripts/run_all.sh --user admin --pass 'SecurePass123!' https://example.com
```

**Authorized Mode (Active Testing — Requires Written Authorization):**
```bash
# Enable authorized mode with brute force testing
bash scripts/run_all.sh --mode authorized --i-accept-risk --brute-force https://example.com

# Authorized mode with audit trail reference
bash scripts/run_all.sh --mode authorized --i-accept-risk --authorization-ref "PEN-2026-001" https://example.com

# Full authorized scan with WordPress authentication
bash scripts/run_all.sh --mode authorized --i-accept-risk --brute-force --user admin --pass 'SecurePass123!' https://example.com
```

### Modes

**🔵 Posture Mode (Default):**
- Passive reconnaissance only
- No brute force, no active authentication probing
- Safe for continuous monitoring and CI/CD pipelines
- No risk of triggering security controls

**🔴 Authorized Mode:**
- Enables brute force lockout testing (10 attempts max)
- Active authentication probing
- Requires `--i-accept-risk` flag (legal acknowledgment)
- **Only use with explicit written authorization**

### WordPress Authenticated Testing

When `--user` and `--pass` are provided, SHIELD performs authenticated checks:

**Step 1 — Authentication:**
- Logs into WordPress admin panel
- Establishes session for subsequent steps
- Verifies admin access rights

**Step 4 — Authenticated Authorization:**
- Enumerates installed plugins with versions
- Detects dangerous code execution plugins (WPCode, Insert Headers & Footers, file managers)
- Tests theme/plugin file editor accessibility
- Reports as **CRITICAL** if code execution capabilities found

**Security:** Credentials used only during scan. Session cookies stored in `$OUT/.session_cookies` and can be deleted after.

### Output Structure

```
test_output/
├── step1/   (3 JSON files)
├── step2/   (16 JSON files)
├── step3/   (11 JSON files)
├── step4/   (19 JSON files)
├── step5/   (12 JSON files)
├── step6/   (8 JSON files)
└── report.md
```

**JSON Format:**
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

Consolidates `step*/` JSON files into a graded Markdown report. Called automatically by `run_all.sh`, but can run standalone.

### Synopsis

```bash
bash scripts/generate_report.sh -i <input_dir> [-o <output_file>]
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-i <dir>` | *(required)* | Directory containing `step*/` JSON folders |
| `-o <file>` | `shield_report.md` | Output path for Markdown report |
| `-h` / `--help` | — | Print usage and exit |

### Examples

```bash
# Generate report from saved scan results
bash scripts/generate_report.sh -i test_output -o report.md

# Re-generate report with custom path
bash scripts/generate_report.sh -i /tmp/shield_run -o ~/reports/example_com.md
```

### Report Contents

- **Executive summary** — Security grade (A–F), issue counts by severity
- **Priority actions** — Critical/High findings first
- **Per-step findings** — Grouped by assessment phase with remediation
- **OWASP mappings** — WSTG + CWE references per finding
- **WordPress analysis** — Platform-specific issues (if detected)
- **Scope disclaimer** — Out-of-scope items (database, filesystem, source)

### Grading Scale

| Grade | Criteria |
|-------|----------|
| **A** | No CRITICAL, HIGH, or MEDIUM issues |
| **B+** | 1 MEDIUM issue |
| **B** | 2–4 MEDIUM issues |
| **C** | 1 HIGH **or** 5+ MEDIUM issues |
| **D** | 3+ HIGH **or** 1 HIGH + 3 MEDIUM |
| **F** | Any CRITICAL issue |

See [docs/scoring.md](scoring.md) for complete grading methodology.

---

## Remediation Database

All remediation guidance comes from [data/remediation.json](../data/remediation.json), keyed by SEC ID (e.g., `SEC-HDR-001`). Each entry includes:
- Apache/Nginx/PHP/WordPress configuration samples
- OWASP WSTG references
- CWE mappings
