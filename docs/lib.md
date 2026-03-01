# lib — Shared Library

## Purpose

Reusable Bash modules sourced by every step script. Centralises CLI parsing, HTTP helpers, JSON output building, security check primitives, and WordPress detection so individual step scripts stay focused on their specific checks.

## Architecture

```
scripts/lib/
├── cli.sh          # CLI argument parser — sourced first by every script
│                   #   Exports: OUT, TIMEOUT, ARGS[], BRUTE_FORCE, WP_USER, WP_PASS
│                   #   Flags: -o <dir>, -t <sec>, --brute-force, --user <name>, --pass <pass>, -h/--help
│
├── http.sh         # HTTP request helpers
│                   #   fetch_headers(url, timeout)    → raw response headers
│                   #   fetch_full(url, timeout)       → headers + body
│                   #   get_header(headers, name)      → header value (case-insensitive)
│                   #   has_header(headers, name)      → 0/1 boolean
│
├── output.sh       # JSON report builder
│                   #   json_escape(str)               → safely escaped JSON string
│                   #   init_report(step, target)      → empty JSON structure
│                   #   add_check(id, name, status,
│                   #     severity, found, expected,
│                   #     detail)                      → appends check object
│
├── checks.sh       # Reusable security check primitives
│                   #   check_hsts(headers)            → PASS/WARN/FAIL|value|expected
│                   #   (and other header assertion helpers)
│
└── wp_detect.sh    # WordPress detection — sourced by all WP-specific scripts
                    #   detect_wordpress(target)
                    #     Sets: WP_DETECTED (true/false)
                    #           WP_CONFIDENCE (HIGH/MEDIUM/LOW/NONE)
                    #           WP_VERSION (string or empty)
                    #   Signals checked: wp-login.php, wp-admin redirect,
                    #     generator meta tag, wp-content paths, REST API header
```

## Sourcing Convention

Every step script sources `cli.sh` first, then any other lib modules it needs:

```bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/../lib/cli.sh"
source "$SCRIPT_DIR/../lib/http.sh"
source "$SCRIPT_DIR/../lib/output.sh"
```

WP-specific scripts additionally source `wp_detect.sh` and exit early when `WP_DETECTED` is `false`.
