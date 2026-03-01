# Step 1 — Scope & Target Validation

## Purpose

Establishes the assessment baseline. Confirms the target is reachable, resolves the canonical URL, records the target in scope, and detects the technology stack. WordPress detection at this step gates all WP-specific checks in Steps 3–5.

## Architecture

```
step1/
├── scope.sh              # Resolves target URL, records canonical host, confirms reachability
├── wp_version.sh         # Detects WordPress; checks version against EOL list; flags version disclosure
└── authenticate.sh       # [Optional] WordPress authentication; establishes session if credentials provided
```

## Authentication (Optional)

When credentials are provided via `--user` and `--pass` flags, SHIELD authenticates to WordPress and establishes a session. This enables **authenticated testing** in subsequent steps, providing deeper analysis of:

- Installed plugins and their versions
- Dangerous code execution plugins (WPCode, file managers)
- Theme/plugin editor accessibility
- Admin-only configuration exposure

**Authentication is completely optional** — if credentials are not provided, SHIELD runs in standard black-box mode.
