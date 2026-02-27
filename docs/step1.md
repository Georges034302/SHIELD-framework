# Step 1 — Scope & Target Validation

## Purpose

Establishes the assessment baseline. Confirms the target is reachable, resolves the canonical URL, records the target in scope, and detects the technology stack. WordPress detection at this step gates all WP-specific checks in Steps 3–5.

## Architecture

```
step1/
├── scope.sh              # Resolves target URL, records canonical host, confirms reachability
└── wp_version.sh         # Detects WordPress; checks version against EOL list; flags version disclosure
```
