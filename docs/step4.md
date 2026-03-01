# Step 4 — Authorization & Access Control

## Purpose

Probes what unauthenticated requests can reach. Tests access control boundaries, dangerous file/endpoint exposure, and WordPress-specific attack surface.

## Architecture

```
step4/
├── access_control.sh     # Forced browsing: restricted pages reachable without auth
├── admin_paths.sh        # Exposed admin panel paths (/admin, /dashboard, /wp-admin, etc.)
├── api_auth.sh           # API endpoints enforcing authentication (REST, JSON)
├── cors_check.sh         # CORS policy: wildcard origins, credentials with wildcard
├── directory_listing.sh  # Open directory listing on web root and common asset paths
├── sensitive_files.sh    # Sensitive file exposure: robots.txt leakage, sitemap, changelog
├── graphql.sh            # GraphQL introspection enabled; batching / field enumeration
├── cloud_storage.sh      # Public S3 / GCS / Azure Blob bucket access
├── file_upload.sh        # File upload type validation; executable upload acceptance
├── backup_files.sh       # Backup and archive file exposure (.sql, .zip, .bak, .tar.gz)
├── path_traversal.sh     # Path traversal via URL parameters and path segments
├── http_methods.sh       # Dangerous HTTP methods: PUT, DELETE, TRACE, WebDAV
│
│   ── WordPress (gated on WP detection in Step 1) ──────────────
├── wp_config_exposure.sh # [WP] wp-config.php / backup config file readable from web
├── wp_debug.sh           # [WP] WP_DEBUG active; debug.log web-accessible
├── wp_plugins.sh         # [WP] Plugin version detection; known-vulnerable plugin check
├── xmlrpc.sh             # [WP] XML-RPC active; system.multicall brute amplification; pingback SSRF
│
│   ── Authenticated Tests (require --user and --pass) ──────────
├── installed_plugins_auth.sh    # [AUTH] Enumerate all installed plugins and versions
├── dangerous_plugins_auth.sh    # [AUTH] Detect code execution plugins (WPCode, file managers)
└── file_editors_auth.sh         # [AUTH] Check if theme/plugin file editors are accessible
```
