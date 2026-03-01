# Step 4 — Access Control & Exposure: JSON Report Model

## Purpose

Step 4 tests whether application resources that should be restricted are actually protected. It probes admin paths, sensitive files, API endpoints, CORS policy, directory listing, HTTP methods, backup/archive files, path traversal, file upload handling, GraphQL introspection, cloud storage ACLs, and — for WordPress targets — configuration file exposure, debug mode, plugin vulnerabilities, and xmlrpc.php. When credentials are provided, additional authenticated tests enumerate installed plugins, detect dangerous code execution plugins, and verify file editor access controls. Nineteen JSON files are produced.

---

## Output Files

| File | SEC IDs | What It Checks | WP Only |
|------|---------|----------------|---------|
| `step4/access_control.json` | SEC-ACCESS-001/002 | Authenticated-only paths accessible without credentials |  |
| `step4/admin_paths.json` | SEC-ADMIN-001/002 | Common admin panel paths publicly accessible |  |
| `step4/sensitive_files.json` | SEC-FILES-001/002 | Config files, `.git`, `.env`, SSH keys, licence files |  |
| `step4/cors_check.json` | SEC-CORS-001/002 | CORS Allow-Origin wildcard; credentials with wildcard |  |
| `step4/directory_listing.json` | SEC-DIRLISTING-001/002 | Apache/Nginx directory listing on web directories |  |
| `step4/api_auth.json` | SEC-API-001/002 | Unauthenticated API endpoints returning data |  |
| `step4/graphql.json` | SEC-GRAPHQL-001/002 | GraphQL introspection and playground exposed in production |  |
| `step4/cloud_storage.json` | SEC-CLOUD-001/002 | Public S3/GCS/Azure Blob bucket accessible |  |
| `step4/file_upload.json` | SEC-UPLOAD-001/002 | File upload accepting executable types (PHP, JSP, SH) |  |
| `step4/backup_files.json` | SEC-BACKUP-001/002 | Backup archives and SQL dumps in web root |  |
| `step4/path_traversal.json` | SEC-TRAVERSAL-001 | Path traversal via `../` sequences in parameters |  |
| `step4/http_methods.json` | SEC-METHODS-001/002 | PUT, DELETE, TRACE, CONNECT enabled via OPTIONS |  |
| `step4/wp_config_exposure.json` | SEC-WPCONF-001 | wp-config.php readable; credential exposure | ✅ |
| `step4/wp_debug.json` | SEC-WPDEBUG-001/002 | WP_DEBUG active; debug.log accessible | ✅ |
| `step4/wp_plugins.json` | SEC-WPPLUGIN-001/002 | Plugin enumeration; known vulnerable plugin versions | ✅ |
| `step4/xmlrpc.json` | SEC-XMLRPC-001/002/003 | xmlrpc.php enabled; multicall brute-force amplification | ✅ |
| `step4/installed_plugins_auth.json` | — | Enumerates all installed plugins with versions (requires auth) | ✅ |
| `step4/dangerous_plugins_auth.json` | SEC-PLUGIN-001 | Detects code execution plugins like WPCode (requires auth) | ✅ |
| `step4/file_editors_auth.json` | SEC-EDIT-001/002 | Tests theme/plugin editor accessibility (requires auth) | ✅ |

---

## JSON Structure

### `sensitive_files.json` — files exposed

```json
{
  "step": "step4/sensitive_files",
  "timestamp": "2026-02-27T10:05:00Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-FILES-002",
      "name": "Sensitive Files Exposure",
      "status": "FAIL",
      "severity": "CRITICAL",
      "found": "/.git/config (HTTP 200), /.env (HTTP 200)",
      "expected": "Sensitive files protected",
      "detail": "2 sensitive files exposed: .git/config, .env"
    }
  ]
}
```

### `cors_check.json` — wildcard with credentials

```json
{
  "step": "step4/cors_check",
  "timestamp": "2026-02-27T10:05:30Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-CORS-001",
      "name": "CORS Wildcard with Credentials",
      "status": "FAIL",
      "severity": "CRITICAL",
      "found": "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true",
      "expected": "Restricted CORS policy",
      "detail": "CORS allows any origin with credentials — cross-site session theft possible"
    }
  ]
}
```

### `xmlrpc.json` — multicall enabled

```json
{
  "step": "step4/xmlrpc",
  "timestamp": "2026-02-27T10:06:00Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-XMLRPC-001",
      "name": "XML-RPC Active",
      "status": "FAIL",
      "severity": "HIGH",
      "found": "xmlrpc.php HTTP 200, system.listMethods returns 42 methods",
      "expected": "xmlrpc.php blocked or disabled",
      "detail": "xmlrpc.php active and responding to system.listMethods"
    },
    {
      "id": "SEC-XMLRPC-002",
      "name": "Multicall Brute Force",
      "status": "FAIL",
      "severity": "CRITICAL",
      "found": "system.multicall enabled — 100 credential attempts per HTTP request possible",
      "expected": "Disable xmlrpc.php entirely",
      "detail": "system.multicall allows batching 100+ credential attempts per request"
    }
  ]
}
```

### `backup_files.json` — SQL dump exposed

```json
{
  "step": "step4/backup_files",
  "timestamp": "2026-02-27T10:06:30Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-BACKUP-002",
      "name": "Backup Files Exposed",
      "status": "FAIL",
      "severity": "CRITICAL",
      "found": "/backup.sql (HTTP 200, 2.4 MB), /db_backup.zip (HTTP 200)",
      "expected": "Remove backup/archive files from web root; rotate credentials",
      "detail": "Database dump and backup archive publicly accessible"
    }
  ]
}
```

---

## Status Values

| Status | Meaning |
|--------|---------|
| `PASS` | Path/resource protected as expected |
| `WARN` | Partially exposed or weakly configured |
| `FAIL` | Unprotected resource accessible without authentication |
| `SKIP` | WP-only check on non-WordPress target |

---

## What to Look For

| Priority | Finding | Risk |
|----------|---------|------|
| 🔴 CRITICAL | `SEC-FILES-002` `.git/config`, `.env` exposed | Source code, credentials, secrets leaked |
| 🔴 CRITICAL | `SEC-BACKUP-002` SQL dump/backup in web root | Full database downloadable |
| 🔴 CRITICAL | `SEC-CORS-001` Wildcard CORS + credentials | Cross-site authenticated API access |
| 🔴 CRITICAL | `SEC-ADMIN-002` Multiple admin panels accessible | Unauthenticated admin access |
| 🔴 CRITICAL | `SEC-XMLRPC-002` Multicall brute force amplification | 100x password attempt rate |
| 🔴 CRITICAL | `SEC-TRAVERSAL-001` Path traversal confirmed | Arbitrary file read |
| 🔴 CRITICAL | `SEC-UPLOAD-002` PHP/JSP upload accepted | Remote code execution |
| 🔴 CRITICAL | `SEC-WPCONF-001` wp-config.php readable | Database credentials exposed |
| 🔴 CRITICAL | `SEC-WPDEBUG-002` debug.log with credentials | Sensitive data in accessible file |
| 🔴 CRITICAL | `SEC-WPPLUGIN-001` Known CVE plugin version | Public exploit available |
| 🔴 HIGH | `SEC-METHODS-002` PUT/TRACE enabled | File write or HTTP response splitting |
| 🔴 HIGH | `SEC-GRAPHQL-001` Introspection in production | Full schema enumeration for attack planning |
| 🔴 HIGH | `SEC-CLOUD-002` Public bucket with write access | Data exfiltration or defacement |
| 🟡 MEDIUM | `SEC-DIRLISTING-002` Directory listing on multiple paths | File enumeration |
| 🟡 MEDIUM | `SEC-API-002` Multiple unauthenticated API endpoints | PII or business data leakage |
