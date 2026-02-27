# Step 3 — Authentication & Session: JSON Report Model

## Purpose

Step 3 audits the authentication layer and session lifecycle. It checks for rate limiting on login forms, cookie security flags, session ID rotation post-authentication, session fixation, inactivity timeout, logout effectiveness, user enumeration, and brute-force resistance. WordPress targets additionally get the WP-specific user enumeration audit. Eleven JSON files are produced.

---

## Output Files

| File | SEC IDs | What It Checks | WP Only |
|------|---------|----------------|---------|
| `step3/discover.json` | — | Login page discovery and HTTP status |  |
| `step3/login_protection.json` | SEC-LOGIN-001/002 | CAPTCHA, 2FA signals, lockout indicators on login form |  |
| `step3/ratelimit.json` | SEC-RATE-001/002 | Rate limiting on login endpoint (429 or lockout response) |  |
| `step3/brute_force_check.json` | SEC-BRUTE-002/003 | Active brute-force test — default credentials + lockout (`--brute-force` flag required) |  |
| `step3/cookie_flags.json` | SEC-COOKIE-001/002 | Secure, HttpOnly, SameSite flags on session cookies |  |
| `step3/session_rotation.json` | SEC-SESS-001 | Session ID changes after authentication |  |
| `step3/session_fixation.json` | SEC-SESS-001/002 | Session fixation vulnerability (pre-auth token accepted post-auth) |  |
| `step3/timeout.json` | SEC-TIMEOUT-001 | Session inactivity timeout present and enforced |  |
| `step3/logout.json` | SEC-LOGOUT-001 | Logout invalidates server-side session (token reuse test) |  |
| `step3/user_enumeration.json` | SEC-ENUM-001/002 | Username oracle via login error messages and response timing |  |
| `step3/wp_users.json` | SEC-WPUSR-001/002/003 | WP REST API user listing, `?author=` redirect enumeration, login error specificity | ✅ |

---

## JSON Structure

### `ratelimit.json` — rate limiting absent

```json
{
  "step": "step3/ratelimit",
  "timestamp": "2026-02-27T10:03:00Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-RATE-002",
      "name": "Login Rate Limiting",
      "status": "FAIL",
      "severity": "HIGH",
      "found": "20 requests, no 429 or lockout detected",
      "expected": "429 or lockout after 5 attempts",
      "detail": "Login endpoint does not rate-limit — brute force unrestricted"
    }
  ]
}
```

### `cookie_flags.json` — missing flags

```json
{
  "step": "step3/cookie_flags",
  "timestamp": "2026-02-27T10:03:30Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-COOKIE-002",
      "name": "Session Cookie Security",
      "status": "WARN",
      "severity": "MEDIUM",
      "found": "PHPSESSID — missing: SameSite",
      "expected": "Secure, HttpOnly, SameSite=Strict/Lax",
      "detail": "2 cookie security issues found: missing SameSite flag"
    }
  ]
}
```

### `brute_force_check.json` — default credentials succeeded

```json
{
  "step": "step3/brute_force_check",
  "timestamp": "2026-02-27T10:04:00Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-BRUTE-003",
      "name": "Default Credential Login",
      "status": "FAIL",
      "severity": "CRITICAL",
      "found": "Login succeeded for user 'admin' with password 'admin'",
      "expected": "No default credentials; strong unique passwords required",
      "detail": "Default credential login succeeded — change password immediately"
    }
  ]
}
```

> **Note:** `brute_force_check.json` only contains active test results when `run_all.sh` was invoked with `--brute-force`. Otherwise it contains a single `SKIP` check.

### `wp_users.json` — WordPress user enumeration

```json
{
  "step": "step3/wp_users",
  "timestamp": "2026-02-27T10:04:30Z",
  "target": "https://example.com",
  "checks": [
    {
      "id": "SEC-WPUSR-001",
      "name": "REST API User Exposure",
      "status": "FAIL",
      "severity": "HIGH",
      "found": "3 users exposed: admin, editor, author1",
      "expected": "REST API user listing disabled",
      "detail": "REST API /wp-json/wp/v2/users exposes 3 users"
    },
    {
      "id": "SEC-WPUSR-002",
      "name": "Author Enumeration",
      "status": "FAIL",
      "severity": "HIGH",
      "found": "?author=1 → /author/admin/, ?author=2 → /author/editor/",
      "expected": "Block ?author= redirects (return 404)",
      "detail": "Author enumeration via /?author=N reveals usernames"
    },
    {
      "id": "SEC-WPUSR-003",
      "name": "Login Error Specificity",
      "status": "FAIL",
      "severity": "MEDIUM",
      "found": "login page reveals 'Invalid username'",
      "expected": "Generic error only: 'Invalid credentials'",
      "detail": "Login page allows username oracle via specific error messages"
    }
  ]
}
```

---

## Status Values

| Status | Meaning |
|--------|---------|
| `PASS` | Control in place and effective |
| `WARN` | Partial implementation or suboptimal configuration |
| `FAIL` | Control absent or bypassable |
| `SKIP` | Check not applicable (WP-only on non-WP target; brute-force without flag) |

---

## What to Look For

| Priority | Finding | Risk |
|----------|---------|------|
| 🔴 CRITICAL | `SEC-BRUTE-003` Default credentials accepted | Full account compromise |
| 🔴 HIGH | `SEC-BRUTE-002` No lockout after N attempts | Unrestricted brute force |
| 🔴 HIGH | `SEC-RATE-002` No rate limiting | Credential stuffing at scale |
| 🔴 HIGH | `SEC-WPUSR-001` REST API exposes usernames | Combine with brute force |
| 🔴 HIGH | `SEC-WPUSR-002` Author enumeration | Username list for password attacks |
| 🔴 HIGH | `SEC-SESS-002` Session fixation confirmed | Session hijack without credentials |
| 🔴 HIGH | `SEC-ENUM-002` Multiple enumeration vectors | Username oracle enables targeted attacks |
| 🔴 HIGH | `SEC-LOGOUT-001` Session token valid after logout | Persistent session hijack |
| 🟡 MEDIUM | `SEC-COOKIE-002` Missing SameSite flag | CSRF combined with XSS |
| 🟡 MEDIUM | `SEC-WPUSR-003` Specific login errors | Username validation without brute force |
| 🟡 MEDIUM | `SEC-TIMEOUT-001` No inactivity timeout | Long-lived session exposure |
| 🟡 MEDIUM | `SEC-LOGIN-001` No lockout indicator | Indicates absent rate limit backend |
