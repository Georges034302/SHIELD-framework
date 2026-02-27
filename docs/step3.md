# Step 3 — Authentication & Session Controls

## Purpose

Tests the login surface and the full session lifecycle — from credential submission through authenticated state to logout. Includes an opt-in active brute force lockout verification.

## Architecture

```
step3/
├── discover.sh           # Discovers login endpoints (common paths + WP-specific)
├── login_protection.sh   # CAPTCHA and lockout presence on login forms
├── brute_force_check.sh  # Active lockout test: 10 common credential pairs (requires --brute-force flag)
├── ratelimit.sh          # HTTP 429 / rate limit headers on login and API endpoints
├── user_enumeration.sh   # Username enumeration via response timing and error differentiation
├── cookie_flags.sh       # Session cookie Secure, HttpOnly, SameSite flag enforcement
├── session_fixation.sh   # Session ID fixation after authentication
├── session_rotation.sh   # Session token rotation on privilege change
├── timeout.sh            # Idle session timeout enforcement
├── logout.sh             # Session invalidation on logout (token unusable after logout)
└── wp_users.sh           # [WP] User enumeration via REST API and /?author=N redirects  ⟵ WordPress only
```
