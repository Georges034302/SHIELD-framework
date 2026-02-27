# Step 5 — Defensive Controls & Backdoor Detection

## Purpose

Two-part step: validates OWASP-recommended defensive controls, then performs active black-box backdoor and compromise detection — scanning for injected malware, webshells, SEO spam, cloaking, and threat intelligence flags.

## Architecture

```
step5/
│   ── OWASP Defensive Controls ────────────────────────────────
├── owasp_defensive.sh    # OWASP Top 10 defensive signal checks (aggregate)
├── verbose_errors.sh     # Verbose error messages exposing stack traces or paths
├── error_pages.sh        # Custom 404/500 pages; server info in error responses
├── open_redirect.sh      # Open redirect via URL parameters
├── php_info.sh           # phpinfo() / server-status pages publicly accessible
├── sri_check.sh          # Subresource Integrity on external scripts and stylesheets
├── third_party_scripts.sh # External script sources audited against known CDN whitelist
│
│   ── Backdoor & Compromise Detection ──────────────────────────
├── malicious_content.sh  # Obfuscated JS (eval/atob/fromCharCode), hidden iframes,
│                         #   cryptominer scripts, SEO spam pharma keywords
├── cloaking_check.sh     # Googlebot vs normal UA response diff; Referer-based cloaking;
│                         #   Bingbot confirmation; pharma keywords in bot-only view
├── webshell_paths.sh     # Probes ~30 known webshell paths (c99, r57, wso, alfa, cmd, shell);
│                         #   timing-based execution confirmation
├── env_exposure.sh       # Sensitive file exposure: .env, .git/config, .htpasswd,
│                         #   private keys (id_rsa, server.key), Dockerfile, composer.lock
└── threat_intel.sh       # IP reputation: Spamhaus ZEN/DBL, AbuseIPDB confidence score,
                          #   Google Safe Browsing API, reverse DNS anomalies
```
