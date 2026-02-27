# Step 2 — External Hardening

## Purpose

Evaluates everything visible to the outside world before any authentication. Covers the full HTTP/TLS stack — headers, encryption, certificate health, redirect enforcement, and server information disclosure.

## Architecture

```
step2/
├── headers.sh            # Core HTTP security headers: X-Frame-Options, X-Content-Type-Options, X-XSS-Protection
├── advanced_headers.sh   # Referrer-Policy, Permissions-Policy, Cross-Origin headers
├── csp_quality.sh        # Content-Security-Policy presence and directive quality
├── hsts_advanced.sh      # HSTS max-age, includeSubDomains, preload flag
├── https.sh              # HTTPS availability and enforcement
├── http_redirect.sh      # HTTP → HTTPS redirect correctness (301 vs 302, no mixed content)
├── tls.sh                # TLS protocol version (rejects SSLv3, TLS 1.0/1.1)
├── tls_protocols.sh      # Detailed TLS protocol negotiation
├── tls_ciphers.sh        # Cipher suite strength; flags weak/export ciphers
├── cert_expiry.sh        # Certificate expiry countdown; alerts at <30 days
├── ocsp_stapling.sh      # OCSP stapling availability and response validity
├── cache_control.sh      # Cache-Control and Pragma headers on sensitive responses
├── exposure.sh           # General information exposure in response headers
├── server_leakage.sh     # Server/X-Powered-By header information leakage
├── server_version.sh     # Web server product version disclosure (Apache, Nginx)
└── php_version.sh        # PHP version disclosure via X-Powered-By header
```
