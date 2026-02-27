# Step 6 — Infrastructure & Exposure Surface

## Purpose

Maps the external attack surface at the network and DNS layer — beyond the web application itself. Identifies internet-exposed services, DNS misconfigurations, certificate anomalies, WAF presence, and hosting infrastructure risks that influence the overall security posture.

## Architecture

```
step6/
├── infra_exposure.sh     # Admin interfaces, service banners, and management port exposure
├── dns_hygiene.sh        # DNS health: basic SPF/MX checks, resolution consistency
├── dns_integrity.sh      # SPF hardfail, DMARC enforcement, MX hijack, wildcard DNS,
│                         #   suspicious TXT records
├── subdomain_enum.sh     # Subdomain enumeration via DNS probing
├── waf_fingerprint.sh    # WAF presence detection and product fingerprinting
├── shared_hosting.sh     # Shared hosting indicators; cross-site contamination risk;
│                         #   cPanel/Plesk/Webmin port exposure
├── port_scan.sh          # Open port sweep: backdoor listeners (4444/1337/31337),
│                         #   exposed DBs (3306/5432/27017), admin panels (2082/8443/10000)
└── cert_transparency.sh  # Unexpected SANs via crt.sh, recently issued certs,
                          #   self-signed certificates, untrusted CA detection
```
