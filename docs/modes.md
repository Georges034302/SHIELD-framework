# SHIELD Dual-Mode Architecture

## Overview

SHIELD operates in two distinct modes to serve different security testing needs while maintaining clear legal and ethical boundaries.

| Mode | Purpose | Authorization | Use Cases |
|------|---------|---------------|-----------|
| **Posture** | Continuous security monitoring | ❌ Not required | CI/CD pipelines, compliance checking, production monitoring |
| **Authorized** | Active penetration testing | ✅ Required | Pre-production audits, security assessments, vulnerability validation |

---

## Posture Mode (Default)

### Purpose

Passive, non-destructive security assessment suitable for production environments and continuous monitoring.

### Characteristics

✅ **100% Passive Checks**
- Reads public data only (headers, DNS, certificates, content)
- No write operations
- No form submissions
- No file uploads
- No authentication attempts (except if `--user/--pass` provided for WordPress checks)

✅ **Safe for Production**
- Cannot disrupt services
- Cannot trigger security alerts
- Cannot create data
- Cannot modify configuration

✅ **No Authorization Required**
- Legal to run against any publicly accessible website
- Respects standard web protocols (HTTP, DNS, TLS)
- Operates within normal web browser capabilities

✅ **Default Behavior**
- No special flags required
- All 69 checks run in passive mode (active checks skipped)
- Standard timeout values (10 seconds default)

### Command Examples

```bash
# Basic posture scan
bash scripts/run_all.sh https://example.com

# With custom output directory
bash scripts/run_all.sh -o /tmp/scan_results https://example.com

# With rate-aware mode (respectful scanning)
bash scripts/run_all.sh --rate-aware https://example.com

# WordPress authenticated checks (still posture mode for non-WP tests)
bash scripts/run_all.sh --user admin --pass 'SecurePass123' https://example.com
```

### What Gets Checked

All 69 checks run, but active tests are **skipped**:

| Check Type | Posture Mode Behavior |
|------------|----------------------|
| Header analysis | ✅ Full scan |
| TLS configuration | ✅ Full scan |
| DNS records | ✅ Full scan |
| Content analysis | ✅ Full scan|
| File exposure detection | ✅ Full scan (read-only)|
| Port scanning | ✅ Full scan |
| Subdomain enumeration | ✅ Full scan |
| JWT analysis | ✅ Decode only (no manipulation) |
| API endpoint discovery | ✅ Discovery only (no abuse testing) |
| Dependency file parsing | ✅ Read-only |
| Brute force testing | ❌ Skipped |
| Write operation tests | ❌ Skipped |
| SQL injection probes | ❌ Skipped |

### Audit Trail

**JSON Output Includes:**
```json
{
  "scan_mode": "posture",
  "authorization_ref": null,
  "timestamp": "2026-03-02T10:15:30Z",
  "stability": {
    "total_requests": 245,
    "successful_requests": 243,
    "failed_requests": 2
  }
}
```

---

## Authorized Mode

### Purpose

Controlled active testing for pre-production security assessment and penetration testing engagements.

### Requirements

#### 1. Explicit Risk Acceptance

```bash
--i-accept-risk
```

This flag is **mandatory** and serves as acknowledgment that:
- Active testing may trigger security alerts
- Services may be temporarily disrupted
- Test artifacts will be created (and automatically cleaned up)
- User assumes responsibility for testing

#### 2. Authorization Reference (Recommended)

```bash
--authorization-ref /path/to/authorization.pdf
```

Provides audit trail linking scan to written authorization. Best practices:
- Store signed authorization document
- Include scope definition (URLs, date range, test types)
- Reference in all reports

#### 3. Written Permission

**Must have:**
- Document from system owner authorizing testing
- Defined scope (specific domains/URLs)
- Time window (start and end dates)
- Contact information for emergencies
- Liability acknowledgment

**Authorization Template:**

```
SECURITY TESTING AUTHORIZATION

I, [System Owner Name], authorize [Tester Name] to conduct security 
testing on the following systems:

Scope:
  • URLs: https://staging.example.com, https://app.example.com
  • Excluded: https://production.example.com
  
Time Window:
  • Start: 2026-03-15 00:00 UTC
  • End: 2026-03-22 23:59 UTC
  
Authorized Tests:
  • Authentication bypass testing
  • Session manipulation
  • API abuse detection
  • SQL injection probes (detection-based only)
  • Rate limit measurement
  • File upload validation
  
Contact:
  • Emergency: +1-555-0100
  • Email: security@example.com

Signature: _______________  Date: __________
```

### Characteristics

✅ **Controlled Active Testing**
- Write operations allowed (with auto-cleanup)
- Authentication bypass tests
- Rate limit threshold measurement
- JWT manipulation tests
- SQL injection probes (error-based, no exploitation)
- API abuse testing

⚠️ **Safety Guardrails**
- Stability monitoring (aborts if target unstable)
- Rate limiting enforced (default: 60 req/min, configurable)
- Auto-cleanup of test artifacts
- Exponential backoff on rate limits
- Full audit trail logging

⚠️ **Still Non-Exploitative**
- Detection-based only (no data extraction)
- No privilege escalation beyond auth tests
- No lateral movement
- No persistent access creation
- No data exfiltration

### Command Examples

```bash
# Minimal authorized mode
bash scripts/run_all.sh \
  --mode authorized \
  --i-accept-risk \
  https://staging.example.com

# With authorization reference
bash scripts/run_all.sh \
  --mode authorized \
  --i-accept-risk \
  --authorization-ref ~/auth_docs/staging_auth.pdf \
  https://staging.example.com

# Full authorized scan with WordPress credentials
bash scripts/run_all.sh \
  --mode authorized \
  --i-accept-risk \
  --authorization-ref auth.pdf \
  --user admin \
  --pass 'TestPassword123!' \
  --brute-force \
  https://staging.example.com

# With rate-aware mode
bash scripts/run_all.sh \
  --mode authorized \
  --i-accept-risk \
  --rate-aware \
  --max-requests 30 \
  https://staging.example.com
```

### What Gets Checked

All 69 checks run with **active tests enabled**:

| Check Type | Authorized Mode Behavior |
|------------|--------------------------|
| All posture mode checks | ✅ Full scan |
| JWT manipulation | ✅ Algorithm confusion tests, signature bypass |
| API abuse | ✅ Write attempt tests (auto-deleted) |
| SQL injection | ✅ Error-based probes (no extraction) |
| Rate limit measurement | ✅ Controlled threshold testing (max 20 req) |
| Brute force | ✅ If `--brute-force` flag set (max 10 attempts) |
| WordPress REST abuse | ✅ Post/media creation tests (auto-deleted) |

### Startup Banner

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔒 AUTHORIZED SECURITY ASSESSMENT MODE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

This mode enables controlled active security testing including:
  • Write operation tests (auto-cleanup enabled)
  • Authentication bypass probes
  • Rate limit threshold measurement
  • Session manipulation tests

All active tests are:
  ✓ Logged in audit trail
  ✓ Rate-limited and stability-monitored
  ✓ Non-exploitative (detection-based only)
  ✓ Automatically cleaned up

Authorization reference: /path/to/auth.pdf

Legal Requirement: Written authorization from system owner required.
Unauthorized testing may violate computer fraud and abuse laws.

Press Ctrl+C within 5 seconds to abort...
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### Audit Trail

**Enhanced JSON Output:**
```json
{
  "scan_mode": "authorized",
  "authorization_ref": "/path/to/auth.pdf",
  "risk_acceptance": true,
  "timestamp": "2026-03-02T10:15:30Z",
  "active_tests_performed": [
    "jwt_algorithm_confusion",
    "api_rate_threshold_test",
    "wp_rest_write_test"
  ],
  "cleanup_actions": [
    "deleted_test_user_id_42",
    "deleted_test_media_123",
    "deleted_test_post_456"
  ],
  "stability": {
    "total_requests": 482,
    "successful_requests": 478,
    "failed_requests": 1,
    "rate_limited_requests": 3,
    "server_error_requests": 0
  },
  "stability_events": [
    {
      "timestamp": "2026-03-02T10:16:45Z",
      "type": "rate_limit",
      "message": "Rate limit hit (429) for /api/users - backoff 2s"
    }
  ]
}
```

---

## Comparison Matrix

| Feature | Posture Mode | Authorized Mode |
|---------|--------------|-----------------|
| **Authorization Required** | ❌ No | ✅ Yes (written) |
| **`--i-accept-risk` Flag** | ❌ Not required | ✅ Mandatory |
| **Read Operations** | ✅ Full | ✅ Full |
| **Write Operations** | ❌ None | ✅ Controlled + auto-cleanup |
| **Brute Force Testing** | ❌ Skipped | ✅ If `--brute-force` flag |
| **JWT Manipulation** | ❌ Decode only | ✅ Algorithm confusion tests |
| **API Abuse Testing** | ❌ Discovery only | ✅ Write tests (deleted) |
| **SQL Injection Probes** | ❌ None | ✅ Error-based detection |
| **Stability Monitoring** | ✅ Basic | ✅ Enhanced (auto-abort) |
| **Audit Trail** | ✅ Standard | ✅ Enhanced (all actions logged) |
| **Rate Limiting** | ✅ Optional (`--rate-aware`) | ✅ Enforced (default 60 req/min) |
| **Use in Production** | ✅ Safe | ⚠️ Not recommended |
| **Use in CI/CD** | ✅ Ideal | ❌ Not recommended |
| **Legal Risk** | ✅ Minimal (passive) | ⚠️ Requires authorization |

---

## Mode Selection Guide

### Use Posture Mode When:

✅ Scanning production websites  
✅ Continuous compliance monitoring  
✅ CI/CD security gates  
✅ Public reconnaissance (legal)  
✅ Client demos (no authorization yet)  
✅ Academic research on public sites  
✅ Bug bounty reconnaissance phase  

### Use Authorized Mode When:

✅ Pre-production security audits  
✅ Penetration testing engagements  
✅ Vulnerability validation  
✅ Internal security assessments  
✅ Red team exercises  
✅ Compliance audits requiring active tests  
✅ Security assessment deliverables  

### Never Use Authorized Mode:

❌ Without written authorization  
❌ Against targets you don't own/control  
❌ In production environments (use posture instead)  
❌ For public reconnaissance  
❌ For competitive analysis  
❌ For "testing" websites without permission  

---

## Legal Disclaimer

**⚠️ IMPORTANT:** Unauthorized access to computer systems is illegal in most jurisdictions.

- **U.S.:** Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030
- **U.K.:** Computer Misuse Act 1990
- **EU:** Various national laws implementing Cybercrime Directive

**Even in authorized mode, you MUST:**
1. Have explicit written permission from the system owner
2. Stay within the defined scope
3. Operate within the authorized time window
4. Stop immediately if asked by the system owner
5. Report findings responsibly

**Violation may result in:**
- Criminal prosecution
- Civil lawsuits
- Professional sanctions
- Termination of employment
- Reputational damage

---

## Migration from Phase 5

Existing SHIELD users upgrading to Phase 6:

**Backward Compatibility:**
- Default mode is `posture` (same behavior as Phase 5)
- No breaking changes to existing scans
- Existing `--brute-force` flag still works (now requires authorized mode)
- All CLI flags from Phase 5 still supported

**New Capabilities:**
- Add `--mode authorized` for active testing
- Add policy file support for suppressions
- Enhanced audit trails in all reports
- Stability monitoring prevents target damage

**Recommended Actions:**
1. Review [scoring.md](./scoring.md) for grade calculation changes
2. Update CI/CD pipelines to explicitly use `--mode posture`
3. Archive authorization documents for authorized mode scans

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.0.0 | 2026-03-02 | Phase 6: Initial dual-mode architecture |

---

## See Also

- [Methodology](./methodology.md) — Threat model and boundaries
- [Scoring](./scoring.md) — Grading algorithm
- [Usage](./usage.md) — Command-line examples
