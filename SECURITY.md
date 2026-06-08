# Security Policy

## Threat Model

Sentinel-mcp operates as a **read-heavy SOC bridge** with limited write capabilities. The threat model categorizes risks:

### High-Risk Operations (Write Tools)
- `isolate_device(hostname)` — Quarantine endpoint from network
- `disable_user(email)` — Suspend user account  
- `block_ip(ip)` — Add IP to firewall blocklist
- `kill_process(hostname, pid)` — Terminate a running process

**Mitigation:** Two-step confirmation with 10-minute TTL tokens. All write actions require explicit analyst approval + token validation.

### Medium-Risk Operations (Information Disclosure)
- `enrich_ioc(indicator)` — Multi-source threat intel lookups (may leak internal IOCs)
- `user_context(email)` — User profile + login history (PII exposure)
- `generate_incident_report(alert_id)` — Structured incident data (includes sensitive details)

**Mitigation:** Rate limiting per analyst, audit logging, role-based access control via Keycloak.

### Low-Risk Operations (Read-Only)
- `get_alert(alert_id)` — Retrieve alert details
- `search_logs(query)` — SIEM log search
- `device_processes(hostname)` — Endpoint inventory
- `recent_logins(email)` — Login event history

**Mitigation:** Audit logging, rate limiting, parameterised queries.

---

## Security Controls

### Input Validation
All tool inputs are validated via Pydantic schemas:
- Type checking (str, int, email, hostname)
- Range validation (limits on time windows, result counts)
- Regex pattern matching (IPs, email addresses, process names)
- No template injection via parametrised database queries

**Status:** ✅ Implemented in Phase 7

### Authentication & Authorization
- **OAuth 2.0/OIDC via Keycloak** — analyst login required
- **Service account for MCP** — tools called by Claude on behalf of analyst
- **Role-based access control (RBAC)** — analyst, senior_analyst, admin roles
- **Policy enforcement via OPA** — declarative rules for tool access

**Policy examples:**
```rego
# Analyst: read tools only
allow[action] if {
  analyst_role
  action in ["get_alert", "search_logs", "enrich_ioc"]
}

# Senior analyst: read + report tools
allow[action] if {
  senior_analyst_role
  action in ["generate_incident_report", "weekly_summary"]
}

# Admin: all tools including write
allow[action] if {
  admin_role
}
```

**Status:** ✅ Implemented in Phase 5

### Rate Limiting
Token-bucket algorithm per analyst:
- Analyst: 100 calls/hour
- Senior analyst: 500 calls/hour
- Admin: unlimited

Limits enforced by Redis. If Redis unavailable, enforcement disabled (graceful degradation).

**Status:** ✅ Implemented in Phase 7

### Audit Logging
Every tool call (allowed or denied) appended to immutable audit log:
- **Tamper-evident:** hash-chained with SHA-256
- **Concurrent-safe:** Postgres advisory locks (serialised writes)
- **Queryable:** timestamp, analyst_id, tool_name, input, policy_result, response_code, duration_ms

Example log entry:
```json
{
  "trace_id": "abc123",
  "analyst_id": "alice.hr@acmecorp.com",
  "tool_name": "isolate_device",
  "input_summary": {"hostname": "DESKTOP-042"},
  "policy_result": {"allowed": true, "reason": "admin role"},
  "response_code": "confirmed",
  "duration_ms": 234,
  "timestamp": "2026-06-08T14:32:01Z"
}
```

**Status:** ✅ Implemented in Phase 1

### Two-Step Confirmation for Write Tools
All write tools require explicit confirmation:
1. **Proposal phase** — analyst runs tool, receives confirmation prompt
2. **Verification phase** — analyst confirms with confirmation token (10-min TTL)

Token stored in Postgres (or in-memory fallback) with:
- Random 32-char URL-safe token (unguessable)
- Tool name validation (prevents token reuse across tools)
- TTL expiry (10 minutes)
- Single-use (consumed on confirmation)

**Example flow:**
```python
# Step 1: proposal
token = await create_proposal(
  tool_name="isolate_device",
  analyst_id="alice@acme.com",
  hostname="DESKTOP-042"
)
# Returns: {"status": "pending", "token": "a1b2c3d4..."}

# Step 2: confirmation (must happen within 10 minutes)
result = await execute_confirmed(
  tool_name="isolate_device",
  analyst_id="alice@acme.com",
  token="a1b2c3d4...",
  hostname="DESKTOP-042"
)
# Returns: {"status": "completed", "hostname": "DESKTOP-042", ...}
```

**Status:** ✅ Implemented in Phase 2

### Error Messages
All errors return generic messages (no sensitive info leakage):
- ❌ Bad: `"User alice@acme.com not found in Keycloak"`
- ✅ Good: `"User not found (code: NOT_FOUND)"`

**Status:** ✅ Implemented in Phase 7

### Secrets Management
- **Environment variables only** — no hardcoded secrets
- **No secrets in .env.example** — only variable names
- **.env file in .gitignore** — never committed
- **Rotation support** — OPA can invalidate policies; API keys can be rotated
- **No client-side secrets** — all sensitive data server-side only

**Status:** ✅ Implemented in Phase 5

### Resilience & Circuit Breakers
All external adapters have:
- **Circuit breaker** — fail fast if service unreachable (5 consecutive failures → OPEN)
- **Exponential backoff retry** — 1s, 2s, 4s, 8s, 16s with jitter
- **Fallback to mock mode** — continue with mock data if adapter fails
- **Health checks** — periodic health probes on all services

**Status:** ✅ Implemented in BaseAdapter (Phase 1)

---

## Security Best Practices for Deployment

### 1. Secrets
```bash
# Generate strong API keys
openssl rand -hex 32  # For ANTHROPIC_API_KEY, etc.

# Store in secure vault (Vault, AWS Secrets Manager, etc.)
export ANTHROPIC_API_KEY=$(vault kv get secret/sentinel/anthropic-key)
export VIRUSTOTAL_API_KEY=$(vault kv get secret/sentinel/virustotal-key)
```

### 2. Database Security
```bash
# Use strong PostgreSQL password
export POSTGRES_PASSWORD=$(openssl rand -base64 32)

# Enable SSL for Postgres connections
SQLALCHEMY_DATABASE_URL="postgresql+asyncpg://user:password@host:5432/sentinel?sslmode=require"

# Restrict Postgres network access to localhost or VPC only
```

### 3. Identity Provider
```bash
# Use Keycloak over HTTPS only
export KEYCLOAK_URL="https://keycloak.example.com"

# Configure realm with:
# - Strong password policies (≥12 chars, mixed case, numbers, symbols)
# - MFA/TOTP enabled for all analysts
# - Session timeout: 1 hour idle, 8 hours absolute
# - Account lockout: 5 failed logins → 15 min lockout
```

### 4. OPA Policies
```bash
# Deploy OPA sidecar with immutable policy bundle
# Never allow runtime policy eval from untrusted sources
# Review all policy changes before deployment

# Example: restrict tool access by time
data.sentinel.time_windows[tool][time_of_day] = allowed
```

### 5. Logging & Monitoring
```bash
# Ship audit logs to centralized SIEM
journalctl -u sentinel | systemd-journal-remote@example.com

# Alert on:
# - Write tool confirmations (isolate_device, disable_user, etc.)
# - Policy violations (denied tool calls)
# - Failed authentications (5+ in 5 minutes)
# - Error rates > 5% on any adapter
```

### 6. Network Security
```bash
# Isolate Sentinel network:
# - Firewall: 8000 (MCP) from Claude Desktop only
# - Firewall: 5432 (Postgres) from localhost only
# - Firewall: 6379 (Redis) from localhost only
# - Firewall: 9200 (OpenSearch) from Wazuh + tests only

# Use VPC/subnet isolation in cloud deployments
```

### 7. Regular Updates
```bash
# Weekly security updates
pip install --upgrade -r requirements.txt
docker pull ghcr.io/astral-sh/uv:latest

# Monthly dependency audit
pip-audit --desc

# Quarterly penetration testing
```

---

## Reporting Security Vulnerabilities

If you discover a security vulnerability, please:

1. **Do NOT open a public GitHub issue** — this could expose others to the vulnerability
2. **Email security@example.com** with:
   - Vulnerability description
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if you have one)
3. We will acknowledge within 48 hours and provide a timeline for patch release

---

## Security Roadmap

### Phase 9 (Future)
- [ ] Hardware security module (HSM) support for key storage
- [ ] Cryptographic attestation of audit log (Merkle tree)
- [ ] FIPS 140-2 compliance mode
- [ ] HIPAA/SOC2 compliance audit

### Phase 10+ (TBD)
- [ ] Fuzzing of all tool inputs
- [ ] Formal verification of OPA policies
- [ ] Supply chain security (SLSA provenance, sigstore signing)

---

## Security Checklist for Operators

Before deploying Sentinel to production:

- [ ] All API keys configured in secrets vault, not .env
- [ ] PostgreSQL has strong password (≥32 chars random)
- [ ] Keycloak realm configured with MFA enforcement
- [ ] OPA policies reviewed and approved by security team
- [ ] Network firewall rules in place (see "Network Security" above)
- [ ] Audit log shipping configured to centralized SIEM
- [ ] Health checks verified on all services (curl /health)
- [ ] Rate limits tuned for your analyst count (default: 100 req/hr)
- [ ] Backup plan documented (how to recover from Postgres loss)
- [ ] Incident response plan drafted (who to notify if tool abused)

---

## Contact

For security questions or to report vulnerabilities:
- **Email:** security@example.com
- **PGP Key:** [Link to public key]
- **Response SLA:** 48 hours acknowledgment, patch release within 72 hours for critical issues

---

**Last Updated:** June 8, 2026  
**Status:** Production (v1.0.0)