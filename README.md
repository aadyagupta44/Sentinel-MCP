# Sentinel MCP

Sentinel MCP is a production-grade Model Context Protocol (MCP) server that turns
Claude into a security operations analyst. It gives Claude secure,
policy-enforced, and fully audited access to an entire Security Operations Center
(SOC) toolstack — SIEM alerts, multi-source threat intelligence, identity and
login data, and endpoint telemetry — so an analyst can investigate incidents and
take containment actions in natural language, without leaving the conversation.

It is not a thin wrapper around an API. Every tool call passes through real
authentication (OAuth 2.1 with PKCE against Keycloak), role-based authorization,
an Open Policy Agent policy check, and rate limiting, and is written to a
tamper-evident, hash-chained audit log. Containment actions such as isolating a
host or disabling an account require an explicit two-step confirmation before any
change is made. The same codebase runs as a local stdio server for Claude
Desktop or as a remote, OAuth-secured HTTP connector for a whole team.

## Highlights

- **Eighteen MCP tools** across investigation, threat intelligence, identity, and
  endpoint domains, plus four resources and three investigation playbooks.
- **Real authentication.** OAuth 2.1 with PKCE against Keycloak, including Dynamic
  Client Registration, and RS256 JWT validation on every call.
- **Layered authorization.** A scope-and-role check on every request, backed by an
  Open Policy Agent policy engine as defence in depth.
- **Two-step confirmation** for every containment action, with time-limited,
  tamper-resistant tokens persisted in PostgreSQL.
- **Tamper-evident audit log.** Append-only and SHA-256 hash-chained, serialized
  with PostgreSQL advisory locks, with sensitive data redacted.
- **Redis-backed rate limiting** with per-tool, per-analyst limits defined in
  policy, and fail-closed behaviour for write tools.
- **Resilient integrations.** Every adapter has a circuit breaker, retry with
  exponential backoff, OpenTelemetry spans, and structured logging.
- **Multi-source threat intelligence** across ten providers, with optional
  commercial sources that degrade gracefully when unconfigured.
- **Perimeter enforcement.** `block_ip` persists to a durable block list and, when
  a firewall is configured, pushes the block to its API.
- **Optional AI-generated narratives** for incident reports, produced through the
  Anthropic API when enabled.
- **Full observability.** OpenTelemetry tracing and structured JSON logging
  throughout.
- **Runs anywhere.** A zero-dependency mock mode for evaluation; stdio and
  OAuth-secured HTTP transports; a Docker Compose stack for the full backend.
- **More than 500 automated tests** at roughly 90 percent line coverage.

---

## Live demo

A public demo is deployed as a remote MCP connector. It runs the complete
security stack — Keycloak, PostgreSQL, Redis, Open Policy Agent, and the Sentinel
server — with real authentication, roles, policy enforcement, and audit. Only the
underlying security data is simulated, so you can explore the full workflow
without connecting real systems.

Connector URL:

```
https://aadyagupta44-sentinel-mcp.hf.space/mcp
```

Landing page: https://aadyagupta44-sentinel-mcp.hf.space

### Try it in Claude

1. In Claude (Desktop or claude.ai), open **Settings > Connectors > Add custom
   connector**.
2. Give it any name. Set the URL to the connector URL above. Leave the OAuth
   client ID and secret fields empty — the server supports Dynamic Client
   Registration, so Claude registers itself automatically.
3. When prompted, sign in with one of the demo accounts below. The account you
   choose determines what Claude is allowed to do:

   | Username | Password    | Role           | Access                                   |
   |----------|-------------|----------------|------------------------------------------|
   | `analyst`| `analyst123`| Analyst        | Read and investigation tools only        |
   | `senior` | `senior123` | Senior analyst | Read tools plus containment actions       |
   | `admin`  | `admin123`  | Administrator  | Full access                              |

4. Start a chat and ask, for example:
   - "Get alert ALT-2026-001 and summarize what happened."
   - "Enrich the indicator 185.220.101.5 and tell me if it is malicious."
   - "Give me the weekly SOC summary."
   - "Isolate the host workstation-07." (As `senior`, Claude proposes the action
     and asks you to confirm; as `analyst`, the same request is denied by policy.)

The demo is hosted on free, shared infrastructure. The first request after a
period of inactivity may take up to a minute while the service wakes.

### Demo video

https://github.com/user-attachments/assets/f5bea64c-0e8c-4550-a565-dcfa904e913f

The walkthrough covers:

1. Adding the custom connector in Claude and completing the OAuth sign-in.
2. Investigating an alert end to end: retrieval, indicator enrichment, user
   context, and endpoint telemetry.
3. Correlating related alerts into a single incident and generating a structured
   incident report.
4. Requesting a containment action and completing the two-step confirmation.
5. Demonstrating the role boundary: the same action allowed for a senior analyst
   and denied for a standard analyst.

---

## Getting started

The server runs with no external accounts in a built-in mock mode, which serves
deterministic synthetic data and is suitable for evaluation and development.
Requirements: Python 3.12 or later and the
[uv](https://github.com/astral-sh/uv) package manager.

```bash
git clone <repository-url> sentinel-soc
cd sentinel-soc

uv sync --group dev          # install dependencies (with dev and test tools)
cp .env.example .env         # defaults run in mock mode, no services needed
```

### Run locally

```bash
# stdio transport (default) — used by a local Claude Desktop
uv run python -m sentinel.main

# HTTP transport and the full backend stack (PostgreSQL, Redis, OPA, Keycloak, OpenSearch)
docker compose up -d
```

### Connect a local server to Claude Desktop

Add the server to the Claude Desktop MCP configuration:

```json
{
  "mcpServers": {
    "sentinel": {
      "command": "uv",
      "args": ["run", "python", "-m", "sentinel.main"],
      "cwd": "/path/to/sentinel-soc"
    }
  }
}
```

### Run for real

For a production deployment the same code runs unchanged; the difference is
configuration and infrastructure:

- Set `MOCK_ADAPTERS=false` and point the connection settings (`DATABASE_URL`,
  `REDIS_URL`, `OPA_URL`, `KEYCLOAK_URL`, `OPENSEARCH_URL`, and the optional EDR
  and threat-intelligence settings) at real, managed services.
- Provision analyst accounts and roles in Keycloak (or federate Keycloak to an
  existing corporate identity provider), and assign each analyst the `analyst`,
  `senior_analyst`, or `admin` role.
- Serve the HTTP transport behind TLS on a stable hostname, and have each analyst
  add it as a remote connector in their Claude client. Every analyst authenticates
  as themselves; the server scopes each session to that analyst's role and records
  every action against their identity.
- Run on durable storage so that identities, the block list, pending
  confirmations, and the audit log persist across restarts.

The server validates its configuration at startup and refuses to run in a
production environment with an unsafe setup — for example, authorization disabled,
mock mode enabled, or placeholder connection URLs.

---

## Capabilities

### Tools

Eighteen tools are exposed: fourteen read (investigation) tools and four write
(containment) tools. Write tools require a two-step confirmation before any
change is made.

Read tools:

| Tool | Purpose |
|------|---------|
| `get_alert` | Retrieve a single alert with full context: severity, affected user and host, MITRE techniques, and raw log references. |
| `search_logs` | Full-text search across SIEM logs within a time window. |
| `correlate_alerts` | Group related alerts into incident clusters by shared user, host, source IP, or MITRE technique. |
| `similar_incidents` | Rank historically similar incidents by field similarity. |
| `enrich_ioc` | Produce a composite reputation verdict for an IP, domain, hash, or URL across multiple intelligence sources. |
| `threat_hunt` | Search the full log archive for every occurrence of an indicator and build a timeline. |
| `mitre_technique` | Look up a MITRE ATT&CK technique: name, tactic, detection, and mitigation. |
| `user_context` | Return an identity profile: groups, MFA status, registered devices, and account status. |
| `recent_logins` | Return login history with source IP, country, device, and MFA method. |
| `risk_score_user` | Compute a 0–100 user risk score with a factor breakdown. |
| `device_processes` | List process-creation events on a host, flagging suspicious processes. |
| `network_connections` | List network connections on a host, flagging known-malicious destinations. |
| `generate_incident_report` | Orchestrate the read tools into a structured incident report, with an optional AI-generated narrative summary. |
| `weekly_summary` | Aggregate alert statistics and trends for the past seven days. |

Write tools (two-step confirmation):

| Tool | Action |
|------|--------|
| `isolate_device` | Network-isolate a host via the EDR platform. |
| `disable_user` | Suspend a user account in the identity provider. |
| `block_ip` | Add an IP address to the durable block list and, when a firewall is configured, push the block to its API. |
| `kill_process` | Terminate a process on a host via EDR active response. |

### Resources

Four read-only resources provide ambient context without an explicit tool call:
`sentinel://alerts/active`, `sentinel://alerts/{alert_id}`,
`sentinel://mitre/{technique_id}`, and `sentinel://watchlist/ips`.

### Prompts

Three reusable investigation playbooks are provided: `investigate_alert`,
`triage_user`, and `morning_briefing`.

---

## Architecture

```
Claude (Desktop or remote connector)
  | MCP over stdio or HTTP
  v
Sentinel MCP server (FastMCP)
  - Tools (18), Resources (4), Prompts (3)
  - Per-call middleware pipeline:
      authentication -> authorization (scope + role) -> OPA policy -> rate limit -> execute -> audit
  v
Adapter layer (BaseAdapter: circuit breaker, retry with backoff, OpenTelemetry spans)
  v
Backends
  - OpenSearch (SIEM), Keycloak (identity), Wazuh (EDR), optional perimeter firewall
  - Threat intelligence: abuse.ch, Shodan InternetDB, ip-api, CIRCL, Spamhaus DNSBL,
    and optional VirusTotal, AbuseIPDB, AlienVault OTX, URLScan, OpenCTI
  - Optional Anthropic API for incident-report narratives
```

Key components:

- `sentinel/main.py` — application entry point. In stdio mode it runs the MCP
  protocol directly; in HTTP mode it serves a FastAPI application that mounts the
  MCP streamable-HTTP transport at `/mcp`, exposes an authenticated REST tool
  surface at `/tools/{name}`, and publishes a health endpoint and OAuth discovery
  metadata.
- `sentinel/mcp/` — the FastMCP server instance, the middleware pipeline, and the
  resource and prompt definitions.
- `sentinel/tools/` — the eighteen tool implementations, the two-step confirmation
  framework, and a deterministic mock-data factory used in mock mode.
- `sentinel/adapters/` — sixteen service adapters built on a common `BaseAdapter`
  that provides a circuit breaker, retry with exponential backoff, OpenTelemetry
  spans, structured logging, and a mock-mode hook.
- `sentinel/auth/` — the OAuth 2.1 with PKCE flow, RS256 JWT validation against
  the Keycloak JWKS, and scope and role authorization.
- `sentinel/policy/` — the Open Policy Agent client used as a defence-in-depth
  authorization check.
- `sentinel/audit/` — the immutable, hash-chained audit log.
- `sentinel/config.py` — typed settings loaded from the environment.

---

## Security model

- **Authentication.** The HTTP transport uses OAuth 2.1 with PKCE against
  Keycloak, including Dynamic Client Registration so that MCP clients can enroll
  without manual provisioning. Every tool call requires a valid RS256 Bearer
  token; the analyst identity is taken from the JWT `sub` claim. The stdio
  transport is intended for a trusted local process and uses a static configured
  identity.
- **Authorization.** A scope-and-role check (`soc:read` for read tools, `soc:write`
  plus a `senior_analyst` or `admin` role for write tools) is enforced in the
  middleware on every transport, with OPA as an additional policy layer.
- **Two-step confirmation.** Write tools first return a proposed action and a
  time-limited token; the action executes only on a second call with that token.
  Pending actions are persisted in PostgreSQL, and the server fails closed rather
  than using a non-durable store in production.
- **Rate limiting.** A Redis-backed sliding window enforces per-tool, per-analyst
  limits defined in OPA policy. If Redis is unavailable the server fails closed for
  write tools and degrades open for read tools, with a warning.
- **Audit log.** Every call, allowed or denied, is written to an append-only,
  SHA-256 hash-chained log serialized with PostgreSQL advisory locks. Sensitive
  inputs and personally identifiable information are redacted before logging.
- **Hardening.** The HTTP application sets standard security headers
  (Content-Security-Policy, HSTS, X-Frame-Options, and others), enforces a request
  body size limit, restricts CORS to an explicit allowlist, and validates that the
  runtime configuration is safe for the target environment at startup.

A security audit and the resulting fixes are documented in
[SECURITY_AUDIT.md](SECURITY_AUDIT.md) and
[VULNERABILITY_FIXES.md](VULNERABILITY_FIXES.md); the responsible-disclosure
policy is in [SECURITY.md](SECURITY.md).

---

## Technology stack

| Area | Technologies |
|------|--------------|
| Language and runtime | Python 3.12+, asyncio |
| MCP | Anthropic MCP SDK (FastMCP); streamable-HTTP and stdio transports |
| Web and API | FastAPI, Starlette, Uvicorn, httpx |
| Authentication | OAuth 2.1 with PKCE, Keycloak, RS256 JWT (PyJWT), Dynamic Client Registration |
| Data stores | PostgreSQL (SQLAlchemy async, Alembic migrations), Redis |
| Policy | Open Policy Agent (OPA) |
| Validation and settings | Pydantic, pydantic-settings |
| Observability | OpenTelemetry (tracing), structlog (structured logging) |
| Security backends | OpenSearch (SIEM), Keycloak (identity), Wazuh (EDR), optional perimeter firewall |
| Threat intelligence | abuse.ch, Shodan InternetDB, ip-api, CIRCL, Spamhaus DNSBL; optional VirusTotal, AbuseIPDB, AlienVault OTX, URLScan, OpenCTI |
| Optional AI | Anthropic API for incident-report narratives |
| Testing | pytest, respx, coverage |
| Packaging and delivery | uv, Docker and Docker Compose, Caddy, supervisord |

---

## Transports

- **stdio** (default) — the MCP protocol runs directly over standard
  input/output; this is the transport a local Claude Desktop uses.
- **HTTP** — a FastAPI application exposes the MCP streamable-HTTP transport at
  `/mcp` (Bearer-authenticated), an authenticated REST tool surface at
  `/tools/{name}`, a `/health` endpoint, an MCP manifest at `/.well-known/mcp`, and
  OAuth discovery metadata at `/.well-known/oauth-authorization-server` and
  `/.well-known/oauth-protected-resource`.

---

## Traffic simulator

The `simulator/` package generates synthetic security events for demonstrations
and testing. It models ten employee profiles across five departments, emits
realistic login, file-access, and process events, and periodically fires one of
five adversarial scenarios — impossible travel, brute force, suspicious process,
data exfiltration, and known-bad-IP beaconing — using real abuse.ch indicators.
Events are written to OpenSearch (or any sink) so the Sentinel tools can
investigate them.

```bash
uv run python -m simulator.main --duration 300            # write to OpenSearch
uv run python -m simulator.main --duration 60 --dry-run   # in-memory, no writes
```

---

## Testing and quality

```bash
uv run pytest                         # full test suite with coverage
uv run ruff check sentinel/ tests/    # linting
uv run mypy sentinel/                 # type checking
```

The project has more than 500 automated tests (unit and integration) at
approximately 90 percent line coverage, against a configured minimum of 80
percent. Adapters are tested with respx-mocked HTTP and the authentication flow
with mocked Keycloak endpoints, so the suite runs with no external services.
Continuous integration runs linting, type checking, the test suite, and a Docker
image build.

---

## Project status

Version 1.0.0, with all eight development phases complete: foundation; MCP server
and tools; adapters; tool implementation; authentication and HTTP transport; the
traffic simulator; hardening and observability; and release preparation.

Every tool is adapter-backed and serves live data when configured against real
backends. The built-in mock mode provides deterministic data so the full system
can be evaluated, demonstrated, and tested end to end without provisioning any
external services — the public demo above runs in exactly this mode, with real
authentication, authorization, policy, and audit throughout.

---

## Documentation

Each development phase has a technical journey document and a breakage and risk
report:

| Phase | Journey | Risk report |
|-------|---------|-------------|
| 1 — Foundation | [docs/phases/phase1.md](docs/phases/phase1.md) | [docs/test-reports/phase1.md](docs/test-reports/phase1.md) |
| 2 — MCP Server and Tools | [docs/phases/phase2.md](docs/phases/phase2.md) | [docs/test-reports/phase2.md](docs/test-reports/phase2.md) |
| 3 — Adapters | [docs/phases/phase3.md](docs/phases/phase3.md) | [docs/test-reports/phase3.md](docs/test-reports/phase3.md) |
| 4 — Tool Implementation | [docs/phases/phase4.md](docs/phases/phase4.md) | [docs/test-reports/phase4.md](docs/test-reports/phase4.md) |
| 5 — Authentication and HTTP Transport | [docs/phases/phase5.md](docs/phases/phase5.md) | [docs/test-reports/phase5.md](docs/test-reports/phase5.md) |
| 6 — Simulator | [docs/phases/phase6.md](docs/phases/phase6.md) | [docs/test-reports/phase6.md](docs/test-reports/phase6.md) |
| 7 — Hardening and Observability | [docs/phases/phase7.md](docs/phases/phase7.md) | [docs/test-reports/phase7.md](docs/test-reports/phase7.md) |
| 8 — Release Preparation | [docs/phases/phase8.md](docs/phases/phase8.md) | [docs/test-reports/phase8.md](docs/test-reports/phase8.md) |

Additional documents: [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md),
[SECURITY_AUDIT.md](SECURITY_AUDIT.md), [VULNERABILITY_FIXES.md](VULNERABILITY_FIXES.md),
[RELEASE.md](RELEASE.md), and [CHANGELOG.md](CHANGELOG.md).

---

Released under the MIT License. See [LICENSE](LICENSE).
