# Sentinel MCP

Sentinel MCP is a Model Context Protocol (MCP) server that gives Claude secure,
policy-enforced, audited access to a Security Operations Center (SOC) toolstack.
It exposes SIEM alerts, multi-source threat intelligence, identity and login
data, and endpoint telemetry as MCP tools, resources, and prompts, so an analyst
can investigate incidents and take containment actions through Claude Desktop
without switching between consoles.

The server is written in Python (3.12+) on the official Anthropic MCP SDK
(FastMCP), runs over both the stdio and HTTP transports, and is designed to run
with no external accounts in a built-in mock mode for evaluation, or against
real backends in production.

## Overview

A SOC analyst's workflow normally spans several systems: a SIEM for alerts and
logs, threat-intelligence services for indicator reputation, an identity
provider for user and login context, and an endpoint detection and response
(EDR) platform for process and network activity. Sentinel MCP consolidates these
behind a single MCP interface. Through Claude an analyst can retrieve an alert,
enrich its indicators, review the affected user's recent logins, inspect the
processes and connections on the affected host, correlate related alerts into an
incident, and — with explicit two-step confirmation — isolate a device, disable
an account, block an address, or terminate a process. Every action is checked
against an authorization policy and recorded in a tamper-evident audit log.

## Capabilities

### Tools

Eighteen tools are exposed: fourteen read (investigation) tools and four write
(containment) tools. Write tools require a two-step confirmation before any
change is made.

Read tools:

| Tool | Purpose |
|------|---------|
| `get_alert` | Retrieve a single alert with full context (severity, affected user/host, MITRE techniques, raw log references). |
| `search_logs` | Full-text search across SIEM logs within a time window. |
| `correlate_alerts` | Group related alerts into incident clusters by shared user, host, source IP, or MITRE technique. |
| `similar_incidents` | Rank historically similar incidents by field similarity. |
| `enrich_ioc` | Produce a composite reputation verdict for an IP, domain, hash, or URL across multiple intelligence sources. |
| `threat_hunt` | Search the full log archive for every occurrence of an indicator and build a timeline. |
| `mitre_technique` | Look up a MITRE ATT&CK technique (name, tactic, detection, mitigation). |
| `user_context` | Return an identity profile: groups, MFA status, registered devices, account status. |
| `recent_logins` | Return login history with source IP, country, device, and MFA method. |
| `risk_score_user` | Compute a 0–100 user risk score with a factor breakdown. |
| `device_processes` | List process-creation events on a host, flagging suspicious processes. |
| `network_connections` | List network connections on a host, flagging known-malicious destinations. |
| `generate_incident_report` | Orchestrate the read tools into a structured incident report. |
| `weekly_summary` | Aggregate alert statistics and trends for the past seven days. |

Write tools (two-step confirmation):

| Tool | Action |
|------|--------|
| `isolate_device` | Network-isolate a host via the EDR platform. |
| `disable_user` | Suspend a user account in the identity provider. |
| `block_ip` | Add an IP address to the block list. |
| `kill_process` | Terminate a process on a host via EDR active response. |

### Resources

Four read-only resources provide ambient context without an explicit tool call:
`sentinel://alerts/active`, `sentinel://alerts/{alert_id}`,
`sentinel://mitre/{technique_id}`, and `sentinel://watchlist/ips`.

### Prompts

Three reusable investigation playbooks are provided: `investigate_alert`,
`triage_user`, and `morning_briefing`.

## Architecture

```
Claude Desktop
  | (MCP: stdio or HTTP)
  v
Sentinel MCP server (FastMCP)
  - Tools (18), Resources (4), Prompts (3)
  - Middleware pipeline per call:
      authorization (scope + role) -> OPA policy -> rate limit -> execute -> audit
  v
Adapter layer (BaseAdapter: circuit breaker, retry, OpenTelemetry spans)
  v
Backends
  - OpenSearch (SIEM), Keycloak (identity), Wazuh (EDR)
  - Threat intel: abuse.ch, Shodan InternetDB, ip-api, CIRCL, Spamhaus DNSBL,
    and optional VirusTotal, AbuseIPDB, AlienVault OTX, URLScan, OpenCTI
```

Key components:

- `sentinel/main.py` — application entry point. In stdio mode it runs the MCP
  protocol directly; in HTTP mode it serves a FastAPI application that mounts the
  MCP streamable-HTTP transport at `/mcp`, exposes an authenticated REST tool
  surface at `/tools/{name}`, and publishes a health endpoint and discovery
  manifests.
- `sentinel/mcp/` — the FastMCP server instance, the middleware pipeline, and the
  resource and prompt definitions.
- `sentinel/tools/` — the eighteen tool implementations, the two-step
  confirmation framework, and a deterministic mock-data factory used in mock mode.
- `sentinel/adapters/` — fifteen service adapters built on a common
  `BaseAdapter` that provides a circuit breaker, retry with exponential backoff,
  OpenTelemetry spans, structured logging, and a mock-mode hook.
- `sentinel/auth/` — OAuth 2.1 + PKCE flow, RS256 JWT validation against the
  Keycloak JWKS, and scope/role authorization.
- `sentinel/policy/` — the Open Policy Agent (OPA) client used as a
  defence-in-depth authorization check.
- `sentinel/audit/` — the immutable, hash-chained audit log.
- `sentinel/config.py` — typed settings loaded from the environment.

## Security model

- **Authentication.** The HTTP transport uses OAuth 2.1 with PKCE against
  Keycloak. Every tool call requires a valid RS256 Bearer token; the analyst
  identity is taken from the JWT `sub` claim. The stdio transport is intended for
  a trusted local process (for example, a local Claude Desktop launch) and uses a
  static configured identity.
- **Authorization.** A scope-and-role check (`soc:read` for read tools,
  `soc:write` plus a `senior_analyst` or `admin` role for write tools) is enforced
  in the middleware on every transport, with OPA as an additional policy layer.
- **Two-step confirmation.** Write tools first return a proposed action and a
  time-limited token; the action executes only on a second call with that token.
  Pending actions are persisted in PostgreSQL; the server fails closed rather than
  using a non-durable store in production.
- **Rate limiting.** A Redis-backed sliding window enforces per-tool, per-analyst
  limits defined in OPA policy. If Redis is unavailable the server fails closed
  for write tools and degrades open for read tools, with a warning.
- **Audit log.** Every call (allowed or denied) is written to an append-only,
  SHA-256 hash-chained log, serialized with PostgreSQL advisory locks. Sensitive
  inputs and personally identifiable information are redacted before logging.
- **Hardening.** The HTTP application sets standard security headers
  (Content-Security-Policy, HSTS, X-Frame-Options, and others), enforces a request
  body size limit, restricts CORS to an explicit allowlist, and validates that the
  runtime configuration is safe for the target environment at startup.

A security audit and the resulting fixes are documented in
[SECURITY_AUDIT.md](SECURITY_AUDIT.md) and [VULNERABILITY_FIXES.md](VULNERABILITY_FIXES.md);
the responsible-disclosure policy is in [SECURITY.md](SECURITY.md).

## Transports

- **stdio** (default) — the MCP protocol runs directly over standard input/output;
  this is the transport Claude Desktop uses for a local server.
- **HTTP** — a FastAPI application exposes the MCP streamable-HTTP transport at
  `/mcp` (Bearer-authenticated), an authenticated REST tool surface at
  `/tools/{name}`, a `/health` endpoint, and discovery manifests at
  `/.well-known/mcp` and `/.well-known/oauth-authorization-server`.

## Installation

Requirements: Python 3.12 or later and the [uv](https://github.com/astral-sh/uv)
package manager. PostgreSQL, Redis, OPA, Keycloak, and OpenSearch are required
only for full (non-mock) operation and are provided by the included Docker
Compose stack.

```bash
git clone <repository-url> sentinel-soc
cd sentinel-soc

uv sync --group dev          # install dependencies (with dev/test tools)
cp .env.example .env         # create configuration (defaults run in mock mode)
```

By default the server starts in mock mode (`MOCK_ADAPTERS=true`), which requires
no external services and serves deterministic synthetic data, making it suitable
for evaluation and testing.

### Running

```bash
# stdio transport (default)
uv run python -m sentinel.main

# full backend stack for HTTP / non-mock operation
docker compose up -d
```

### Connecting to Claude Desktop

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

## Configuration

All configuration is supplied through environment variables (see
`.env.example` and `sentinel/config.py`). Notable settings include
`MCP_TRANSPORT` (`stdio` or `http`), `MOCK_ADAPTERS`, `POLICY_ENFORCEMENT`, the
`DATABASE_URL`, `REDIS_URL`, `OPA_URL`, `KEYCLOAK_URL`, and `OPENSEARCH_URL`
connection settings, and optional API keys for VirusTotal, AbuseIPDB, AlienVault
OTX, URLScan, OpenCTI, and the Anthropic API. Optional integrations degrade
gracefully when their keys are absent. The server refuses to start in a
production environment with an unsafe configuration (for example, authorization
disabled, mock mode enabled, or placeholder connection URLs).

## Traffic simulator

The `simulator/` package generates synthetic security events for demonstrations
and testing. It models ten employee profiles across five departments, emits
realistic login, file-access, and process events ("normal" bots), and
periodically fires one of five adversarial scenarios — impossible travel, brute
force, suspicious process, data exfiltration, and known-bad-IP beaconing — using
real abuse.ch indicators. Events are written to OpenSearch (or any sink) so the
Sentinel tools can investigate them.

```bash
uv run python -m simulator.main --duration 300            # write to OpenSearch
uv run python -m simulator.main --duration 60 --dry-run   # in-memory, no writes
```

## Testing and quality

```bash
uv run pytest                         # full test suite with coverage
uv run ruff check sentinel/ tests/    # linting
uv run mypy sentinel/                 # type checking
```

The project has 497 automated tests (unit and integration) at approximately 95
percent line coverage, against a configured minimum of 80 percent. Adapters are
tested with respx-mocked HTTP and the authentication flow with mocked Keycloak
endpoints, so the suite runs with no external services. Continuous integration
runs linting, type checking, the test suite, and a Docker image build.

## Project status

Version 1.0.0. All eight planned development phases are complete: foundation; MCP
server and tools; adapters; tool implementation; authentication and HTTP
transport; the traffic simulator; hardening and observability; and release
preparation.

Known limitations: `enrich_ioc` and `risk_score_user` currently return curated
composite results from the mock-data factory rather than composing the live
source adapters; their live multi-source implementation is planned for a future
release. All tools are functional and tested in mock mode, and the remaining
read tools are adapter-backed (serving deterministic data in mock mode and live
data when configured against real backends).

## Documentation

Each development phase has a technical journey document and a breakage/risk
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

Released under the MIT License. See [LICENSE](LICENSE).
