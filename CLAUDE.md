# sentinel-soc — Complete Handover Document

## Project Overview

**sentinel-soc** is a production-grade SOC (Security Operations Center) MCP Server for Claude Desktop. It bridges Claude with your entire security toolstack — alerts, threat intelligence, identity, and endpoint data — without leaving Claude.

Published to the Claude/Anthropic MCP marketplace — **v1.0.0 is production ready.**

**Current Status:** Phase 8 complete ✅ (all 8 phases finished, 497 tests passing, 90.66% coverage).

---

## What We're Building

An MCP server that exposes **18 security tools** divided into 4 categories:

### Read Tools (7)
- `get_alert(alert_id)` — Retrieve a single alert from OpenSearch
- `search_logs(query, time_window, max_results)` — Search SIEM logs
- `user_context(email)` — User profile, recent logins, risk score from Keycloak
- `recent_logins(email, days)` — Login history with geolocation and MFA
- `risk_score_user(email)` — Computed risk score (0-100) based on behaviors
- `enrich_ioc(indicator)` — Multi-source threat intelligence (7 sources)
- `correlate_alerts(alert_ids, time_window)` — Link related alerts
- `similar_incidents(current_alert, lookback_days)` — Find historical precedents
- `threat_hunt(pattern)` — Search for patterns across endpoint data
- `mitre_technique(technique_id)` — MITRE ATT&CK details
- `device_processes(hostname)` — Running processes on an endpoint
- `network_connections(hostname)` — Active network connections
- `generate_incident_report(alert_id)` — Structured incident report with optional narrative
- `weekly_summary()` — Statistics and trends for the SOC week

### Write Tools (4, two-step confirmation)
- `isolate_device(hostname)` — Quarantine endpoint from network
- `disable_user(email)` — Suspend user account
- `block_ip(ip)` — Add IP to firewall blocklist
- `kill_process(hostname, pid)` — Terminate a running process

### Stub Tools (7, Phase 3/4 implementation)
- `search_logs`, `correlate_alerts`, `similar_incidents`, `threat_hunt`, `mitre_technique`, `generate_incident_report`, `weekly_summary`

### MCP Resources (4)
Ambient context without tool calls:
- `sentinel://alerts/active` — List of active alerts
- `sentinel://alerts/{alert_id}` — Full alert details
- `sentinel://mitre/{technique_id}` — MITRE ATT&CK technique
- `sentinel://watchlist/ips` — Blocked/monitored IPs

### MCP Prompts (3)
Reusable investigation playbooks:
- `investigate_alert` — Step-by-step incident investigation
- `triage_user` — User risk assessment
- `morning_briefing` — Daily SOC standup

---

## Architecture

### High-Level Flow
```
Claude Desktop
    ↓
MCP Server (FastMCP)
    ├── Tools (18, with input/output schemas)
    ├── Resources (4, URI-based)
    └── Prompts (3, playbook instructions)
         ↓
Adapter Layer (14 adapters)
    ├── No-auth: abuse.ch, CIRCL, ip-api, InternetDB, DNSBL
    ├── Optional: AlienVault OTX, AbuseIPDB, VirusTotal, URLScan
    ├── Services: OpenSearch, Keycloak, Wazuh, OpenCTI, Anthropic
    └── Mock mode (for testing, no external accounts)
         ↓
External Backends
    ├── OpenSearch (SIEM logs, alerts) — self-hosted, Apache 2.0
    ├── Keycloak (identity, login events) — self-hosted, free
    ├── Wazuh (EDR, process events) — self-hosted, free
    ├── Free services (abuse.ch, ip-api, CIRCL)
    └── Optional APIs (VirusTotal, AbuseIPDB, OTX, URLScan)
```

### Key Components

**sentinel/adapters/** — 14 REST API adapters
- `base.py` — BaseAdapter with circuit breaker, retry, OTel spans, mock support
- `opensearch.py` — Alert + log search
- `abuse_ch.py` — Malicious IP/hash/URL feeds (in-memory, no auth)
- `mitre.py` — MITRE ATT&CK (local STIX bundle)
- `internetdb.py` — Shodan InternetDB (open ports, CVEs)
- `ipapi.py` — IP geolocation
- `circl.py` — Hash reputation (CIRCL Luxembourg)
- `dnsbl.py` — DNS blocklists (Spamhaus ZEN)
- `alienvault.py` — AlienVault OTX (optional)
- `abuseipdb.py` — IP abuse scores (optional)
- `virustotal.py` — Malware analysis (optional, rate-limited)
- `urlscan.py` — URL analysis (optional)
- `wazuh.py` — EDR (optional, resource-heavy)
- `keycloak.py` — Identity provider
- `anthropic_adapter.py` — Report narrative generation (optional)
- `opencti.py` — Structured TI platform (optional)

**sentinel/tools/** — 18 MCP tools
- `alerts.py` — get_alert, search_logs, correlate_alerts, similar_incidents
- `identity.py` — user_context, recent_logins, risk_score_user
- `intel.py` — enrich_ioc, threat_hunt, mitre_technique
- `endpoint.py` — device_processes, network_connections
- `reports.py` — generate_incident_report, weekly_summary
- `actions.py` — isolate_device, disable_user, block_ip, kill_process (two-step)
- `mock_data.py` — Deterministic test data (3 employees, 3 alerts, 4 IOCs)
- `confirmation.py` — Two-step write confirmation framework (Postgres + in-memory fallback)

**sentinel/mcp/** — MCP protocol
- `resources.py` — 4 Resources (sentinel:// URIs)
- `prompts.py` — 3 Prompts (playbooks)

**sentinel/core/** — Foundation (Phase 1)
- `config.py` — Settings from .env
- `db/models.py` — Postgres models (users, alerts, audit log, pending actions, cache)
- `audit.py` — Immutable audit log (hash-chained with advisory locks)
- `opa.py` — OPA sidecar for policy enforcement (default-deny)
- `rate_limit.py` — Redis-backed rate limiting

**sentinel/main.py** — FastMCP server entry point
- Wires all tools, resources, prompts
- Middleware pipeline: policy check → rate limit → execute → audit

### Design Decisions (All Locked)

| Decision | Why |
|----------|-----|
| **OpenSearch** not Elasticsearch | Apache 2.0 license (vs. SSPL). Same API. |
| **Keycloak** not Okta | Self-hosted, free, pre-configured realm export. |
| **No Anthropic API at runtime** | Tools return structured data. Claude synthesizes narratives naturally. Optional via `REPORT_NARRATIVE_ENABLED=true`. |
| **Stateful write confirmation** | Postgres PendingAction table (TTL-based). In-memory fallback for dev/test. Token-based, tamper-proof. |
| **OPA sidecar** | Default-deny policy enforcement. REST API. Docker service. |
| **Redis rate limiting** | Counters keyed by tool+user. Limits defined in OPA policies. |
| **Postgres advisory locks** | Hash-chained audit log. Concurrent writes serialized. |
| **Mock adapters by default** | Zero external accounts for quickstart. `MOCK_ADAPTERS=true` env var. |
| **Shodan InternetDB** not paid Shodan | Free, no-auth REST API. Provides ports, CVEs, tags. |
| **VirusTotal/AbuseIPDB/OTX optional** | Free tier, email signup, graceful degradation if absent. |

---

## Tech Stack

### Core
- **Python 3.11+** — async/await, Pydantic, structlog
- **FastMCP** — MCP server framework (@mcp.tool decorator pattern)
- **asyncio** — Concurrent request handling
- **httpx** — Async HTTP client (all adapters use this)

### Data
- **PostgreSQL** — Users, alerts, audit log, pending actions, threat intel cache
- **Redis** — Rate limiting counters (dev: in-memory fallback)
- **OpenSearch** — SIEM logs and alerts (Apache 2.0)

### Identity & Policy
- **Keycloak** — OAuth 2.0/OIDC identity provider (self-hosted)
- **OPA (Open Policy Agent)** — Declarative security policies (sidecar, REST API)

### Observability
- **OpenTelemetry** — Distributed tracing (otel spans on every adapter call)
- **structlog** — Structured logging (JSON output)

### Testing
- **pytest** — Unit + integration tests
- **respx** — HTTP mocking (httpx-based)
- **unittest.mock** — For config, adapters
- **coverage** — Target 80%+ coverage

### DevOps
- **Docker Compose** — PostgreSQL, Redis, OpenSearch, OPA, Keycloak, optional Wazuh
- **uv** — Python package manager (reproducible, fast)
- **Git** — Version control

### Optional External APIs
- **VirusTotal** (optional) — Malware analysis, rate-limited token bucket
- **AbuseIPDB** (optional) — IP abuse scores
- **AlienVault OTX** (optional) — Threat pulses, malware families
- **URLScan.io** (optional) — URL analysis
- **Anthropic API** (optional) — Narrative generation for reports

---

## Project Structure

```
sentinel-soc/
├── sentinel/
│   ├── main.py                      # FastMCP server entry
│   ├── config.py                    # Settings from .env
│   ├── db/
│   │   ├── models.py                # SQLAlchemy models
│   │   ├── session.py               # DB session factory
│   │   └── migrations/              # Alembic migrations
│   ├── core/
│   │   ├── audit.py                 # Immutable audit log
│   │   ├── opa.py                   # OPA policy enforcement
│   │   └── rate_limit.py            # Redis rate limiter
│   ├── adapters/
│   │   ├── base.py                  # BaseAdapter (circuit breaker, retry, OTel)
│   │   ├── opensearch.py            # SIEM
│   │   ├── keycloak.py              # Identity
│   │   ├── abuse_ch.py              # Threat feeds (no-auth)
│   │   ├── mitre.py                 # ATT&CK (local)
│   │   ├── internetdb.py            # Shodan InternetDB
│   │   ├── ipapi.py                 # Geolocation
│   │   ├── circl.py                 # Hash reputation
│   │   ├── dnsbl.py                 # DNS blocklists
│   │   ├── alienvault.py            # OTX (optional)
│   │   ├── abuseipdb.py             # IP scores (optional)
│   │   ├── virustotal.py            # Malware analysis (optional)
│   │   ├── urlscan.py               # URL analysis (optional)
│   │   ├── wazuh.py                 # EDR (optional)
│   │   ├── anthropic_adapter.py     # Report narratives (optional)
│   │   └── opencti.py               # Structured TI (optional)
│   ├── tools/
│   │   ├── alerts.py                # get_alert, search_logs, ...
│   │   ├── identity.py              # user_context, recent_logins, ...
│   │   ├── intel.py                 # enrich_ioc, ...
│   │   ├── endpoint.py              # device_processes, ...
│   │   ├── reports.py               # generate_incident_report, ...
│   │   ├── actions.py               # isolate_device, disable_user, ...
│   │   ├── schemas.py               # Pydantic models
│   │   ├── mock_data.py             # Test data factory
│   │   └── confirmation.py          # Two-step confirmation
│   └── mcp/
│       ├── resources.py             # sentinel:// Resources
│       └── prompts.py               # Investigation playbooks
├── tests/
│   ├── unit/
│   │   └── test_tools/              # Tool tests with mock adapters
│   └── integration/
│       └── test_mcp_protocol.py     # MCP compliance tests
├── .claude/
│   ├── skills/
│   │   ├── phase-docs/SKILL.md       # Skill: write phase journey doc + update README
│   │   └── phase-test/SKILL.md       # Skill: find where the code breaks / user-facing problems
│   └── agents/
│       └── phase-runner.md           # Orchestrator: runs both skills after a phase completes
├── docker-compose.yml               # Full stack (Postgres, Redis, OpenSearch, OPA, Keycloak)
├── pyproject.toml                   # Dependencies + project metadata
├── .env.example                     # Template for env vars
└── CLAUDE.md                        # This file
```

---

## Phase Breakdown (8 Phases Total)

### Phase 1: Foundation ✅ Complete
**Deliverables:** Config, DB, audit log, OPA, rate limiting, base adapter, FastAPI shell, Docker.
- SQLAlchemy ORM models (users, alerts, audit_log, pending_actions, threat_intel_cache)
- Postgres schema + Alembic migrations
- Immutable audit log with hash chaining (SHA-256)
- OPA sidecar for policy enforcement (default-deny)
- Redis rate limiter (token bucket per tool+user)
- BaseAdapter with circuit breaker, retry (exponential backoff), OTel spans
- pytest setup with respx mocks
- Docker Compose for Postgres, Redis, OpenSearch, OPA, Keycloak
- 62 unit tests, 82% coverage

**Key Files:** `sentinel/config.py`, `sentinel/db/models.py`, `sentinel/core/audit.py`, `sentinel/core/opa.py`, `sentinel/adapters/base.py`

### Phase 2: MCP Server + Tools ✅ Complete
**Deliverables:** All 18 tools, Resources, Prompts, 131 tests, 85% coverage.
- 3 fully working tools: `get_alert` (OpenSearch), `user_context` (Keycloak), `enrich_ioc` (7 sources)
- 4 write tools with two-step confirmation: `isolate_device`, `disable_user`, `block_ip`, `kill_process`
- 11 stubs for Phase 3/4 implementation
- Mock data factory (3 employees, 3 alerts, 4 IOCs) for deterministic testing
- Confirmation framework with Postgres PendingAction + in-memory fallback
- 4 MCP Resources (sentinel:// URIs)
- 3 MCP Prompts (investigation playbooks)
- 131 unit + integration tests, 85% coverage

**Key Files:** `sentinel/tools/`, `sentinel/mcp/`, `sentinel/tools/mock_data.py`, `sentinel/tools/confirmation.py`

### Phase 3: Adapters (In Progress)
**Deliverables:** All 14 adapters with unit tests (respx mocks).

#### Batch 1: Core Adapters (Complete)
- `opensearch.py` — Alert retrieval, log search, aggregation
- `abuse_ch.py` — Malicious IP/hash/URL feeds (in-memory, no auth)
- `mitre.py` — MITRE ATT&CK (local STIX bundle or fallback)

#### Batch 2: No-Auth Adapters (Complete)
- `internetdb.py` — Shodan InternetDB (open ports, CVEs) with cache
- `ipapi.py` — IP geolocation (HTTP, not HTTPS for free tier)
- `circl.py` — Hash reputation lookup (Luxembourg CERT)
- `dnsbl.py` — DNS blocklists (Spamhaus ZEN, socket-based)

#### Batch 3: Optional Adapters (Complete)
- `alienvault.py` — AlienVault OTX (optional, graceful degradation)
- `abuseipdb.py` — IP abuse scores (optional, rate-limited)
- `virustotal.py` — Malware analysis (optional, token bucket 4 req/min)
- `urlscan.py` — URL analysis (optional, scan + search + get_result)

#### Batch 4: Service Adapters (Complete)
- `wazuh.py` — EDR (process, network events, isolation, kill)
- `keycloak.py` — Identity (user profiles, login events, suspend)
- `anthropic_adapter.py` — Report narratives (optional, JSON output)
- `opencti.py` — Structured TI (optional, GraphQL API)

**Next:** Write unit tests for all adapters using respx mocks. Run full test suite. Generate Phase 3 docs.

**Test Pattern:**
```python
@pytest.mark.asyncio
async def test_adapter_lookup(respx_mock):
    respx_mock.get("https://api.example.com/lookup/...").mock(return_value=Response(200, json={...}))
    adapter = get_adapter()
    result = await adapter.lookup("...")
    assert result["key"] == "value"
```

### Phase 4: Implement Read Tools ← Next after Phase 3
**Deliverables:** All 11 stubbed tools → fully working.
- `search_logs` — Query OpenSearch with parameterised Lucene DSL
- `correlate_alerts` — Link alerts by entity (IP, user, hostname)
- `similar_incidents` — Historical precedent search
- `threat_hunt` — Pattern search across Wazuh logs
- `mitre_technique` — Lookup technique by ID + list all
- `device_processes` → Wazuh (already working)
- `network_connections` → Wazuh (already working)
- `generate_incident_report` — Structured output + optional Anthropic narrative
- `weekly_summary` — OpenSearch aggregations + optional narrative
- Unit tests for each (respx mocks)
- Coverage target: 85%+

### Phase 5: Auth + HTTP Transport
**Deliverables:** OAuth 2.1 + PKCE on Keycloak, HTTP transport for Claude Desktop.
- OAuth 2.1 client credentials flow (Keycloak)
- PKCE for public clients (if Claude Desktop is used as client)
- Bearer token authentication on all tool calls
- Rate limiting per user (not global)
- Token refresh logic
- MCP over HTTP (Claude Desktop uses stdio by default, but HTTP for remote)

### Phase 6: Simulator
**Deliverables:** Generates synthetic security events for testing.
- Normal bot behavior (benign users, routine logins, expected processes)
- Adversarial scenarios (credential stuffing, lateral movement, data exfiltration)
- Writes to OpenSearch (index_document in opensearch.py)
- Used to test alert detection, correlation, and reporting
- Scheduled tasks (cron-like)

### Phase 7: Hardening
**Deliverables:** Production-ready security + observability.
- Input sanitization (parameterised queries, no template injection)
- Full OpenTelemetry instrumentation (traces, metrics, logs)
- structlog everywhere (JSON structured logging)
- Secrets rotation (API keys, tokens)
- CORS + CSP headers
- Rate limit error messages (no sensitive info leakage)
- Comprehensive documentation (README, phase docs, API docs)
- Security audit (OWASP top 10, dependency scanning)

### Phase 8: Marketplace Prep
**Deliverables:** Production release (v1.0.0).
- Final checklist (all tests pass, coverage 85%+, docs complete)
- Git tag v1.0.0
- Publish to Claude/Anthropic MCP marketplace
- Package as standalone binary (PyInstaller or uv-based distribution)

---

## How to Continue on a New Machine

### 1. Clone & Setup
```bash
git clone <repo-url> sentinel-soc
cd sentinel-soc

# Install uv (Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh
# (or on Windows: use installer from https://github.com/astral-sh/uv/releases)

# Install Python 3.11+ via uv
uv python install 3.11

# Create and activate venv
uv venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows

# Install dependencies (dev + test groups)
uv sync --group dev
```

### 2. Set Up Environment
```bash
cp .env.example .env
# Edit .env with your settings (or use defaults for mock mode)
```

### 3. Start Services (Docker)
```bash
docker-compose up -d
# Postgres, Redis, OpenSearch, OPA, Keycloak will be running
```

### 4. Run Tests
```bash
# Full test suite (131 tests expected to pass)
pytest -xvs

# With coverage
pytest --cov=sentinel --cov-report=html

# Only unit tests
pytest tests/unit/ -xvs

# Only integration tests
pytest tests/integration/ -xvs

# Specific tool test
pytest tests/unit/test_tools/test_alerts.py -xvs
```

### 5. After a Phase Completes — Run the Phase Workflow
After finishing a development phase, run the **phase-runner** orchestrator agent
(or invoke the two skills directly). It runs:

1. **`/phase-test`** — analyses everything built so far for where the code can
   break and what problems a user might hit; writes a findings report to
   `docs/test-reports/phaseN.md`.
2. **`/phase-docs`** — writes the phase journey (what was built, how, architecture,
   key decisions) to `docs/phases/phaseN.md` and updates `README.md` + `CHANGELOG.md`.

These replace the old `scripts/testing_agent.py` and `scripts/doc_agent.py`
(both removed). The skills live in `.claude/skills/`, the orchestrator in
`.claude/agents/phase-runner.md`.

### 7. Start MCP Server (for Claude Desktop)
```bash
# Development mode (hot-reload)
python -m sentinel.main

# Or as daemon
python -m sentinel.main &
```

### 8. Connect to Claude Desktop
Edit `~/.claude/claude.desktop/mcp-servers.json`:
```json
{
  "sentinel": {
    "command": "python",
    "args": ["-m", "sentinel.main"],
    "cwd": "/path/to/sentinel-soc"
  }
}
```

Restart Claude Desktop. Tools should appear in the MCP browser.

---

## Key Commands to Know

### Development
```bash
# Format code
black sentinel/ tests/

# Type checking
mypy sentinel/

# Lint
ruff check sentinel/ tests/

# Run tests with output
pytest -xvs tests/unit/test_tools/test_alerts.py

# Test coverage
pytest --cov=sentinel --cov-report=term-missing

# Drop into debugger on failure
pytest --pdb -xvs
```

### Database
```bash
# Apply migrations
alembic upgrade head

# Create new migration (after model change)
alembic revision --autogenerate -m "Add new column"

# Rollback one migration
alembic downgrade -1
```

### Docker
```bash
# View logs
docker-compose logs -f opensearch
docker-compose logs -f keycloak

# Stop all services
docker-compose down

# Stop and remove data
docker-compose down -v

# Restart a service
docker-compose restart postgresql
```

---

## Current Progress Summary

| Phase | Status | Tests | Coverage | Key Deliverable |
|-------|--------|-------|----------|-----------------|
| 1 | ✅ Complete | 62 | 82% | Config, DB, audit, OPA, base adapter |
| 2 | ✅ Complete | 131 | 85% | 18 tools, Resources, Prompts, mock data |
| 3 | ✅ Complete | 176 | 89% | 14 adapters, all unit tests passing |
| 4 | ✅ Complete | 263 | 91% | Stubbed read tools → fully working |
| 5 | ✅ Complete | 347 | 92% | OAuth 2.1 + PKCE auth, rate limiting |
| 6 | ✅ Complete | 420 | 93% | Simulator, synthetic events, chaos tests |
| 7 | ✅ Complete | 440 | 90.66% | Hardening, code quality, security audit |
| 8 | ✅ Complete | 497 | 90.66% | **v1.0.0 PRODUCTION RELEASE** |

---

## Next Immediate Steps

1. **Write unit tests for all 14 adapters** (respx mocks)
   - Test happy path, errors, circuit breaker, rate limiting
   - Mock mode tests (no external deps)
   - ~100 tests expected

2. **Run full test suite** to verify Phase 3 completion
   - Target: 231+ tests passing (62 + 131 + 100)
   - Target: 85%+ coverage

3. **Run the `phase-runner` agent for Phase 3**
   - `/phase-test` — find breakages / user-facing problems → `docs/test-reports/phase3.md`
   - `/phase-docs` — write `docs/phases/phase3.md`, update README.md + CHANGELOG.md

5. **Start Phase 4** (implement stubbed read tools)

---

## Important Notes

- **Mock mode default:** `MOCK_ADAPTERS=true`. Tools work without external services.
- **Optional APIs:** VirusTotal, AbuseIPDB, OTX, URLScan, Wazuh, Anthropic are gracefully degraded if keys not set.
- **Keycloak realm:** Pre-configured at `sentinel/migrations/keycloak-realm-export.json`.
- **OPA policies:** Located in `sentinel/core/opa_policies/`. Edit via OPA REST API or reload on startup.
- **Audit log:** Immutable, hash-chained. Every write to sensitive tables is logged.
- **Two-step confirmation:** Pending actions stored in Postgres, TTL 10 minutes. Tokens are 32-char URL-safe random.
- **Rate limiting:** Per tool+user, defined in OPA. Defaults: 100 calls/hour per user.

---

## Questions?

Refer to:
- `sentinel/config.py` for all env vars
- `docs/phases/phase*.md` for phase-specific details
- `README.md` for quickstart (links to full docs in Phase 7)
- Adapter docstrings for API details
- Test files for usage examples

Good luck!
