# Changelog

## Phase 6 — Simulator (synthetic security events) (2026-06-06)

### Added
- New standalone `simulator/` package (separate from `sentinel/`):
  - `profiles.py` — 10 employee `Profile`s, two each across Engineering / Finance / Human
    Resources / DevOps / Sales.
  - `events.py` — `login_event` / `file_access_event` / `process_event` / `network_event` /
    `make_alert` factories; every doc tagged `"simulated": True`; randomness via injected
    `random.Random`.
  - `scenarios.py` — five adversarial scenarios (`impossible_travel`, `brute_force`,
    `suspicious_process`, `data_exfiltration`, `known_bad_ip`), each returning `(logs, alert)`
    that share user/host/source_ip so `correlate_alerts` groups them; uses real abuse.ch IOCs.
  - `iocs.py` — `IocProvider.from_abuse_ch()` pulls real FeodoTracker / MalwareBazaar indicators
    via the adapter, with hard-coded fallbacks.
  - `sink.py` — `EventSink` Protocol; `OpenSearchSink` (writes to the logs/alerts indices via the
    adapter) and `InMemorySink` (tests / dry-run).
  - `bots.py` — `NormalBot` (login + file/process per tick) and `AdversarialBot` (one scenario per
    tick, one prompt fire); `tick()`/`run()` with injectable `sleep`/`clock` for deterministic tests.
  - `main.py` — `python -m simulator.main` CLI (`--duration/--seed/--dry-run` + interval flags) and
    `run_simulator()` orchestrator (`asyncio.gather` of both bots).
- `known_c2_ips()` / `known_malware_hashes()` read-only accessors on
  `sentinel/adapters/abuse_ch.py` for the simulator's IOC provider.
- Tests: `tests/unit/test_simulator/` (profiles, iocs, events, scenarios, bots-with-fake-clock,
  sink) + `tests/integration/test_simulator.py` (dry-run orchestration; simulated adversarial
  alerts cluster into one incident via the live `correlate_alerts`). (+31 tests.)

### Changed
- Full suite 447 → **480** passing; total coverage **95.36%** (gate green).
  `simulator/` is clean on ruff and mypy.
- Coverage gate now includes `simulator/` (`[tool.coverage.run] source = ["sentinel", "simulator"]`
  + `--cov=simulator`); simulator modules 100% except `main.py` (CLI) at 97%.

### Fixed (post-report, in-phase)
- `OpenSearchSink` now writes logs to `sentinel-logs-sim` (wildcard substituted, not stripped) so
  it matches the `search_logs` read pattern `sentinel-logs-*`; a test asserts the match via `fnmatch`.
- `simulator/` brought under the coverage gate (see Changed).

### Known gaps
- Live OpenSearch ingestion, `/health`-under-load, and Claude-Desktop `search_logs`/`correlate_alerts`
  over real data are live-run steps, not exercised in CI (all tests use the in-memory sink / mocks).
- The "≥50 logins + concurrent adversarial in 5 min" criterion is proven in parts (single-bot
  virtual clock + tiny-interval orchestration), not in one wall-clock run.
- Carried forward: `enrich_ioc`/`risk_score_user` mock-only and `weekly_summary` live-shape
  mismatch (Phase 4); breaker-vs-5xx (Phase 3); `/mcp` end-to-end + two authz sources drift (Phase 5).

## Phase 5 — Auth (OAuth 2.1 + PKCE) + HTTP Transport (2026-06-06)

### Added
- New `sentinel/auth/` package: `pkce.py` (code_verifier / S256 challenge / state),
  `oauth.py` (`OAuthClient.authorization_url()` + `exchange_code()` against Keycloak),
  `jwt.py` (`JWTValidator` — JWKS fetch, RS256 + issuer + expiry + optional audience, derives a
  `Principal` with `analyst_id = sub`, role by `admin>senior_analyst>analyst` precedence, scopes
  from `scope`), `context.py` (request-scoped `Principal` ContextVar), `authz.py` (scope+role
  gate mirroring `policies/authz.rego`), `dependencies.py` (FastAPI `require_principal`, 401).
- HTTP OAuth endpoints `/auth/login` (PKCE auth URL + verifier + state) and `/auth/token`
  (code+verifier → tokens), plus `/.well-known/oauth-authorization-server` metadata.
- Authenticated REST tool surface `POST /tools/{name}` — 401 (no/invalid token), 403 (missing
  scope or analyst-attempting-write), 404 (unknown tool), 200 (allowed); the audit row is keyed
  on the JWT `sub`.
- Pure-ASGI `McpAuthMiddleware` guarding the `/mcp` streamable transport (401 without a valid
  Bearer; binds the principal otherwise).
- Config: `oauth_client_secret`, `oauth_redirect_uri`, `oauth_audience`, `oauth_default_scopes`,
  and `oidc_issuer/authorize/token/jwks` derived endpoint properties.
- Tests: `tests/unit/test_auth/` (pkce, authz, jwt with respx-mocked JWKS, oauth) +
  `tests/integration/test_auth_http.py` (full OAuth flow, 401/403/404, `analyst_id==sub` in
  audit, `/mcp` 401, manifest) + JWT/key fixtures in `tests/conftest.py`. (+37 tests.)

### Changed
- The MCP manifest (`/.well-known/mcp`) now honestly advertises `oauth2_pkce` with the
  authorize/token endpoints and scopes.
- `run_middleware` attributes each HTTP call to the request-scoped JWT principal
  (`analyst_id = sub`), falling back to the static settings identity on stdio (trusted local).
- Full suite 410 → **447** passing; total coverage 95.06% → **94.96%** (gate green). `auth/`
  package clean on ruff and mypy.

### Known gaps
- The `/mcp` streamable transport is auth-*guarded* (401 without Bearer) but never driven
  end-to-end — the proven authenticated surface is REST `POST /tools/{name}`. Main gap.
- Two authorization sources of truth: `auth/authz.py` (scope+role) vs `policies/authz.rego`
  (role-only) can drift; scope enforcement is REST-only (`/mcp` falls back to OPA role rules).
- JWKS cache has no TTL (refresh only on unknown `kid`); auth runs only against respx-mocked
  Keycloak — no real OIDC realm hit.
- Carried forward: `enrich_ioc`/`risk_score_user` mock-only (Phase 4), `weekly_summary`
  live-shape mismatch (Phase 4), breaker-vs-5xx (Phase 3). See `docs/test-reports/phase5.md`.

## Phase 4 — All 18 Tools (2026-06-06)

### Added
- Implemented the 11 remaining tool stubs: `search_logs`, `correlate_alerts` (entity-overlap
  clustering), `similar_incidents` (field-similarity ranking), `threat_hunt` (indicator timeline),
  `mitre_technique`, `weekly_summary` (OpenSearch aggregation), and `generate_incident_report`
  (orchestrates get_alert + user_context + recent_logins + device_processes + network_connections
  + enrich_ioc + similar_incidents + mitre_technique; optional Anthropic narrative behind
  `REPORT_NARRATIVE_ENABLED`).
- Deterministic 7-event SIEM log corpus in `sentinel/tools/mock_data.py::search_logs`.
- `tests/integration/test_phase4_tools.py` — drives all 14 read tools through `mcp.call_tool`,
  the full write-tool token lifecycle (propose → reject-without-token → execute+audit →
  reject-expired → reject-wrong-tool), and the report orchestration. (+42 tests.)

### Changed
- Read tools now route through their adapters: `get_alert` → OpenSearch; `user_context`/
  `recent_logins` → Keycloak; `device_processes`/`network_connections` → Wazuh; `mitre_technique`
  → MITRE. Write-tool executors call the real Wazuh/Keycloak adapters instead of inline mocks.
- Full suite 368 → **410** passing; total coverage 93.4% → **95.06%** (gate green). Tool packages
  94–100% covered.

### Known gaps
- `enrich_ioc` and `risk_score_user` are still curated-mock composites, not the advertised live
  multi-source adapter fan-out (`MOCK_ADAPTERS=false` does not change them).
- `weekly_summary` consumes a `{total,by_severity,open,closed}` shape only the adapter's *mock*
  branch returns; the live `aggregate_alerts` returns `{raw_aggregations}` — wrong/empty metrics
  on a real backend.
- `generate_incident_report` fans out to ~8 sub-tools serially — slow/rate-limit-prone live.
- Breaker-vs-5xx bug (Phase 3) now sits under every live read tool. All tools mock/respx-verified
  only; no real OpenSearch/Keycloak/Wazuh hit. See `docs/test-reports/phase4.md`.

## Phase 3 — Adapters (2026-06-06)

### Added
- respx-mocked unit tests for all 15 adapters + `BaseAdapter` under
  `tests/unit/test_adapters/` (246 tests; one `test_<adapter>.py` each + `test_base.py`).
- Shared fixtures in `tests/unit/test_adapters/conftest.py`: `_fast_retry` (neutralises
  tenacity/token-bucket backoff) and `live_mode` (flips `MOCK_ADAPTERS=false` to drive the
  real HTTP path against respx).

### Changed
- `sentinel.adapters` package coverage 0% → **100%**; full suite 368/368 passing, total
  coverage ~37.5% → **93.4%** (the `--cov-fail-under=80` gate now passes).
- Fixed ~50 pre-existing lint issues in adapter source; `ruff check` + `ruff format` clean on
  `sentinel/adapters/` and `tests/unit/test_adapters/`. (Tests/lint only — no adapter logic changed.)

### Known gaps
- Circuit breaker only opens on transport errors, not HTTP 5xx/429 (`base.py:132-140`) —
  an up-but-erroring backend is never tripped or retried.
- All adapter verification is respx-mocked; no real OpenSearch/Keycloak/Wazuh/SaaS API hit.
- `mypy sentinel/` still reports 52 errors (31 in adapters); ruff noise remains outside the
  adapter dirs. Deferred to Phase 7. See `docs/test-reports/phase3.md`.

## Phase 2 — MCP Server + Placeholder Tools (2026-06-03)

### Added
- Full MCP protocol wiring: tool (18), resource (4), and prompt (3) registries on FastMCP.
- Three live, mock-backed tools: `get_alert`, `user_context`, `enrich_ioc`.
- Two-step write-confirmation framework (`isolate_device`, `disable_user`, `block_ip`,
  `kill_process`) with Postgres `PendingAction` + in-memory fallback.
- Redis-backed rate limiting in the middleware pipeline (sanitise → policy → rate-limit →
  execute → audit).
- MCP resources (`sentinel://alerts/active`, `.../alerts/{id}`, `.../mitre/{id}`,
  `.../watchlist/ips`) and prompts (`investigate_alert`, `triage_user`, `morning_briefing`).

### Known gaps
- 11 read/report tools are registered but return `not_yet_implemented` (Phase 3/4).
- Rate limiter fails open if Redis is down; in-memory confirmation store is dev-only.
- See `docs/test-reports/phase2.md`.

## Phase 1 — Foundation (2026-06-03)

### Added
- Typed config (`config.py`), `SecretsProvider` abstraction, SQLAlchemy models +
  async session factory, Alembic initial migration.
- OPA policy engine (default-deny), hash-chained audit log (Postgres advisory lock),
  `BaseAdapter` (circuit breaker, retry, OTel spans, structlog).
- FastMCP server instance, middleware pipeline, FastAPI shell with `/health` and
  `/.well-known/mcp`.
- Docker Compose stack (Postgres, Redis, OpenSearch, OPA, Keycloak) + Keycloak realm export.

### Known gaps
- `POLICY_ENFORCEMENT=false` by default disables the OPA gate; manifest advertises
  `oauth2_pkce` before auth exists (Phase 5). See `docs/test-reports/phase1.md`.
