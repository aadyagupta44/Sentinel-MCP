# Phase 2 — Breakage & Risk Report

*Run: 2026-06-06 (retrospective)*  ·  *Scope: cumulative through Phase 2 (MCP protocol, 3 live tools, write framework, resources, prompts, rate limiting)*

## Baseline
- Tests: 131/131 passing at phase close (0 failed).
- Coverage: 85% at phase close. *(Note: the current cumulative suite reads ~38% only because
  Phase 3's adapter code now exists without tests yet — not a Phase 2 regression.)*
- Lint/Type: clean at phase close. Boots: yes (stdio + http).

## Findings
Ordered by severity.

### [SEV: High] Rate limiting silently disables itself if Redis is down
- **Where:** `sentinel/mcp/middleware.py` (rate-limit step, `_get_rate_count` fallback → 0)
- **What breaks:** When Redis is unavailable the counter falls back to 0, so every call is
  "within limit." The protection vanishes exactly when infra is degraded.
- **Repro (hypothesis):** point `REDIS_URL` at a dead port and hammer a tool — no throttling.
- **Impact:** No abuse protection during an outage; fails open, not closed.
- **Suggested fix:** Decide the policy explicitly — fail closed for write tools, or emit a loud
  structured warning + metric and a degraded-mode flag; add a test for the Redis-down path.
- **✅ Resolved:** `_get_rate_count` now returns `-1` when Redis is unavailable; the middleware
  logs `rate_limit_unavailable_redis_down` and **fails closed for write tools**
  (`RATE_LIMIT_UNAVAILABLE`) while degrading-open for reads. Covered by
  `tests/unit/test_mcp/test_middleware.py::TestRateLimitRedisDown`.

### [SEV: High] In-memory confirmation fallback breaks the two-step guarantee
- **Where:** `sentinel/tools/confirmation.py` (`_mem_store` fallback)
- **What breaks:** If Postgres is unavailable, pending-action tokens live in a process-local
  dict. They don't survive a restart and aren't shared across workers — under gunicorn/uvicorn
  with >1 worker, the confirm call can land on a process that never saw the proposal.
- **Impact:** Destructive write tools (`isolate_device`, `disable_user`, `block_ip`,
  `kill_process`) can become unconfirmable, or behave inconsistently, in multi-worker prod.
- **Suggested fix:** Treat the in-memory store as dev-only; require Postgres (or Redis) for the
  pending-action store in non-dev, and log loudly when the fallback engages.
- **✅ Resolved:** `create_proposal` now fails closed in production when Postgres is unavailable
  (returns `STORAGE_UNAVAILABLE` instead of silently using the process-local store), and logs
  loudly (`pending_action_in_memory_fallback`) in dev. Covered by
  `tests/unit/test_tools/test_actions.py::test_production_requires_durable_storage`.

### [SEV: Medium] 11 advertised tools are stubs a user can call
- **Where:** `sentinel/tools/alerts.py`, `intel.py`, `reports.py` (`not_yet_implemented` returns)
- **What breaks:** `search_logs`, `correlate_alerts`, `similar_incidents`, `threat_hunt`,
  `generate_incident_report`, `weekly_summary` (and the unknown-ID path of `mitre_technique`)
  are registered and visible in Claude Desktop but return a stub.
- **Impact:** A user reading the tool list reasonably expects them to work; they don't.
  For a marketplace build this looks unfinished.
- **Suggested fix:** Until Phase 4, either hide stubs from registration behind a flag, or make
  the stub response unmistakably clear ("not available yet — Phase 4") and keep them out of
  the marketing surface.
- **✅ Resolved:** Phase 4 fully implemented all 18 tools (adapter-backed); no
  `not_yet_implemented` stub remains. Verified by `tests/integration/test_phase4_tools.py`.

### [SEV: Medium] "Working" tools only know 3–4 fixtures
- **Where:** `sentinel/tools/mock_data.py`, `enrich_ioc` in `sentinel/tools/intel.py`
- **What breaks:** `get_alert`, `user_context`, `enrich_ioc` succeed only for the seeded IDs
  (e.g. `ALT-2026-001`, the 4 IOCs). Confirm the not-found path returns a clean structured
  error, not an empty/ambiguous object.
- **Impact:** Demos look great, real inputs mostly miss; not-found UX matters.
- **Suggested fix:** Add explicit not-found tests for each live tool; standardise the
  `{"error","code"}` shape.
- **✅ Resolved:** not-found paths return a standardised `{error, code: "NOT_FOUND"}` across
  `get_alert`, `user_context`, `mitre_technique`, `similar_incidents`, and
  `generate_incident_report`, each with explicit unknown-input tests. Tools are now
  adapter-backed (Phase 4), so live mode reads real data rather than the fixtures.

### [SEV: Low] Input validation leans entirely on Pydantic schemas
- **Where:** tool schemas in `sentinel/mcp/schemas.py` / per-tool signatures
- **What breaks:** Beyond type/shape, there's little semantic validation (e.g. email format,
  IP validity, hostname charset). Garbage that's type-correct flows to the (mock) backend.
- **Impact:** Low now (mock), higher when real adapters run queries with these values.
- **Suggested fix:** Add field validators (EmailStr, IP/hostname constraints) before Phase 4
  wires real backends.

## User-facing problems
- **Stub discoverability** (see High/Medium above) is the biggest first-impression issue.
- **Audit verification is manual.** The phase-2 acceptance check ("inspect `audit_log`,
  compare `prev_hash`") requires DB access and SQL. → Ship a tiny `verify-audit` helper or a
  read-only resource so a user can confirm chain integrity without psql.

## Mock-vs-real gaps
Everything that "works" in Phase 2 is mock-backed. None of the 3 live tools, the resources, or
the write actions has touched OpenSearch / Keycloak / Wazuh. The two-step confirmation has only
been exercised against the fixtures + in-memory/test DB. Before release, re-run all of this
against real services with `MOCK_ADAPTERS=false`.

## Summary
MCP wiring is clean and the contract is stable. Top 3 to fix next: **(1)** decide fail-open vs
fail-closed for the rate limiter and confirmation store when Redis/Postgres are down, **(2)**
stop letting stub tools masquerade as working features on the user surface, and **(3)** add
not-found + semantic input validation before real adapters land in Phase 4.
