# Phase 4 — Breakage & Risk Report

*Run: 2026-06-06*  ·  *Scope: cumulative through Phase 4 (all 18 MCP tools now adapter-backed)*

## Baseline
- Tests: 410/410 passing (0 failed). +42 vs Phase 3 (368); the new file is
  `tests/integration/test_phase4_tools.py` (drives all 14 read tools + the write-tool
  token lifecycle + report orchestration through `mcp.call_tool`).
- Coverage: 95.06% (`--cov-fail-under=80` gate **green**, up from 93.40%).
  - Tool package strong: `tools/alerts.py` 100%, `tools/intel.py` 100%, `tools/endpoint.py`
    100%, `tools/actions.py` 98%, `tools/mock_data.py` 96%, `tools/reports.py` 94%,
    `tools/identity.py` 94%, `tools/confirmation.py` 89%.
  - Low-coverage modules are all pre-Phase-4 infra: `audit/log.py` 48%, `db/session.py` 65%,
    `mcp/middleware.py` 72%, `main.py` 75%, `mcp/resources.py` 82%, `policy/engine.py` 82%.
- Lint: `sentinel/tools/` + `sentinel/adapters/` + `tests/integration/test_phase4_tools.py`
  **clean** (`ruff check`). Elsewhere: `ruff check sentinel/` = 11 issues (all in
  `audit/`, `mcp/`, `main.py` — pre-existing, outside Phase 4 scope), `ruff check tests/` =
  40 issues (pre-existing in the non-Phase-4 test dirs: unused imports, E501 long lines,
  E741 ambiguous `l`, etc.).
- Type: `mypy sentinel/` = 55 errors across 20 files (was 52 in Phase 3). The +3 net is
  in the tool layer the phase touched: `tools/intel.py` 5, `tools/alerts.py` 5,
  `tools/actions.py` 4, `tools/identity.py` 3, `tools/reports.py` 2, `tools/endpoint.py` 2 —
  all the same `resp.json()`/dict → `Any` `no-any-return` class plus one `unused-ignore` in
  `main.py`. Deferred to Phase 7 (hardening) per plan.
- Boots: yes — `uv run python -c "import sentinel.main"` → `BOOTS_OK`.

## Findings
Ordered by severity.

### [SEV: High] `weekly_summary` consumes a shape the live OpenSearch path never returns
- **Where:** `sentinel/tools/reports.py:175,192-194` vs `sentinel/adapters/opensearch.py:131-164`
- **What breaks:** `_execute_weekly_summary` reads `stats.get("total")`, `stats.get("by_severity")`,
  `stats.get("open")`, `stats.get("closed")`. The adapter's **mock** branch returns exactly those
  keys (`opensearch.py:136-142`), but the **live** branch returns `{"raw_aggregations": <raw OS
  agg buckets>}` (`opensearch.py:159-160`) — none of the consumed keys exist. Against a real
  OpenSearch, `weekly_summary` silently degrades: `total` falls back to the alert-list length,
  `by_severity` is `{}`, and `open`/`closed` come back `None`. The summary looks fine but the
  severity/open/closed numbers are wrong/empty.
- **Repro:** Reasoned from source; mock vs live key sets diverge. Mock-mode tests can't catch it
  because they only exercise the matching-key branch.
- **Impact:** Wrong management/shift-handover metrics the first time someone points at a real
  backend. Quiet-wrong is worse than a crash here.
- **Suggested fix:** Make the live `aggregate_alerts` branch parse the OS agg buckets into the
  same `{total, by_severity, open, closed}` contract the mock returns (and add a test asserting
  both branches return the same shape).
- **✅ Resolved:** the live `aggregate_alerts` branch now normalises the OS agg buckets via
  `_parse_aggregations` into the same `{total, by_severity, open, closed}` contract the mock
  returns (`track_total_hits` added for an accurate `total`). Covered by
  `tests/unit/test_adapters/test_opensearch.py::...test_aggregate_alerts_success_returns_weekly_contract`.

### [SEV: High] `enrich_ioc` / `risk_score_user` are still curated-mock composites, not live adapter fan-out
- **Where:** `sentinel/tools/intel.py:33` (`return mock.enrich_ioc(...)`),
  `sentinel/tools/identity.py:99` (`return mock.risk_score(...)`)
- **What breaks:** The `enrich_ioc` docstring (`intel.py:42-52`) advertises a live fan-out to
  abuse.ch / InternetDB / ip-api / CIRCL / DNSBL (+ optional VT/AbuseIPDB/OTX/URLScan), but the
  executor returns a hand-curated composite from `mock_data`. The individual source adapters were
  built and tested in Phase 3, but nothing composes them here. `risk_score_user` is likewise a
  mock computation, not derived from `recent_logins`/`device_processes`. Setting
  `MOCK_ADAPTERS=false` does **not** change these two tools' behavior.
- **Repro:** Source-confirmed: neither executor calls any adapter; both call `mock_data` directly.
- **Impact:** The two TI/risk tools a SOC analyst leans on hardest return canned data regardless of
  mode. This is the headline "tools use adapters" gap for Phase 4 and a marketplace blocker.
- **Suggested fix:** Build the real composite in a follow-up: fan `enrich_ioc` out to the Phase-3
  source adapters with `asyncio.gather` + a verdict-merge; derive `risk_score_user` from the real
  identity/endpoint signals. Until then keep the docstring honest about mock backing.

### [SEV: High] Circuit breaker still treats HTTP 5xx/429 as success — now under live tool calls
- **Where:** `sentinel/adapters/base.py:132-152` (carried from Phase 3)
- **What breaks:** `_call` records *success* for any returned response and only retries
  `TimeoutException`/`NetworkError`, so an up-but-erroring backend (500/502/429) never trips the
  breaker and is never retried. Unchanged from Phase 3, but Phase 4 wired every read tool to these
  adapters, so the gap now sits directly under live `get_alert`/`search_logs`/`weekly_summary`/etc.
- **Repro:** Source-confirmed; see Phase 3 report. No source edits allowed this workflow.
- **Impact:** The reliability feature doesn't cover the most common real failure mode, and it's now
  on the hot path of the whole tool surface. Matters the moment `MOCK_ADAPTERS=false`.
- **Suggested fix:** Count `>=500`/`429` as failures in `_retry_request`; add a breaker-on-500 test.
- **✅ Resolved:** fixed in `base._call` (see Phase 3 report) — `status >= 500`/`429` now record a
  breaker failure, so the gap no longer sits under the live tool surface. Breaker-on-500/429 tests
  added in `tests/unit/test_adapters/test_base.py::TestBreakerOnHttpErrors`.

### [SEV: Medium] `generate_incident_report` fans out to ~8 sub-tools serially — latency/cost on real backends
- **Where:** `sentinel/tools/reports.py:30-107`
- **What breaks:** The report awaits its sub-tools one at a time: `get_alert`, then `user_context`,
  `recent_logins`, `device_processes`, `network_connections`, then `enrich_ioc` **per IOC** (source
  IP + every TI-flagged connection), then `mitre_technique` **per technique**, then
  `similar_incidents`. In mock mode this is instant; against real OpenSearch/Keycloak/Wazuh +
  external TI APIs each is a network round-trip, so worst-case latency is the **sum** of ~8–15+
  calls, and the per-IOC `enrich_ioc` calls (once they're truly live — see the High above) can hit
  VirusTotal's 4 req/min token bucket and stall the whole report.
- **Repro:** Static reasoning from the serial `await` chain; not reproducible in mock mode (no I/O).
- **Impact:** A single `generate_incident_report` could take many seconds-to-minutes live and amplify
  rate-limit pressure. Acceptable now (mock), must be addressed before live use.
- **Suggested fix:** Parallelise the independent fan-out legs with `asyncio.gather` (identity /
  endpoint / per-IOC enrich / per-technique are independent once the alert is fetched); add an
  overall timeout and partial-result handling.
- **✅ Resolved:** `generate_incident_report` now fans out concurrently with `asyncio.gather` —
  identity, endpoint, similar-incidents, per-technique MITRE, and source-IP enrichment run in
  parallel, then TI-flagged destination enrichment runs as a second parallel batch. Wall-clock is
  the slowest leg, not the sum. (Overall-timeout/partial-result handling left for Phase 7.)

### [SEV: Medium] Mock `search_logs` / `threat_hunt` over-match on naive substring search
- **Where:** `sentinel/tools/mock_data.py:330-337` (matches if the lower-cased query appears
  *anywhere* in the serialised event), consumed by `tools/alerts.py:67` and `tools/intel.py:75`
- **What breaks:** Any common substring returns the whole corpus. `query="a"` → all 7 events;
  `query="acmecorp"` → all 7. There's no tokenisation, field targeting, or word-boundary, so the
  result count is meaningless for short/common queries and `threat_hunt`'s "first_seen/last_seen/
  affected_hosts" timeline can be built from spurious hits.
- **Repro:**
  ```
  query a -> total_hits: 7
  query acmecorp -> total_hits: 7
  ```
- **Impact:** Misleading hunt results in the demo/mock path; also sets a weak contract the live
  `multi_match` (`opensearch.py:79`) won't mirror (real OS does relevance scoring + analysis).
- **Suggested fix:** Match on tokenised words / specific fields in the mock corpus, or document
  that the mock is substring-only and not a search-quality reference.
- **✅ Resolved:** `mock_data.search_logs` now matches per-term against tokens (IPs/hashes/
  hostnames kept intact; only ≥4-char terms allowed as substrings), so short/common queries no
  longer return the whole corpus (`query="a"` → 0 hits). Covered by
  `tests/unit/test_tools/test_alerts.py::...test_short_common_substring_does_not_match_everything`.

### [SEV: Low] Tool-layer mypy debt grew by the Phase-4 work
- **Where:** `sentinel/tools/intel.py`, `alerts.py`, `actions.py`, `identity.py`, `reports.py`,
  `endpoint.py` (21 of the 55 total `mypy` errors)
- **What breaks:** `no-any-return` from `dict`/`resp.json()`-shaped values returned from functions
  typed `dict[str, Any]`. No runtime effect; strict-typing debt.
- **Impact:** Type-safety debt; deferred to Phase 7 per plan, consistent with the adapter debt.
- **Suggested fix:** Validate tool outputs into Pydantic response models at the tool boundary.

## User-facing problems
- **Two flagship tools are mock-only regardless of `MOCK_ADAPTERS`** (`enrich_ioc`,
  `risk_score_user`). A user who sets real API keys and flips mock off will still get canned
  verdicts/scores with no warning — the docstrings actively claim live multi-source enrichment.
  Highest-priority honesty/feature gap.
- **`weekly_summary` will quietly report empty/None severity & open/closed counts** against a real
  OpenSearch (shape mismatch above) — confusing because it doesn't error, it just under-reports.
- **No new setup friction this phase**, but everything still depends on `MOCK_ADAPTERS=true` for
  correct output; the documented quickstart remains mock-first and the live path is unverified.
- **Lint/type noise outside the touched dirs** (11 ruff in `sentinel/`, 40 in `tests/`, 55 mypy)
  is pre-existing but will surprise anyone running the documented `ruff`/`mypy` commands expecting
  clean output. Track for the Phase 7 cleanup.

## Mock-vs-real gaps
- `enrich_ioc` and `risk_score_user` never touch an adapter — pure mock composites (High above).
- `weekly_summary`'s consumed contract only matches the adapter's *mock* branch; the live agg
  branch returns a different shape (High above).
- All other read tools route through the Phase-3 adapters but have only ever run against
  `MOCK_ADAPTERS=true` / respx — no real OpenSearch / Keycloak / Wazuh call has happened, and the
  breaker-vs-5xx bug means the mock path can't surface the most likely production failure.
- `generate_incident_report`'s serial fan-out is free in mock mode and expensive/rate-limit-prone
  live (Medium above).
- Write tools' executors now call the real Wazuh/Keycloak adapters (`actions.py:23-26,102-105,
  252-255`), but `block_ip` has no firewall adapter — it only records to a Postgres blocklist
  (`actions.py:175-183`); "pushes to the perimeter firewall" is aspirational.

## Summary
Phase 4 hits its headline goal: all 18 tools are wired and return schema-shaped data through the
MCP server (410 tests green, 95.06% coverage, tool packages 94–100%, no `not_yet_implemented`
left), and the new integration test proves the write-tool token lifecycle end-to-end. But two of
the most analyst-critical tools — `enrich_ioc` and `risk_score_user` — are still mock composites,
not the advertised live adapter fan-out, and `weekly_summary` consumes a shape only the mock
backend returns. Top 3 to fix next: **(1)** make `enrich_ioc`/`risk_score_user` actually compose the
Phase-3 adapters (close the headline gap); **(2)** align `aggregate_alerts` live output with the
`{total,by_severity,open,closed}` contract `weekly_summary` expects; **(3)** parallelise + bound
`generate_incident_report` and fix the breaker-vs-5xx bug before any live use. None block
*documenting* Phase 4, but (1) and (2) are blockers for calling the tools "adapter-backed" in a
real deployment.
