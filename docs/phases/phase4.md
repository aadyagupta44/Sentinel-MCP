# Phase 4 — All 18 Tools (adapter-backed)

*Documented: 2026-06-06*  ·  *Status: Complete — with two known mock-only tools (see deferred)*

## Goal
Turn the 11 stubbed read/report tools from Phase 2 into working tools and route every read tool
through its Phase-3 adapter, so the MCP surface returns real schema-shaped data end-to-end (no
`not_yet_implemented` left) and the write tools execute against real adapters instead of inline mocks.

## What was built
- **Stubs implemented (`sentinel/tools/`):**
  - `search_logs` (`alerts.py:57-98`) — full-text log search via `OpenSearchAdapter.search_logs`;
    bounded params (window ≤168h, results ≤500); structured `match` clause, never raw Lucene.
  - `correlate_alerts` (`alerts.py:114-197`) — entity-overlap clustering (union-find style) over
    user/host/IP/MITRE technique; emits generated `CL-NNN` cluster IDs + shared-factor summaries.
  - `similar_incidents` (`alerts.py:226-282`) — field-similarity ranking (same rule 0.4 / shared
    technique 0.3 / same severity 0.2 / same user 0.1) against the alert pool.
  - `threat_hunt` (`intel.py:67-118`) — indicator timeline via `search_logs` over a longer window;
    returns first/last-seen + affected hosts.
  - `mitre_technique` (`intel.py:124-158`) — routed to the MITRE adapter's local STIX dataset.
  - `weekly_summary` (`reports.py:171-209`) — `OpenSearchAdapter.aggregate_alerts` + top risky
    users / top source IPs computed from the alert list.
  - `generate_incident_report` (`reports.py:19-165`) — orchestration tool (see below).
- **Read data tools routed to adapters:** `get_alert` → OpenSearch; `user_context`/`recent_logins`
  → Keycloak; `device_processes`/`network_connections` → Wazuh; `mitre_technique` → MITRE.
- **Write tools now call real adapters** (`actions.py`): `isolate_device`/`kill_process` →
  `WazuhAdapter` (`:23-26,252-255`), `disable_user` → `KeycloakAdapter` (`:102-105`); two-step
  confirmation unchanged. `block_ip` records to a Postgres blocklist — no firewall adapter exists
  yet (`:175-183`).
- **New mock corpus:** `sentinel/tools/mock_data.py::search_logs` (`:330+`) — a deterministic 7-event
  SIEM log corpus backing `search_logs`/`threat_hunt` in mock mode.
- **New integration test:** `tests/integration/test_phase4_tools.py` drives all 14 read tools through
  `mcp.call_tool` (asserting no stub/error), the full write-tool token lifecycle (propose →
  reject-without-token → execute+audit → reject-expired → reject-wrong-tool), and the report
  orchestration. +42 tests.
- **Explicitly still mock-composite (not adapter fan-out):** `enrich_ioc` (`intel.py:33`) and
  `risk_score_user` (`identity.py:99`) return curated `mock_data` composites. The individual TI
  source adapters exist + are tested (Phase 3), but the live multi-source composition is deferred.

## How it works
The tool layer keeps the Phase-2 contract: each `@mcp.tool()` is a thin wrapper over
`run_middleware(name, args, _execute_*)`, and the `_execute_*` helper does validation + the real
work. Phase 4 changed the body of the helpers from stub returns to adapter calls.

`generate_incident_report` is the one composite. Rather than re-enter the middleware per sub-tool,
it calls the sibling `_execute_*` helpers **directly** (`reports.py:25-28`) and assembles their
outputs:

```
get_alert ─▶ (affected_user) ─▶ user_context, recent_logins        ┐
          ─▶ (affected_host) ─▶ device_processes, network_connections ├─▶ report
          ─▶ (source_ip + TI-flagged conns) ─▶ enrich_ioc (per IOC)   │
          ─▶ (mitre_techniques) ─▶ mitre_technique (per technique)     │
          ─▶ similar_incidents                                         ┘
```

The fan-out is **serial** (`reports.py:30-107`) — free in mock mode, expensive live. An optional
Anthropic narrative is added only when `report_narrative_enabled` **and** `has_anthropic`
(`reports.py:110-117`); otherwise the structured data is returned and Claude writes the narrative.

`search_logs`/`weekly_summary`/`correlate_alerts` go through `OpenSearchAdapter`, which branches on
`is_mock` (`opensearch.py:67,104,136`): mock mode hits the `mock_data` corpus/canned aggregates,
live mode runs the real parameterised `multi_match` / agg queries.

## Key decisions & trade-offs
- **`enrich_ioc`/`risk_score_user` left as mock composites** — the Phase-3 source adapters are
  built but the live verdict-merge/score-derivation is non-trivial, so this phase shipped the other
  16 tools end-to-end and recorded the fan-out as a deliberate follow-up rather than half-building
  it. Cost: the two most analyst-critical tools return canned data even with `MOCK_ADAPTERS=false`.
- **Report orchestrates via `_execute_*` helpers, not nested `mcp.call_tool`** — avoids re-running
  policy/rate-limit/audit middleware once per sub-tool (a single report would otherwise emit ~10
  audit rows and burn 10 rate-limit tokens). Cost: the sub-calls bypass per-sub-tool policy checks;
  the outer `generate_incident_report` call is still gated.
- **Serial fan-out for now** — simplest correct version; in mock mode latency is ~0. Trade-off
  carried to the risk report: live latency is the sum of ~8–15 round-trips and can stall on VT rate
  limits. Parallelisation deferred.
- **Bounded, structured inputs over raw query passthrough** — every tool clamps windows/limits and
  passes user text as a `match`/`multi_match` value, never interpolated Lucene (`opensearch.py:79`),
  keeping query-injection off the table.
- **Tests-and-tools only, no infra changes** — middleware/audit/OPA untouched; the integration test
  stubs only the infra hooks (OPA/Redis/audit) so the *tool logic itself* runs for real.

## Problems & gotchas
From `docs/test-reports/phase4.md`:
- **`weekly_summary` shape mismatch (High):** it consumes `total`/`by_severity`/`open`/`closed`,
  which only the adapter's **mock** branch returns; the **live** `aggregate_alerts` returns
  `{"raw_aggregations": ...}` (`opensearch.py:159-160`). Against real OpenSearch the severity/
  open/closed numbers come back empty/None — quiet-wrong, not a crash.
- **`enrich_ioc`/`risk_score_user` are mock-only (High):** docstrings advertise live multi-source
  enrichment; the executors return `mock_data`. Flipping `MOCK_ADAPTERS=false` doesn't change them.
- **Breaker-vs-5xx (High, carried from Phase 3):** the breaker counts HTTP 5xx/429 as success and
  only retries transport errors; now sits under every live read tool.
- **`generate_incident_report` serial fan-out (Medium):** ~8–15 sequential round-trips live; can
  stall on VirusTotal's 4 req/min bucket.
- **Mock `search_logs` over-matches (Medium):** naive substring search — `query="a"` returns all 7
  corpus events (reproduced).
- Everything else still runs only against mock/respx — no real backend exercised.

## Verification
- Tests: 410/410 passing (`uv run pytest -q`); +42 vs Phase 3.
- Coverage: **95.06%** total (real, this run); tool packages 94–100% (`alerts`/`intel`/`endpoint`
  100%, `actions` 98%, `reports`/`identity` 94%). `--cov-fail-under=80` gate passes.
- Lint/type: `ruff` clean on `sentinel/tools/`, `sentinel/adapters/`, and the new Phase-4 test.
  11 ruff issues remain elsewhere in `sentinel/` (`audit/`, `mcp/`, `main.py`) and 40 in non-Phase-4
  `tests/` — pre-existing. `mypy sentinel/` = 55 errors (21 in the tool layer, same `no-any-return`
  class as the adapters) — deferred to Phase 7. Boots: `import sentinel.main` → OK.

## Deferred to later phases
Live `enrich_ioc`/`risk_score_user` composition over the Phase-3 source adapters (the headline
"uses adapters" gap); aligning `aggregate_alerts` live output with the `weekly_summary` contract;
parallelising + bounding `generate_incident_report`; a real firewall adapter for `block_ip`; the
opt-in live integration suite + closing the mock-vs-real gap (Phase 5+); breaker-vs-5xx fix and the
mypy/lint debt (Phase 7 hardening).
