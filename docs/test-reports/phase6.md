# Phase 6 — Breakage & Risk Report

*Run: 2026-06-06*  ·  *Scope: cumulative through Phase 6 (standalone traffic simulator)*

## Baseline
- Tests: 478/478 passing (0 failed). +31 vs Phase 5 (447). New files are
  `tests/unit/test_simulator/` (`test_profiles.py`, `test_iocs.py`, `test_events.py`,
  `test_scenarios.py`, `test_bots.py` with a fake clock, `test_sink.py`) and
  `tests/integration/test_simulator.py` (dry-run orchestration + simulated adversarial alerts
  correlating into one cluster via the live `correlate_alerts`).
- Coverage: 94.97% (`--cov-fail-under=80` gate **green**, ~unchanged from 94.96%). **But the
  number is for `sentinel/` only** — the new `simulator/` package is **not in the coverage
  `source`** (see Medium finding below), so its lines are unmeasured and ungated despite the
  tests existing.
  - Low-coverage modules are all pre-Phase-6 infra, unchanged: `audit/log.py` 48%,
    `db/session.py` 65%, `mcp/middleware.py` 72%, `main.py` 79%, `mcp/resources.py` 82%,
    `policy/engine.py` 82%.
- Lint: `ruff check simulator/` **clean** ("All checks passed!"); `ruff check tests/unit/test_simulator/
  tests/integration/test_simulator.py` **clean**; `ruff format --check simulator/` → "8 files
  already formatted". `ruff check tests/` = 38 issues — all **pre-existing** in non-Phase-6 test
  dirs (e.g. `F401` unused `pytest`, `E741` ambiguous `l` in `test_identity.py:54`).
- Type: `mypy simulator/` **clean** ("no issues found in 8 source files"). `mypy sentinel/` = 60
  errors across 20 files — **pre-existing debt, unchanged** by this phase (the +2 in
  `adapters/abuse_ch.py:214,233` are in the pre-Phase-6 lookup methods, not the new accessors;
  the new `known_c2_ips`/`known_malware_hashes` are clean). Deferred to Phase 7.
- Boots / runs: yes — `MOCK_ADAPTERS=true uv run python -m simulator.main --duration 2 --dry-run
  --seed 7 --normal-min 0.05 --normal-max 0.1 --adv-min 0.3 --adv-max 0.6` →
  `Simulator done: 24 logins emitted, 5 adversarial scenario(s) fired (brute_force,
  suspicious_process, suspicious_process, data_exfiltration, brute_force).`

## Findings
Ordered by severity.

### [SEV: Medium] The `simulator/` package is excluded from the coverage gate — its tests run but cover nothing measurable
- **Where:** `pyproject.toml:124-126` (`[tool.coverage.run] source = ["sentinel"]`)
- **What breaks:** The coverage `source` is `["sentinel"]`, so `simulator/` lines are never
  counted. The 94.97% TOTAL is `sentinel/`-only; the simulator's eight modules contribute
  nothing to the number and are not protected by `--cov-fail-under=80`. The Phase 6 tests exist
  and pass, but a future regression that drops a simulator branch (e.g. an untested scenario or
  sink path) would not move the gate. The suite *looks* like it covers the new package; the gate
  does not.
- **Repro:** Coverage table from `uv run pytest -q` lists `sentinel\...` modules only — no
  `simulator\...` row appears; TOTAL = 2368 statements (all `sentinel/`).
- **Impact:** Phase-6 code is functionally tested but its coverage is invisible and ungated —
  honest accounting requires stating the 94.97% does not include the simulator.
- **Suggested fix:** Add `"simulator"` to `[tool.coverage.run] source` (or a second gate) so the
  new package is measured and held to the same bar.
- **✅ Resolved in-phase:** `simulator` added to `[tool.coverage.run] source` and `--cov=simulator`
  to addopts. Simulator now gated: bots/events/iocs/profiles/scenarios/sink at 100%, main.py 97%;
  overall coverage 95.36% across sentinel + simulator.

### [SEV: Medium] OpenSearchSink writes to a derived concrete index that must match the read pattern on a live stack
- **Where:** `simulator/sink.py:43-50`, `sentinel/config.py:52-53`,
  `sentinel/adapters/opensearch.py:31` / `:61` (`search_logs`)
- **What breaks:** The sink writes logs to a concrete index derived from the *read* pattern:
  `opensearch_index_logs` (`"sentinel-logs-*"`) → `.replace("*","").rstrip("-")` → `"sentinel-logs"`
  (`sink.py:44`). Alerts are written to `opensearch_index_alerts` (`"sentinel-alerts"`), which the
  alert tools read directly — that pair lines up. For logs, `search_logs` queries the wildcard
  pattern `sentinel-logs-*` (`opensearch.py:31`), and `"sentinel-logs"` does **not** match
  `sentinel-logs-*` (no trailing segment after the dash) under OpenSearch wildcard index
  resolution. So on a **live** stack (`MOCK_ADAPTERS=false`) `search_logs` may not return the
  simulator's log events even though they were ingested.
- **Repro:** Source-confirmed only — never exercised against a live OpenSearch (all tests use the
  InMemorySink / mock adapter). This is a live-run verification item, not a CI-proven bug.
- **Impact:** A first-time user who runs the simulator against real OpenSearch and then asks
  Claude to `search_logs` for simulated traffic could get empty results, while `correlate_alerts`
  (reading the alerts index) still works. Confusing mock-vs-real gap.
- **Suggested fix:** Write logs to a name the read pattern matches (e.g. `sentinel-logs-sim` or a
  date-suffixed `sentinel-logs-YYYY.MM.DD`), or make the sink derive the write index from the
  pattern by substituting a concrete suffix rather than stripping the wildcard.
- **✅ Resolved in-phase:** `OpenSearchSink` now substitutes the wildcard with a concrete suffix
  (`"sentinel-logs-*"` → `"sentinel-logs-sim"`), which matches the `search_logs` read pattern. A
  test asserts the write index matches the read pattern via `fnmatch`.

### [SEV: Low] The "≥50 logins in 5 min AND ≥1 adversarial concurrently" acceptance is proven in parts, not in one wall-clock run
- **Where:** `tests/unit/test_simulator/test_bots.py` (virtual-clock `NormalBot.run`),
  `tests/integration/test_simulator.py:21-36` (real-asyncio dry-run, `duration_s=0.5`, tiny
  intervals)
- **What breaks:** The deterministic tests drive a **single** bot with a per-bot virtual clock
  (so `NormalBot.run` can prove `logins_emitted ≥ 50` without real time), and the orchestration
  test runs both bots under real asyncio but for 0.5 s with millisecond intervals. The
  `asyncio.gather` overlap of two long-running sleeps over a real 5-minute window is therefore
  never executed as one run; the two halves of the acceptance criterion (volume + concurrent
  adversarial) are validated separately. The `run_simulator` injects one shared `sleep`/`clock`
  to both bots (`main.py:50-65`), which under real asyncio overlaps correctly, but a virtual
  clock shared across two gathered coroutines would not advance as wall time — the tests sidestep
  this by using real (tiny) sleeps for orchestration and virtual clocks only for single-bot
  volume.
- **Repro:** Test inspection.
- **Impact:** Low — each property is proven; only the exact combined wall-clock scenario is not.
  The CLI dry-run above (24 logins + 5 scenarios in ~2 s of compressed intervals) is the closest
  end-to-end evidence.
- **Suggested fix:** None required; optionally add one short real-time orchestration assertion
  (e.g. duration 2–3 s with sub-second intervals) checking both `logins_emitted` and
  `len(scenarios_fired)` in a single gathered run.

## User-facing problems
- **Live OpenSearch ingestion + Claude-Desktop `search_logs` is a live-run step, not CI-proven.**
  Everything in Phase 6 is verified with the InMemorySink and mock adapters. The documented
  "point it at a real OpenSearch with `MOCK_ADAPTERS=false`" path (`simulator/main.py:6`) —
  ingest → `search_logs` returns simulated events → `correlate_alerts` clusters them, with
  `/health` up under load — has not been run. Document it as a manual live-run acceptance step.
- **The log-index naming gap (Medium above) surfaces only live.** A user running against real
  OpenSearch may see `correlate_alerts` work (alerts index matches) while `search_logs` returns
  nothing (logs written to `sentinel-logs`, read via `sentinel-logs-*`). Worth a quickstart note
  until the index name is reconciled.
- **No CLI flag to choose a single scenario or to seed the IOC list offline.** Minor: the bot
  picks scenarios randomly; reproducing a specific incident requires the seed plus knowledge of
  the RNG draw order. Acceptable for a simulator.

## Mock-vs-real gaps
- Real OpenSearch ingestion, the logs read-pattern↔write-index match, `/health`-during-load, and
  Claude-Desktop `search_logs`/`correlate_alerts` over live data are **all unexercised** — live-run
  steps only.
- `IocProvider.from_abuse_ch()` pulls real FeodoTracker / MalwareBazaar indicators only when
  `MOCK_ADAPTERS=false`; in CI the abuse.ch adapter is pre-seeded, so the "real IOC" path is the
  mock seed, with hard-coded fallbacks (`iocs.py:12-13`) if a feed is empty. The live feed
  download is untested.
- Carry-forward, still unfixed: `enrich_ioc`/`risk_score_user` mock-only and `weekly_summary`
  live-shape mismatch (Phase 4); breaker-vs-5xx (`adapters/base.py`, Phase 3); `/mcp` end-to-end
  exercise and the two authz sources drift (`auth/authz.py` ↔ `policies/authz.rego`) (Phase 5).
  No real OpenSearch/Keycloak/Wazuh has ever been hit.

## Summary
Phase 6 lands cleanly: a standalone `simulator/` package (10 profiles × 5 departments, four event
factories, five correlated adversarial scenarios using real abuse.ch IOCs, two injectable-clock
bots, two sinks, a CLI) — 478 tests green, `simulator/` clean on both ruff and mypy, and the
CLI dry-run produces 24 logins + 5 scenarios reproducibly. The honest caveats are all about
measurement and the mock boundary, not correctness: **(1)** the 94.97% coverage excludes
`simulator/` entirely (`source = ["sentinel"]`), so the new code is tested but ungated; **(2)** on
a live stack the sink writes logs to `sentinel-logs` while `search_logs` reads `sentinel-logs-*`,
a potential index-name mismatch to verify; **(3)** the "≥50 logins + concurrent adversarial in 5
min" criterion is proven in parts (virtual-clock single-bot + tiny-interval orchestration), not in
one wall-clock run. None block documenting Phase 6; the single most important fix is **(1)** add
`simulator` to the coverage source so the package is actually gated.
