# Phase 3 — Breakage & Risk Report

*Run: 2026-06-06*  ·  *Scope: cumulative through Phase 3 (15 adapters + BaseAdapter, all now respx-tested)*

## Baseline
- Tests: 368/368 passing (0 failed). Adapter suite alone: 246/246.
- Coverage: 93.40% (`--cov-fail-under=80` gate now **green**, up from ~37.5%).
  - `sentinel.adapters` package: **100%** line coverage (1173 stmts, 0 missed).
  - Remaining low-coverage modules are all pre-Phase-3: `sentinel/audit/log.py` 48%,
    `sentinel/db/session.py` 65%, `sentinel/mcp/middleware.py` 72%, `sentinel/main.py` 75%.
- Lint: `sentinel/adapters/` + `tests/unit/test_adapters/` **clean**. Elsewhere: `ruff check
  sentinel/` = 59 issues, `ruff check tests/` = 52 issues (all pre-existing, outside Phase 3 scope).
- Type: `mypy sentinel/` = 52 errors (31 in adapter source; rest pre-existing in tools/main).
- Boots: yes — `uv run python -c "import sentinel.main"` → `BOOTS_OK`.

## Findings
Ordered by severity.

### [SEV: High] A persistently-failing backend (HTTP 5xx/4xx) never opens the circuit breaker
- **Where:** `sentinel/adapters/base.py:132-140` (`_call`), `:142-152` (`_retry_request`)
- **What breaks:** `_call` only invokes `record_failure()` when `_retry_request` *raises*. An
  HTTP error response (500, 502, 403, 429) is returned as a normal `resp` with no exception, so
  `record_success()` runs and the failure counter resets to 0. Retry is likewise scoped to
  `httpx.TimeoutException | httpx.NetworkError` only (`:145`). Net effect: only transport-level
  failures (timeouts, conn-refused) ever trip the breaker; a backend that is up-but-erroring is
  hammered indefinitely with no breaker protection and no retry.
- **Repro:** Reasoned from source + confirmed by the adapter tests — breaker-open tests drive
  `httpx.ConnectError`, never a 500. No test asserts breaker behavior on a 5xx (because it
  doesn't happen).
- **Impact:** The headline reliability feature silently doesn't cover the most common real-world
  failure mode (an overloaded/erroring upstream). Matters the moment `MOCK_ADAPTERS=false`.
- **Suggested fix:** Treat configurable status classes (>=500, 429) as failures: either
  `resp.raise_for_status()` inside `_retry_request` for those, or count them in `_call` before
  returning. Add a breaker test on repeated 500s.
- **✅ Resolved:** `_call` now records a breaker **failure** for `status >= 500` or `429`
  (success otherwise), so a persistently-erroring backend trips the breaker. The response is
  still returned so callers keep their own status handling. Covered by
  `tests/unit/test_adapters/test_base.py::TestBreakerOnHttpErrors` (5xx + 429 open it; 2xx/404
  do not).

### [SEV: Medium] Circuit-breaker `state` transition mutates shared state on read, outside the lock
- **Where:** `sentinel/adapters/base.py:58-65` (`state` property), read by `is_open()` (`:67`)
- **What breaks:** The OPEN→HALF_OPEN transition writes `self._state` inside a `@property`
  getter. `record_success`/`record_failure` guard writes with `self._lock`, but this read-path
  write is unlocked. A read (`is_open()`) can race a concurrent `record_*` write on the same
  breaker shared across tasks/event loops.
- **Repro:** Hypothesis (static reasoning). The transition is idempotent and the loop is
  single-threaded, so practical fallout is limited; flagged as a latent correctness smell.
- **Impact:** Low under the current single-event-loop stdio model; would matter if a breaker
  instance is shared across threads/loops. A getter with a side effect is also surprising.
- **Suggested fix:** Move the time-based transition into the locked `record_*`/an explicit
  `_maybe_half_open()` called under the lock; keep `state` a pure read.
- **✅ Resolved:** the `state` getter is now a pure read — after the recovery window it *returns*
  `HALF_OPEN` without mutating `self._state`, so a concurrent reader can't race a writer. Covered
  by `tests/unit/test_adapters/test_base.py::TestStateReadIsPure`.

### [SEV: Medium] Adapter "live HTTP works" is proven only against respx mocks
- **Where:** all of `tests/unit/test_adapters/` via the `live_mode` fixture
  (`tests/unit/test_adapters/conftest.py`) that flips `MOCK_ADAPTERS=false`
- **What breaks:** `live_mode` exercises the real HTTP code paths, but the responses are respx
  fakes shaped from docs/assumptions. No call has touched a real OpenSearch / Keycloak / Wazuh /
  VirusTotal / abuse.ch. Response-shape drift, auth quirks, pagination, and error envelopes from
  real services are unverified.
- **Repro:** N/A — structural gap, not a crash.
- **Impact:** 100% adapter coverage measures "matches our mock," not "matches the vendor." This
  is the single biggest pre-release risk and must be re-verified live before marketplace.
- **Suggested fix:** Add an opt-in integration suite (`-m live`) against dockerized OpenSearch/
  Keycloak/Wazuh and recorded real fixtures for the SaaS APIs; run before each release tag.

### [SEV: Low] Test backoff is neutralised by a fixture, so retry *timing* is never exercised
- **Where:** `tests/unit/test_adapters/conftest.py` `_fast_retry` (patches tenacity wait → no sleep)
- **What breaks:** Necessary to keep the suite fast, but it means the exponential-backoff
  schedule (`wait_exponential(min=1, max=10)`) and the read/connect timeouts in
  `base.py:101-104` are asserted only structurally, not behaviorally.
- **Impact:** Polish — a regression in the wait policy wouldn't fail a test.
- **Suggested fix:** One targeted test that asserts the computed wait sequence without sleeping.

### [SEV: Low] 31 mypy errors remain in adapter source
- **Where:** `sentinel/adapters/opensearch.py:55`, `wazuh.py:177`, et al. (`resp.json()` → `Any`
  returned from functions typed `dict[...]`)
- **What breaks:** Strict `no-any-return` violations; no runtime effect.
- **Impact:** Type-safety debt; deferred to Phase 7 (hardening) per plan.
- **Suggested fix:** Cast/validate `resp.json()` into typed models (Pydantic) at the adapter boundary.

## User-facing problems
- **Adapters still gated by `MOCK_ADAPTERS=true` for any real value.** Nothing in Phase 3
  changes that a first-time user pointing at real services hits untested paths (see High/Medium
  breaker findings + the mock-vs-real gap). No new setup friction was introduced this phase.
- **Lint/type noise outside adapters** (59 ruff in `sentinel/`, 52 in `tests/`, 21 non-adapter
  mypy) is pre-existing but will confuse anyone running the documented `ruff`/`mypy` commands and
  expecting clean output. Track for a Phase 7 cleanup pass.

## Mock-vs-real gaps
Every adapter's success and error handling is verified against respx, not a live backend. The
breaker only opens on transport errors (not 5xx), so the mock tests can't even surface the most
likely production failure. Before release: run all adapters with `MOCK_ADAPTERS=false` against
real OpenSearch/Keycloak/Wazuh and recorded real responses for the optional SaaS APIs.

## Summary
Phase 3 is solid on the metric it set out to move: the adapter layer went from 0% to 100%
coverage with 246 honest respx tests, the global gate is green at 93.4%, and adapters lint/format
clean. The work also exposed a genuine reliability bug it can't paper over. Top 3 to fix next:
**(1)** make the circuit breaker (and retry) treat HTTP 5xx/429 as failures, not successes;
**(2)** stand up an opt-in live integration suite so coverage means "matches the vendor"; **(3)**
make the `state` transition lock-safe / side-effect-free. None block starting Phase 4.
