# Phase 3 — Adapters

*Documented: 2026-06-06*  ·  *Status: Complete*

## Goal
Bring the 15 external-service adapters (all written in earlier batches but untested) under
real test coverage — respx-mocked unit tests for every adapter plus `BaseAdapter` — so the
adapter layer goes from 0% coverage to a verified contract and the suite's `--cov-fail-under=80`
gate goes green.

## What was built
- **Adapter test suite** — `tests/unit/test_adapters/` now has one `test_<adapter>.py` per
  adapter (15) plus `test_base.py` for `BaseAdapter`/`CircuitBreaker`. 246 tests total,
  all respx-mocked (or mocked socket / SDK for `dnsbl` and `anthropic`). No test makes a real
  network call.
- **Shared fixtures** — `tests/unit/test_adapters/conftest.py`:
  - `_fast_retry` (autouse): monkeypatches `asyncio.sleep` to a no-op so tenacity's exponential
    backoff and the VirusTotal/URLScan token-bucket waits run instantly.
  - `live_mode`: sets `MOCK_ADAPTERS=false` and clears the `get_settings` cache so an adapter
    built inside the test exercises its real HTTP path; restored on teardown.
- **Coverage outcome** — `sentinel.adapters` package at **100%** line coverage (1173 stmts,
  0 missed). Both the happy path and the error/circuit-breaker/rate-limit paths are exercised.
- **Lint cleanup** — ~50 pre-existing lint issues in the adapter *source* were fixed; `ruff
  check` + `ruff format` are clean on `sentinel/adapters/` and `tests/unit/test_adapters/`.
- **No source behavior changed** — this phase added tests + lint fixes only; adapter logic and
  all other tools/resources/prompts are untouched.

## How it works
Each adapter test constructs the adapter and drives it through respx:

```python
@pytest.mark.asyncio
async def test_lookup(respx_mock, live_mode):          # live_mode → real HTTP path
    respx_mock.get(URL).mock(return_value=Response(200, json={...}))
    result = await get_adapter().lookup("...")
    assert result["key"] == "value"
```

Two modes are covered per adapter: **mock mode** (suite default `MOCK_ADAPTERS=true`, hits the
adapter's `_mock_response` hook) and **live mode** (the `live_mode` fixture flips the flag so
the real `BaseAdapter._call` → `_retry_request` HTTP path runs against respx). `BaseAdapter`
itself is tested directly in `test_base.py`: retry on `TimeoutException`/`NetworkError`
(`sentinel/adapters/base.py:142-152`), circuit-breaker open after 5 failures
(`base.py:75-87`), and the OPEN→HALF_OPEN recovery transition (`base.py:58-65`).

## Key decisions & trade-offs
- **respx mocks, not live integration** — fast, deterministic, zero external accounts; the cost
  is that "100% adapter coverage" means "matches our mock," not "matches the real vendor." The
  mock-vs-real gap is carried forward (see test report) and must be closed before release.
- **Neutralise backoff in tests (`_fast_retry`)** — keeps the failure/retry/breaker tests
  instant; trade-off is that retry *timing* (the exponential schedule, real timeouts) is asserted
  structurally, not behaviorally.
- **`live_mode` fixture instead of per-test env juggling** — one place to flip mock off and
  reset the settings cache, so live-HTTP tests don't leak `MOCK_ADAPTERS=false` into the rest of
  the suite.
- **Tests-only phase, no source edits** — keeps the adapter contract frozen while it gets
  verified; the reliability bug the tests exposed (breaker ignores HTTP 5xx) is documented, not
  patched, per the no-source-changes rule for this workflow.

## Problems & gotchas
From `docs/test-reports/phase3.md`:
- **Circuit breaker only opens on transport errors, not HTTP 5xx/429** (`base.py:132-140`):
  `_call` records *success* for any returned response, so a backend that is up-but-erroring never
  trips the breaker and isn't retried. Real bug; the most important fix before Phase 5/live use.
- **`state` property mutates `_state` outside the lock** (`base.py:58-65`): the OPEN→HALF_OPEN
  transition is an unlocked write inside a getter — a latent race / surprising side effect, low
  impact under the single event loop.
- **Mock-vs-real** is the dominant risk: no adapter has touched a real OpenSearch/Keycloak/Wazuh
  or the SaaS APIs.

## Verification
- Tests: 368/368 passing (`uv run pytest -q`); adapter subset 246/246.
- Coverage: **93.40%** total (real, this run); `sentinel.adapters` 100%. `--cov-fail-under=80`
  gate passes.
- Lint/type: `ruff` clean on adapters + adapter tests (59 issues remain elsewhere in `sentinel/`,
  52 in non-adapter `tests/`, pre-existing). `mypy sentinel/` = 52 errors (31 in adapters,
  `resp.json()` → `Any`) — deferred to Phase 7. Boots: `import sentinel.main` → OK.

## Deferred to later phases
Implementing the 11 stubbed read/report tools that consume these adapters (Phase 4); an opt-in
live integration suite + closing the mock-vs-real gap (Phase 5+); fixing the breaker-vs-5xx bug
and the mypy/lint debt (Phase 7 hardening).
