# Phase 1 — Breakage & Risk Report

*Run: 2026-06-06 (retrospective)*  ·  *Scope: foundation (config, db, audit, policy, base adapter, MCP/HTTP shell)*

## Baseline
- Tests: 62/62 passing at phase close (0 failed).
- Coverage: 82% at phase close.
- Lint (ruff) / Type (mypy): clean at phase close. Boots: `docker compose up` clean, `/health` → 200.

## Findings
Ordered by severity.

### [SEV: High] Policy enforcement is OFF with the shipped dev defaults
- **Where:** `.claude/settings.json`, `.env.example`, `sentinel/policy/engine.py`,
  `sentinel/mcp/middleware.py`
- **What breaks:** The default env sets `POLICY_ENFORCEMENT=false`, so the OPA gate in the
  middleware is bypassed. The carefully built default-deny only protects you when enforcement
  is explicitly turned on.
- **Impact:** Anyone running with the out-of-the-box config gets *no* authorization checks.
  Easy to ship to "prod" still flipped off.
- **Suggested fix:** Default `POLICY_ENFORCEMENT=true`; require an explicit opt-out for dev,
  and refuse to start in a non-dev `ENVIRONMENT` with enforcement disabled.
- **✅ Resolved:** `policy_enforcement` defaults to `True` in `config.py`, and
  `Settings.validate_runtime()` (called in `main.py` lifespan) now refuses to start in
  `ENVIRONMENT=production` when policy enforcement is off (or mock adapters on, or
  placeholder DB/Keycloak URLs). Covered by `tests/unit/test_config.py`.

### [SEV: High] Manifest advertises `oauth2_pkce` before auth exists
- **Where:** `sentinel/main.py:99`
- **What breaks:** `/.well-known/mcp` claims `"auth": "oauth2_pkce"`, but `sentinel/auth/` is
  empty until Phase 5. A client that trusts the manifest will try an auth flow that isn't there.
- **Impact:** Misleading capability advertisement — a correctness/trust gap for any HTTP client.
- **Suggested fix:** Advertise auth conditionally (only when implemented/enabled), or mark it
  `"none"`/`"planned"` until Phase 5.
- **✅ Resolved:** OAuth 2.1 + PKCE was implemented in Phase 5; the manifest now honestly
  advertises `oauth2_pkce` alongside the real `authorization_endpoint`/`token_endpoint`/`scopes`,
  and `/mcp` enforces a Bearer JWT. The capability claim now matches the implementation.

### [SEV: Medium] Audit chain integrity depends on Postgres being up
- **Where:** `sentinel/audit/log.py`
- **What breaks:** The hash chain + advisory lock require Postgres. If the DB is unavailable,
  audit writes fail — confirm the tool call also fails closed rather than proceeding unlogged.
- **Impact:** A silently-unlogged sensitive action would defeat the point of an immutable log.
- **Suggested fix:** Make "audit write failed" a hard stop for write tools; add a test that
  asserts no action commits when the audit row can't be written.

### [SEV: Medium] CORS is wide open in development
- **Where:** `sentinel/main.py:64`
- **What breaks:** `allow_origins=["*"]` when `is_development`. Fine locally, dangerous if a
  dev build is ever exposed.
- **Impact:** CSRF/credential-leak surface if a dev instance is reachable.
- **Suggested fix:** Restrict to an explicit localhost allowlist even in dev; document it.
- **✅ Resolved:** dev CORS now uses an explicit localhost origin allowlist
  (`_DEV_CORS_ORIGINS` in `main.py`) instead of `"*"`; production defaults to no cross-origin
  allowance.

### [SEV: Low] No startup validation that required secrets are present
- **Where:** `sentinel/config.py`, `sentinel/secrets.py`
- **What breaks:** Optional service keys absent is fine (graceful degradation), but there's no
  fail-fast for genuinely required prod secrets (DB URL, etc.).
- **Impact:** Failures surface late, at first use, instead of at boot.
- **Suggested fix:** Add a `validate_for(environment)` check on startup in non-dev.
- **✅ Resolved:** `Settings.validate_runtime()` runs in the `main.py` lifespan and raises on
  unsafe production config (auth off, mock adapters on, `localhost` DB/Keycloak URLs) — failing
  fast at boot instead of at first use. Covered by `tests/unit/test_config.py`.

## User-facing problems
- **Quickstart commands are bash-only.** `CLAUDE.md` uses `source .venv/bin/activate` etc.;
  on this Windows/PowerShell machine `python3` isn't even on PATH (`python` is). First-run
  users on Windows will hit this immediately. → Add PowerShell equivalents.
- **Heavy first run.** `docker compose up` pulls Postgres + Redis + OpenSearch + OPA + Keycloak.
  OpenSearch alone is memory-hungry. → Document minimum RAM and a "mock-only, no Docker" path.

## Mock-vs-real gaps
At Phase 1 there are no real integrations yet — but `MOCK_ADAPTERS=true` is the default and the
base adapter's mock hook means nothing has touched a real backend. Every "it works" claim from
here on must be re-verified against live services before release.

## Summary
Foundation is solid and tests are green. The two things to fix before they calcify: **(1)**
flip policy enforcement on by default (or fail-fast in prod), and **(2)** stop advertising
OAuth in the manifest until it exists. Both are cheap now and painful later.
