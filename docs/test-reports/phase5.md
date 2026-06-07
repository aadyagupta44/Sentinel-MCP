# Phase 5 — Breakage & Risk Report

*Run: 2026-06-06*  ·  *Scope: cumulative through Phase 5 (OAuth 2.1 + PKCE auth + HTTP transport)*

## Baseline
- Tests: 447/447 passing (0 failed). +37 vs Phase 4 (410); the new files are
  `tests/unit/test_auth/` (`test_pkce.py`, `test_authz.py`, `test_jwt.py` with respx-mocked
  JWKS, `test_oauth.py`) and `tests/integration/test_auth_http.py` (full OAuth flow,
  401/403/404, `analyst_id==sub` in audit, `/mcp` 401, manifest) — plus JWT/key fixtures
  in `tests/conftest.py`.
- Coverage: 94.96% (`--cov-fail-under=80` gate **green**, ~unchanged from 95.06%).
  - New auth package strong: `auth/pkce.py` 100%, `auth/authz.py` 100%, `auth/context.py`
    100%, `auth/oauth.py` 97%, `auth/jwt.py` 98%, `auth/dependencies.py` 95%.
  - Low-coverage modules are all pre-Phase-5 infra: `audit/log.py` 48%, `db/session.py` 65%,
    `mcp/middleware.py` 72% (the new HTTP-principal branch `:153-175` is the Redis fallback,
    not the auth path), `main.py` 79%, `mcp/resources.py` 82%, `policy/engine.py` 82%.
- Lint: `sentinel/auth/` **clean** (`ruff check`). Elsewhere: `ruff check sentinel/` = 9 issues
  (in `mcp/`, `main.py`, `tools/schemas` — pre-existing import-sort + E501, outside Phase 5
  scope), `ruff check tests/` = 38 issues (pre-existing in non-Phase-5 test dirs).
- Type: `mypy sentinel/` = 60 errors across 20 files (was 55 in Phase 4). `sentinel/auth/` is
  **clean** (`mypy sentinel/auth/` → "no issues found in 7 source files"). The +5 net is in
  `main.py` (1 → 8): the new `/tools/{name}` `content[0].text` indexing against FastMCP's
  `TextContent | ImageContent | ...` union (`main.py:257`, 6 errors) and an untyped lifespan
  signature (`main.py:53`). Deferred to Phase 7 (hardening) per plan.
- Boots: yes — `MOCK_ADAPTERS=true uv run python -c "import sentinel.main"` → `BOOTS_OK`.

## Findings
Ordered by severity.

### [SEV: High] The MCP streamable transport at `/mcp` is only auth-*guarded*, never exercised end-to-end
- **Where:** `sentinel/main.py:70-110` (`McpAuthMiddleware`), `:262-263` (mount),
  `tests/integration/test_auth_http.py:135-139`
- **What breaks:** The authenticated tool surface that *tests* prove works is the REST
  `POST /tools/{name}` (`main.py:230-257`). The real MCP-over-HTTP transport mounted at `/mcp`
  is protected by a pure-ASGI bearer guard that returns 401 without a valid token — but the only
  `/mcp` test asserts the **401** (`test_mcp_requires_bearer`). No test drives an actual MCP
  `tools/call` through the streamable-HTTP session (initialize → call → result), so the path a
  real Claude Desktop client uses is unverified: principal propagation through
  `streamable_http_app()` into `run_middleware`, session handling, and JSON-RPC framing have
  never run in the suite.
- **Repro:** Source + test inspection; the streamable session is never opened in any test.
- **Impact:** The headline "MCP over HTTP" deliverable is auth-gated but not functionally
  proven. A client that authenticates successfully could still fail at the transport/session
  layer, and that would not be caught by the green suite. This is the **main gap** of Phase 5.
- **Suggested fix:** Add an integration test that opens a streamable-HTTP MCP session with a
  valid Bearer, runs `initialize` + a `tools/call`, and asserts the result + an audit row keyed
  on the JWT `sub` — i.e. extend the `/mcp` coverage from "401 without token" to "works with one".

### [SEV: High] Two sources of truth for authorization can drift (`auth/authz.py` vs `policies/authz.rego`)
- **Where:** `sentinel/auth/authz.py:16-66` and `policies/authz.rego:9-80`
- **What breaks:** Authorization is enforced **twice**: the HTTP layer's code-level `authorize()`
  (scope + role) runs in `/tools/{name}` before dispatch, and OPA's rego runs again inside
  `run_middleware`. The two encode the rule set independently — the tool name lists
  (`READ_TOOLS`/`WRITE_TOOLS` vs `read_tools`/`write_tools`) are duplicated by hand, and they
  already **disagree on model**: `authz.py` requires an OAuth *scope* (`soc:read`/`soc:write`)
  **in addition** to the role, while `authz.rego` keys on *role only* and has no concept of
  scope. So a token with `role=analyst` but no `soc:read` scope is denied 403 by the HTTP layer
  yet would be *allowed* by OPA — today the HTTP layer is strictly tighter, but any future tool
  added to one list and not the other (or a scope rule added to rego) silently diverges.
- **Repro:** Source-confirmed: rego allow rules (`authz.rego:36-71`) test only `input.role`;
  `authorize()` (`authz.py:60`) additionally calls `principal.has_scope(...)`.
- **Impact:** Maintenance hazard / latent authz bug. Two lists to keep in sync; the stricter
  layer (HTTP scope check) is also the one OPA can't see, so disabling the HTTP path (e.g. the
  `/mcp` transport, which only validates the JWT and does **not** call `authorize()`) drops the
  scope check entirely and falls back to role-only OPA.
- **Suggested fix:** Pick one source of truth — either pass `scopes` into the OPA input and
  delete the rego role-only rules' implicit allow, or generate both lists from a shared
  constant. At minimum, run `authorize()` (or feed scopes to OPA) on the `/mcp` path too.
- **✅ Resolved:** `run_middleware` now calls `auth.authz.authorize()` for any request with a JWT
  principal — so the code-level scope+role gate is the authoritative check on **every** transport
  (`/tools/{name}` and `/mcp`), and OPA's rego is now strictly defence-in-depth. A drift in the
  rego can no longer open a hole because `authorize()` (the stricter, scope-aware gate) always
  runs first. Covered by `tests/unit/test_mcp/test_middleware.py::TestPrincipalAuthorization`.
  (Generating the two tool lists from one shared constant remains a nice-to-have.)

### [SEV: Medium] `/mcp` transport skips the scope/role `authorize()` check entirely
- **Where:** `sentinel/main.py:76-110` (`McpAuthMiddleware`) vs `:237` (`/tools/{name}` calls
  `authorize()`)
- **What breaks:** `McpAuthMiddleware` validates the JWT and binds the principal, but never
  calls `authorize(principal, tool_name)` — it can't, because at the ASGI layer the tool name
  isn't known yet (it's inside the JSON-RPC body). So over `/mcp`, the only gate before
  `run_middleware` is "valid token present"; the per-tool scope check (`soc:read`/`soc:write`)
  and the write-role check (`senior_analyst`/`admin`) are enforced **only** by OPA inside the
  middleware — and OPA, per the drift finding above, doesn't check scopes at all. Net: an
  authenticated `analyst` token *without* `soc:write` could reach a write tool over `/mcp` and
  be stopped only by OPA's role rule (which does deny analyst writes), but the **scope**
  requirement the manifest advertises is not enforced on the transport clients actually use.
- **Repro:** Source-confirmed; `authorize()` appears only in the REST handler, not the ASGI
  guard.
- **Impact:** The scope model is enforced on the REST convenience surface but not on the real
  MCP transport. Role-based denial still works (via OPA), so this is not an open write hole, but
  the advertised scope-based access control is effectively REST-only.
- **Suggested fix:** Enforce `authorize()` inside `run_middleware` (where the tool name is
  known and the principal is already in the ContextVar) so both transports share one gate.
- **✅ Resolved:** `authorize()` is now enforced inside `run_middleware`, where the tool name and
  the ContextVar principal are both available — so the scope (`soc:read`/`soc:write`) and
  write-role checks now apply to the `/mcp` transport too, not just REST. Covered by
  `tests/unit/test_mcp/test_middleware.py::TestPrincipalAuthorization`.

### [SEV: Medium] JWKS is cached for the process lifetime with no TTL — only a one-shot refresh on unknown `kid`
- **Where:** `sentinel/auth/jwt.py:32-58`
- **What breaks:** `_get_jwks()` fetches the Keycloak JWKS once and caches it on the validator
  instance forever (`self._jwks`). The only invalidation is `_signing_key()`'s single
  refresh-and-retry when a token's `kid` isn't in the cached set (`jwt.py:53-57`). There is no
  time-based expiry, so a *removed* key (rotated out) stays trusted until the process restarts,
  and the validator is a module-level singleton (`get_jwt_validator()`), so the stale cache is
  shared by every request. The refresh also has no backoff/lock — a burst of tokens with a new
  `kid` can stampede the JWKS endpoint.
- **Repro:** Source-confirmed; no `expires_at`/`max_age` on the cache.
- **Impact:** Correct for the common "new key added" rotation, but a security/availability edge:
  revoked-key tokens validate until restart; concurrent unknown-`kid` requests can hammer
  Keycloak. Real Keycloak is never hit in tests (respx-mocked), so the live refresh behaviour is
  unverified.
- **Suggested fix:** Add a short TTL (e.g. 5–15 min) to the JWKS cache and a single-flight lock
  around the refetch; add a test that a rotated-out key is rejected after TTL.
- **✅ Resolved:** the JWKS cache now has a 10-minute TTL and a single-flight `asyncio.Lock`
  around the refetch (so a burst of unknown-`kid` tokens can't stampede Keycloak). After the TTL
  the keyset is refetched, so a rotated-out key is rejected. Covered by
  `tests/unit/test_auth/test_jwt.py::TestJWKSCacheTTL`.

### [SEV: Low] HTTP-transport auth runs only against respx-mocked Keycloak — no real OIDC hit
- **Where:** `tests/integration/test_auth_http.py:26-33`, `tests/unit/test_auth/test_jwt.py`
- **What breaks:** Every auth test signs tokens with a local test key and respx-mocks the JWKS
  and token endpoints. The whole flow — `authorization_url` shape, `exchange_code` form encoding,
  RS256 verification, issuer/audience matching — is asserted against a stand-in, never a running
  Keycloak. Same mock-vs-real caveat carried from Phases 3–4, now extended to auth.
- **Repro:** Test inspection.
- **Impact:** Issuer/redirect/audience/realm mismatches and Keycloak-version quirks won't
  surface until someone points it at a real realm. Pre-release verification item.
- **Suggested fix:** Add an opt-in live auth smoke test against the bundled Keycloak realm
  export, alongside the deferred live adapter suite.

### [SEV: Low] `main.py` mypy debt grew with the HTTP tool surface
- **Where:** `sentinel/main.py:53,257` (8 of the 60 total `mypy` errors; was 1 in Phase 4)
- **What breaks:** `content[0].text` indexes FastMCP's `TextContent | ImageContent |
  AudioContent | ResourceLink | EmbeddedResource` union and a `dict[str, Any]` with an `int`
  (`union-attr` + `index`), plus the untyped lifespan signature. No runtime effect — the
  `/tools/{name}` test proves the JSON parse works — but strict-typing debt.
- **Impact:** Type-safety debt; deferred to Phase 7 per plan, consistent with the tool/adapter
  debt.
- **Suggested fix:** Narrow the result to `TextContent` (assert/`isinstance`) before `.text`, or
  use FastMCP's typed result accessor; annotate `lifespan`.

## User-facing problems
- **stdio = no auth (by design, but verify it's documented).** `main.py:3-7` and
  `middleware.py:42-48` state stdio is a "trusted local process" using the static settings
  identity, with auth only on HTTP. This is the intended model for Claude Desktop's local stdio
  launch, but a deployer who exposes the stdio path remotely would have **no** authentication.
  The docstrings say it; ensure the README/quickstart say it too so it isn't a surprise.
- **`POLICY_ENFORCEMENT` default + the no-auth stdio path interact.** On stdio with policy
  enforcement off (the documented test default), there is neither auth *nor* OPA gating — fine
  for local dev, but the security posture flips entirely between stdio-dev and http-prod. Worth a
  one-line "security model" note so the difference is explicit, not implicit.
- **Two flagship tools remain mock-only (carried from Phase 4):** `enrich_ioc` and
  `risk_score_user` still return curated `mock_data` composites regardless of `MOCK_ADAPTERS`;
  auth now gates *who* can call them, but not *what they return*.
- **Lint/type noise outside `auth/`** (9 ruff in `sentinel/`, 38 in `tests/`, 60 mypy) is
  pre-existing but will surprise anyone running the documented `ruff`/`mypy` commands expecting
  clean output. Track for the Phase 7 cleanup.

## Mock-vs-real gaps
- JWT validation, JWKS fetch, and token exchange run only against respx-mocked Keycloak — no real
  realm hit (Low above). The JWKS cache has no TTL, so live key rotation is untested (Medium).
- The `/mcp` streamable transport is auth-guarded but the actual MCP session/tool-call path is
  never run end-to-end (High above).
- Scope-based access control is enforced on `/tools/{name}` but **not** on `/mcp` (Medium) and
  not by OPA (drift, High) — the advertised `soc:read`/`soc:write` model is REST-surface-only.
- Carry-forward, still unfixed: `enrich_ioc`/`risk_score_user` mock-only (Phase 4),
  `weekly_summary` live-shape mismatch (Phase 4 — `opensearch.py:159-160` returns
  `{raw_aggregations}` not `{total,by_severity,open,closed}`), breaker-vs-5xx
  (`adapters/base.py:132-152`, Phase 3). No real OpenSearch/Keycloak/Wazuh has ever been hit.

## Summary
Phase 5 hits its headline goal: a real OAuth 2.1 + PKCE flow against Keycloak, RS256 JWT
validation deriving a `sub`-keyed Principal, a scope+role authz layer, and an authenticated HTTP
surface — 447 tests green, 94.96% coverage, `auth/` clean on both ruff and mypy, and the four
acceptance criteria (full flow, no-token 401, missing-scope 403, analyst-write 403) all proven.
The catch: what's *tested* is the REST `/tools/{name}` surface; the actual MCP-over-HTTP
transport at `/mcp` is only 401-guarded, never driven end-to-end. Top 3 to fix next: **(1)**
exercise a real MCP `tools/call` through the `/mcp` streamable session with a Bearer (the
headline transport is unproven); **(2)** unify the two authz sources (`authz.py` scope+role vs
`authz.rego` role-only) and enforce the scope check on `/mcp`, not just REST; **(3)** give the
JWKS cache a TTL + single-flight refresh. None block *documenting* Phase 5, but (1) is a blocker
for claiming MCP-over-HTTP actually works for a real Claude Desktop client.
