# Phase 5 — Auth (OAuth 2.1 + PKCE) + HTTP Transport

*Documented: 2026-06-06*  ·  *Status: Complete — MCP-over-HTTP transport auth-guarded but not yet driven end-to-end (see deferred)*

## Goal
Put real authentication in front of the HTTP transport: an OAuth 2.1 + PKCE flow against
Keycloak, RS256 JWT validation on every call, and a scope+role authorization layer — so the MCP
manifest's `oauth2_pkce` advertisement is honest and every tool call over HTTP is attributed to a
real analyst identity (`analyst_id == JWT sub`) in the audit log. stdio stays the trusted, no-auth
local path.

## What was built
- **New `sentinel/auth/` package** (previously empty):
  - `pkce.py` — `generate_code_verifier` (URL-safe, 43–128 chars), `code_challenge_s256`,
    `generate_state` (CSRF) per RFC 7636 (`pkce.py:19-32`).
  - `oauth.py` — `OAuthClient`: `authorization_url()` builds the OAuth 2.1 + PKCE auth URL
    (`oauth.py:24-43`); `exchange_code()` POSTs code+verifier to Keycloak's token endpoint and
    returns tokens, or a structured `{error,...}` on non-200 (`oauth.py:45-78`). Sends
    `client_secret` only if configured (public PKCE clients send none, `oauth.py:61-62`).
  - `jwt.py` — `JWTValidator`: fetches Keycloak JWKS via httpx (`jwt.py:32-38`), resolves the
    signing key by `kid` with a one-shot refresh on miss (`jwt.py:43-58`), validates RS256
    signature + issuer + expiry (+ optional audience, `jwt.py:60-77`), and derives a `Principal`
    — `analyst_id = sub`, role from `realm_access.roles` with `admin>senior_analyst>analyst`
    precedence, scopes from the `scope` claim (`jwt.py:84-92`).
  - `context.py` — request-scoped `Principal` `ContextVar` (`set_/get_/reset_current_principal`).
  - `authz.py` — scope+role authorization mirroring `policies/authz.rego`: read tools need
    `soc:read`, write tools need `soc:write` **and** `senior_analyst`/`admin`; returns stable
    machine reason codes (`authz.py:54-66`).
  - `dependencies.py` — FastAPI `require_principal` (401 on missing/invalid Bearer) +
    `extract_bearer`.
- **`sentinel/config.py`** — added `oauth_client_secret`, `oauth_redirect_uri`, `oauth_audience`,
  `oauth_default_scopes` (`config.py:43-47`) and `oidc_issuer/authorize/token/jwks` derived
  endpoint properties (`config.py:136-148`).
- **`sentinel/main.py`** — the HTTP app gained: `/auth/login` (returns auth URL + verifier +
  state, `main.py:192-204`) and `/auth/token` (`main.py:207-224`); `/.well-known/mcp` now
  advertises `oauth2_pkce` with the authorize/token endpoints + scopes (`main.py:151-172`) and a
  new `/.well-known/oauth-authorization-server` metadata doc (`main.py:175-186`); an
  authenticated REST tool surface `POST /tools/{name}` (401/403/404/200, `main.py:230-257`); and
  a pure-ASGI `McpAuthMiddleware` guarding `/mcp` — 401 without a valid Bearer, binds the
  principal otherwise (`main.py:70-110`).
- **`sentinel/mcp/middleware.py`** — `run_middleware` now reads the request-scoped principal from
  the ContextVar: on HTTP `analyst_id = sub` / `role` from the JWT; on stdio it falls back to the
  static settings identity (`middleware.py:42-48`).
- **Tests:** `tests/unit/test_auth/` (`test_pkce`, `test_authz`, `test_jwt` with respx-mocked
  JWKS, `test_oauth`) + `tests/integration/test_auth_http.py` (full OAuth flow, 401/403/404,
  `analyst_id==sub` in the audit entry, `/mcp` 401, manifest). JWT/key fixtures added to
  `tests/conftest.py`. +37 tests.

## How it works
Two transports, two security postures:

```
stdio  → mcp.run()                → no auth, static settings identity        (trusted local)
HTTP   → FastAPI app
          /auth/login  ─▶ PKCE verifier+challenge+state, authorization_url
          /auth/token  ─▶ OAuthClient.exchange_code() ─▶ Keycloak ─▶ tokens
          POST /tools/{name}
            ├─ require_principal (Depends) ── JWTValidator ─▶ Principal(sub,role,scopes)
            ├─ authorize(principal, tool)  ── scope+role gate → 403/404
            └─ set_current_principal ─▶ mcp.call_tool ─▶ run_middleware (OPA + audit on sub)
          /mcp (streamable-HTTP)
            └─ McpAuthMiddleware (ASGI) ── valid Bearer? → bind principal | 401
```

The REST `/tools/{name}` path is the **fully exercised** authenticated surface: it validates the
JWT (`require_principal`), runs the code-level `authorize()` scope+role check, binds the principal
into the ContextVar, then dispatches through `mcp.call_tool`. Inside, `run_middleware` reads that
same principal so the OPA check and the audit row are keyed on the JWT `sub` (`middleware.py:46-47`)
— the test asserts the audit entry's `analyst_id == sub` (`test_auth_http.py:84-86`).

The `/mcp` mount (`main.py:262-263`, only when `MCP_TRANSPORT=http`) is wrapped by a pure-ASGI
guard rather than a FastAPI dependency so the principal `ContextVar` survives across the
streamable-HTTP machinery. It validates the Bearer and binds the principal, returning 401 with
`WWW-Authenticate: Bearer` if absent/invalid (`main.py:94-104`).

## Key decisions & trade-offs
- **Two authz layers (code + OPA), code mirrors rego** — `auth/authz.py` re-implements the rego
  rules so the HTTP layer fails fast and deterministically even if the OPA sidecar is down, with
  OPA kept as defence-in-depth inside the middleware. Cost: **two sources of truth** that can
  drift; they already differ in model (`authz.py` requires an OAuth *scope* on top of the role;
  `authz.rego` is role-only — so the HTTP layer is strictly tighter and OPA can't see scopes).
  Flagged High in the risk report.
- **PKCE flow split into `/auth/login` + `/auth/token`, no server-side session** — the server
  hands the `code_verifier` back to the caller, who holds it and posts it back with the `code`.
  Keeps the server stateless (no session store for the verifier). Cost: the caller must keep the
  verifier; there's no callback handler that completes the flow server-side.
- **Pure-ASGI middleware for `/mcp`, FastAPI `Depends` for `/tools/{name}`** — the streamable-HTTP
  app is mounted as a sub-app, so a FastAPI dependency wouldn't reliably run / preserve the
  principal ContextVar across it; a raw ASGI guard does. Cost: the ASGI guard only knows the
  *path*, not the tool name, so it can validate the JWT but **cannot** run the per-tool
  `authorize()` scope check — over `/mcp`, scope/role enforcement falls to OPA alone (role-only).
- **JWKS cached on the validator singleton with one-shot refresh on unknown `kid`** — cheap and
  handles the common "new key added" rotation. Cost: no TTL, so a rotated-*out* key stays trusted
  until process restart, and no single-flight lock on the refresh. Risk-reported Medium.
- **stdio stays unauthenticated by design** — Claude Desktop launches the server as a trusted
  local stdio child; adding OAuth there would break the local UX. Documented in `main.py:3-7`.
  Cost: the stdio path has no auth, so it must never be exposed remotely.
- **Auth-package-and-tests only, no tool/adapter changes** — the only non-auth source edits are
  the config additions, the `main.py` HTTP surface, and the `run_middleware` principal lookup;
  the 18 tools and 15 adapters are untouched.

## Problems & gotchas
From `docs/test-reports/phase5.md`:
- **`/mcp` transport unproven end-to-end (High):** the headline MCP-over-HTTP path is only
  401-guarded; no test opens a streamable-HTTP session and runs a real `tools/call`. The
  *authenticated* surface that tests actually exercise is the REST `POST /tools/{name}`. This is
  the main gap.
- **Two authz sources can drift (High):** `auth/authz.py` (scope+role) vs `policies/authz.rego`
  (role-only) duplicate the tool lists and disagree on the scope model — a maintenance hazard and
  a latent gap on the `/mcp` path.
- **`/mcp` skips `authorize()` (Medium):** scope-based access control is enforced on
  `/tools/{name}` but not on the real MCP transport (the ASGI guard can't see the tool name); OPA
  role rules still deny analyst writes, but the advertised `soc:read`/`soc:write` scopes aren't
  enforced there.
- **JWKS has no TTL (Medium):** module-singleton cache, refresh only on unknown `kid`; rotated-out
  keys stay trusted until restart, and concurrent unknown-`kid` requests can stampede Keycloak.
- **Auth runs only against respx-mocked Keycloak (Low):** no real OIDC realm hit — issuer/redirect/
  audience/version mismatches won't surface until a live realm is wired (same mock-vs-real caveat
  as Phases 3–4).
- **Carried forward, still unfixed:** `enrich_ioc`/`risk_score_user` mock-only (Phase 4),
  `weekly_summary` live-shape mismatch (Phase 4), breaker-vs-5xx (Phase 3).

## Verification
- Tests: 447/447 passing (`uv run pytest -q`); +37 vs Phase 4.
- Coverage: **94.96%** total (real, this run); `auth/` package 95–100% (`pkce`/`authz`/`context`
  100%, `jwt` 98%, `oauth` 97%, `dependencies` 95%). `--cov-fail-under=80` gate passes.
- Lint/type: `ruff` and `mypy` **clean on `sentinel/auth/`** (mypy: "no issues found in 7 source
  files"). 9 ruff issues remain elsewhere in `sentinel/` (`mcp/`, `main.py`) and 38 in non-Phase-5
  `tests/` — pre-existing. `mypy sentinel/` = 60 errors (8 now in `main.py`, +7 from the new HTTP
  tool surface — the `content[0].text` union-attr/index class) — deferred to Phase 7. Boots:
  `import sentinel.main` → OK.

## Deferred to later phases
End-to-end MCP-over-HTTP exercise through the `/mcp` streamable session (the headline transport
gap); unifying the two authz sources (`authz.py` ↔ `authz.rego`) and enforcing the scope check on
`/mcp` not just REST; a TTL + single-flight refresh on the JWKS cache; token-refresh handling and a
server-side OAuth callback; the opt-in live auth smoke test against the bundled Keycloak realm
export. Carried over: live `enrich_ioc`/`risk_score_user` composition and the `weekly_summary`
live-shape fix (Phase 6+); breaker-vs-5xx and the mypy/lint debt (Phase 7 hardening).
