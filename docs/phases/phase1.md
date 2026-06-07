# Phase 1 — Foundation

*Documented: 2026-06-06 (retrospective)*  ·  *Status: Complete*

## Goal
Build the skeleton every later phase plugs into: typed config, database + audit, policy
enforcement, the base adapter contract, the MCP/FastAPI shell, and the full Docker stack —
nothing user-facing yet, but everything load-bearing.

## What was built
- **Packaging & deps** — `pyproject.toml` with all dependencies locked (mcp, fastapi,
  sqlalchemy[asyncio], asyncpg, pydantic(-settings), authlib/PyJWT, opentelemetry, structlog,
  httpx, tenacity, redis, opensearch-py, stix2, dnspython, anthropic). uv-managed, Python ≥3.12.
- **Config** — `sentinel/config.py`: every env var as a typed Pydantic `Settings` field
  (server/transport, DB pool, Redis, OPA, Keycloak, OpenSearch, optional services, OTel,
  `MOCK_ADAPTERS`). Single `get_settings()` cached accessor.
- **Secrets** — `sentinel/secrets.py`: `SecretsProvider` abstraction with `EnvSecretsProvider`
  today, so call sites don't change when swapping to AWS Secrets Manager later.
- **Database** — `sentinel/db/models.py`: SQLAlchemy ORM for `audit_log`, `pending_actions`,
  `threat_intel_cache`; `sentinel/db/session.py`: async engine + session factory with pooling
  and `init_db`/`close_db` lifecycle. `alembic/versions/001_initial_schema.py` initial migration.
- **Policy** — `sentinel/policy/engine.py`: OPA REST client (`/v1/data/...`) with
  **default-deny** fallback when OPA is unreachable; `is_allowed()` + `check_rate_limit()`.
  Rego in `policies/authz.rego` and `policies/rate_limit.rego` (+ `policies/data/`).
- **Base adapter** — `sentinel/adapters/base.py`: `BaseAdapter` with circuit breaker
  (CLOSED/OPEN/HALF_OPEN), retry with exponential backoff, an OpenTelemetry span per call,
  structlog request/response logging, and a mock-mode hook.
- **Audit** — `sentinel/audit/log.py`: append-only, SHA-256 hash-chained writer; writes are
  serialized with a Postgres advisory lock (`pg_advisory_xact_lock`) so the chain stays
  consistent under concurrency. Chain-integrity verifier included.
- **MCP/HTTP shell** — `sentinel/mcp/server.py` (FastMCP instance),
  `sentinel/mcp/middleware.py` (policy → execute → audit pipeline), `sentinel/main.py`
  (FastAPI app, `/health`, `/.well-known/mcp` manifest, stdio vs http entry point).
- **Infra** — `Dockerfile`, `docker-compose.yml` (Postgres, Redis, OpenSearch, OPA, Keycloak),
  `docker-compose.dev.yml`, OTel collector config, and a pre-configured Keycloak realm
  (`keycloak/realm-export.json`).

## How it works
Every request flows through one pipeline so cross-cutting concerns live in one place:

```
caller → middleware: policy check (OPA, default-deny)
                   → execute tool fn
                   → audit log (hash-chained, advisory-locked)
```

`main.py` boots a FastAPI app whose lifespan calls `init_db()`/`close_db()`; in stdio mode it
hands off to `mcp.run(transport="stdio")`, in http mode it mounts the streamable-HTTP app and
serves `/health` + `/.well-known/mcp` (see `sentinel/main.py:72` and `:86`). Adapters all
inherit `BaseAdapter` so retry/circuit-breaker/tracing is uniform (`sentinel/adapters/base.py:92`).

## Key decisions & trade-offs
- **OPA sidecar over in-process rules** — policy is declarative and hot-swappable, at the cost
  of a network hop and a hard dependency; mitigated by **default-deny** when OPA is down.
- **Hash-chained audit + advisory lock** — tamper-evidence and serialized writes, chosen over
  a plain append table; cost is that the chain's integrity is tied to Postgres availability.
- **`SecretsProvider` indirection now** — small upfront abstraction so the AWS migration in a
  later phase is a provider swap, not a refactor of every call site.
- **Mock-mode baked into the base adapter** — lets the whole stack run with zero external
  accounts; the risk (carried forward) is that "works in mock" ≠ "works against real backends".

## Problems & gotchas
See `docs/test-reports/phase1.md`. Headline items: with the shipped dev defaults
(`POLICY_ENFORCEMENT=false`) the OPA gate is bypassed, and `main.py` already advertises
`oauth2_pkce` in the manifest though auth lands in Phase 5.

## Verification
- Tests: 62/62 passing at phase close (audit chain integrity, OPA evaluation, base-adapter
  circuit breaker, `/health`).
- Coverage: 82% (at phase close).
- `docker compose up` brings the stack up; `GET /health` → 200; `GET /.well-known/mcp` →
  manifest JSON.

## Deferred to later phases
Real tools and adapter integrations (Phases 2–4), OAuth 2.1 + PKCE and HTTP transport
hardening (Phase 5), full OTel/structlog wiring and the security audit (Phase 7).
