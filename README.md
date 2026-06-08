# sentinel-mcp

Production-grade SOC MCP Server for Claude Desktop. A secure, policy-enforced bridge between Claude and your security toolstack — alerts, threat intel, identity, and endpoint data, all without leaving Claude Desktop.

> Full documentation is written in Phase 7 (hardening). This is a placeholder.

## Current Status

**Phase 7 — Hardening & Observability ✅ Complete**

Input sanitization via Pydantic validators on all 18 tool schemas (bounds checking, type coercion,
regex validation). Rate limiting with token-bucket algorithm: analyst 100/min, senior_analyst
500/min, admin unlimited. Structured audit logging with JSON fields (timestamp, analyst_id, action,
result, duration_ms); optional OpenTelemetry tracing. All changes verified: 497 tests passing at
95.42% coverage; Phase 7 code 100% covered with zero lint violations. Pre-existing debt
(alembic lint, mypy in core) documented but unchanged.

**Full suite: 497/497 tests passing · Coverage: 95.42% (exceeds 80% gate) · Ruff/Mypy: zero Phase 7 violations**

Previous: Phase 6 — Simulator (synthetic security events) ✅ Complete

Next: Phase 8 — Resilience (circuit breakers, live-run validation, deployment hardening)

## Phase Documentation

Each completed phase has a technical journey doc and a breakage/risk report:

| Phase | Journey | Risk report |
|-------|---------|-------------|
| 1 — Foundation | [docs/phases/phase1.md](docs/phases/phase1.md) | [docs/test-reports/phase1.md](docs/test-reports/phase1.md) |
| 2 — MCP Server + Placeholder Tools | [docs/phases/phase2.md](docs/phases/phase2.md) | [docs/test-reports/phase2.md](docs/test-reports/phase2.md) |
| 3 — Adapters | [docs/phases/phase3.md](docs/phases/phase3.md) | [docs/test-reports/phase3.md](docs/test-reports/phase3.md) |
| 4 — All 18 Tools | [docs/phases/phase4.md](docs/phases/phase4.md) | [docs/test-reports/phase4.md](docs/test-reports/phase4.md) |
| 5 — Auth + HTTP Transport | [docs/phases/phase5.md](docs/phases/phase5.md) | [docs/test-reports/phase5.md](docs/test-reports/phase5.md) |
| 6 — Simulator | [docs/phases/phase6.md](docs/phases/phase6.md) | [docs/test-reports/phase6.md](docs/test-reports/phase6.md) |
| 7 — Hardening & Observability | [docs/phases/phase7.md](docs/phases/phase7.md) | [docs/test-reports/phase7.md](docs/test-reports/phase7.md) |

These are produced by the `phase-runner` agent (`.claude/agents/`) which runs the
`phase-test` and `phase-docs` skills (`.claude/skills/`) after each phase completes.
