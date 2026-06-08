# sentinel-mcp

Production-grade SOC MCP Server for Claude Desktop. A secure, policy-enforced bridge between Claude and your security toolstack — alerts, threat intel, identity, and endpoint data, all without leaving Claude Desktop.

## Current Status

**Phase 8 — Marketplace Prep & v1.0.0 Release ✅ COMPLETE**

Production-ready release. All 497 tests passing (95.42% coverage, gate target 80%). Security audit complete: no critical/high issues, 4 low-severity findings documented. All 18 tools implemented (14 read, 4 write with two-step confirmation). 15 adapters with circuit breaker, retry, and OTel spans. OAuth 2.1 + PKCE auth, role-based rate limiting, immutable audit log. Documentation complete (phase journey docs, risk reports, CONTRIBUTING, SECURITY, RELEASE notes). v1.0.0 tagged and ready for Claude/Anthropic MCP marketplace publication.

**Full suite: 497/497 tests ✅ · Coverage: 95.42% ✅ · Security audit ✅ · v1.0.0 tagged ✅**

**Known Phase 4 limitations (documented in test report):** `enrich_ioc`, `risk_score_user`, `weekly_summary` are curated-mock stubs; live adapter implementation deferred to Phase 9. All tools are functional and tested in mock mode.

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
| 8 — Marketplace Prep & v1.0.0 | [docs/phases/phase8.md](docs/phases/phase8.md) | [docs/test-reports/phase8.md](docs/test-reports/phase8.md) |

These are produced by the `phase-runner` agent (`.claude/agents/`) which runs the
`phase-test` and `phase-docs` skills (`.claude/skills/`) after each phase completes.
