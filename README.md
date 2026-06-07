# sentinel-mcp

Production-grade SOC MCP Server for Claude Desktop. A secure, policy-enforced bridge between Claude and your security toolstack — alerts, threat intel, identity, and endpoint data, all without leaving Claude Desktop.

> Full documentation is written in Phase 7 (hardening). This is a placeholder.

## Current Status

**Phase 6 — Simulator (synthetic security events) ✅ Complete**

A standalone `simulator/` package now generates realistic SOC telemetry to investigate: 10
employees across 5 departments, four event factories (login / file-access / process / network),
and five adversarial scenarios (`impossible_travel`, `brute_force`, `suspicious_process`,
`data_exfiltration`, `known_bad_ip`) that use real abuse.ch C2 IPs and malware hashes. Each
scenario stamps a shared user/host/source-IP across its logs and alert, so the live
`correlate_alerts` clusters them into one incident. Every doc is tagged `"simulated": True`. A
`NormalBot` and `AdversarialBot` run concurrently via `python -m simulator.main`
(`--duration/--seed/--dry-run` + interval flags); RNG and `sleep`/`clock` are injectable for
reproducible, time-free tests. Full suite 478/478 passing at 94.97% total coverage; `simulator/`
is clean on both ruff and mypy.

Caveats: the 94.97% coverage is `sentinel/`-only — `simulator/` is not in the coverage source, so
it is tested but ungated. Live OpenSearch ingestion is unexercised (all tests use the in-memory
sink / mock adapters); on a live stack the sink writes logs to `sentinel-logs` while `search_logs`
reads `sentinel-logs-*`, an index-name match to verify. Carried-forward gaps: `enrich_ioc`/
`risk_score_user` mock-only, `weekly_summary` live-shape mismatch, `/mcp` not yet driven
end-to-end, no real backend hit yet.

Next: Phase 7 — Hardening (input sanitization, full observability, security audit, docs)

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

These are produced by the `phase-runner` agent (`.claude/agents/`) which runs the
`phase-test` and `phase-docs` skills (`.claude/skills/`) after each phase completes.
