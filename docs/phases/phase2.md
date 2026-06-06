# Phase 2 — MCP Server + Placeholder Tools

*Documented: 2026-06-06 (retrospective)*  ·  *Status: Complete*

## Goal
Wire the full MCP protocol end to end — tool/resource/prompt registries plus the middleware
pipeline — and prove it with three real, mock-backed tools and the two-step write framework.

## What was built
- **Full registry wiring** — `sentinel/mcp/server.py` exposes the FastMCP instance; all 18
  tools register via `@mcp.tool()`, 4 resources via `@mcp.resource()`, 3 prompts via
  `@mcp.prompt()` (triggered by imports in `sentinel/main.py:25`).
- **Middleware on every call** — `sentinel/mcp/middleware.py` runs sanitise → policy → rate
  limit → execute → audit for each tool invocation.
- **Three working tools (mock data)** — `get_alert` (`sentinel/tools/alerts.py`),
  `user_context` (`sentinel/tools/identity.py`), `enrich_ioc` (`sentinel/tools/intel.py`),
  all served from `sentinel/tools/mock_data.py` (3 employees, 3 alerts, 4 IOCs).
- **Write tools w/ two-step confirmation** — `isolate_device`, `disable_user`, `block_ip`,
  `kill_process` in `sentinel/tools/actions.py`, backed by
  `sentinel/tools/confirmation.py` (Postgres `PendingAction` + in-memory fallback, token TTL).
- **11 registered stubs** — the remaining read/report tools return a structured
  `{"status": "not_yet_implemented", "phase": ...}` so the contract exists ahead of Phase 3/4.
- **Resources** — `sentinel://alerts/active`, `sentinel://alerts/{alert_id}`,
  `sentinel://mitre/{technique_id}`, `sentinel://watchlist/ips` (`sentinel/mcp/resources.py`).
- **Prompts** — `investigate_alert`, `triage_user`, `morning_briefing` (`sentinel/mcp/prompts.py`).
- **Rate limiting** — Redis-backed counters keyed by tool+user, enforced inside the middleware.

## How it works
```
Claude Desktop ──stdio──► FastMCP
   tool call → middleware: sanitise inputs
                         → OPA policy check (skipped if POLICY_ENFORCEMENT=false)
                         → Redis rate-limit check
                         → execute tool (mock_data for the 3 live tools)
                         → write hash-chained audit row
```
Write tools are stateful: the first call returns a proposal + token; the second call replays
the token to `execute_confirmed()`, which validates TTL/ownership before running the (mock)
action (`sentinel/tools/confirmation.py`). Resources give Claude ambient context without a
tool call; prompts are reusable investigation playbooks.

## Key decisions & trade-offs
- **Register all 18 tools now, stub the unfinished 11** — the MCP contract is stable from
  Phase 2, but a Claude Desktop user can *see and call* tools that only return
  `not_yet_implemented` (tracked as a UX risk in the test report).
- **Token-based two-step confirmation, stateful** — prevents accidental destructive actions;
  cost is shared state (Postgres, or the in-memory fallback that doesn't survive restarts or
  span processes).
- **Mock data factory as the tool backend** — deterministic tests and zero external accounts;
  the trade-off is that "working" here means "works against fixtures", not real systems.
- **Resources + Prompts included early** — richer Claude UX from the start, slightly more
  surface to keep honest as real data lands later.

## Problems & gotchas
See `docs/test-reports/phase2.md`. Headline items: the rate limiter silently disables itself
if Redis is unavailable; the in-memory confirmation fallback loses tokens across
restarts/processes; and 11 advertised tools are stubs.

## Verification
- Tests: 131/131 passing at phase close (unit + MCP protocol integration).
- Coverage: 85% (at phase close).
- Manual: connect Claude Desktop via stdio → `get_alert("ALT-2026-001")` returns a structured
  alert; two sequential audited calls show `row[2].prev_hash == row[1].row_hash` in
  `audit_log`.

## Deferred to later phases
Real adapter integrations + unit tests (Phase 3), implementing the 11 stubbed tools (Phase 4),
OAuth/PKCE + HTTP transport (Phase 5).
