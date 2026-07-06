---
title: Sentinel MCP
emoji: 🛡️
colorFrom: blue
colorTo: green
sdk: docker
app_port: 7860
pinned: false
short_description: A production-grade SOC MCP server for Claude (live demo).
---

# Sentinel MCP — live demo

A production-grade **Model Context Protocol** server that gives Claude secure,
policy-enforced access to a Security Operations Center toolstack (SIEM, threat
intel, identity, EDR).

This Space runs the **full stack** — the MCP server, a self-hosted **Keycloak**
OAuth 2.1 provider, Postgres, Redis and OPA — all in one container. It runs in
**demo mode**: OAuth login, per-analyst roles, rate limiting and the
tamper-evident audit chain are all **real**; only the tool *data* is simulated,
so no real credentials or security telemetry are exposed.

## Try it
- Landing page: the root URL of this Space.
- Manifest: `/.well-known/mcp` · Health: `/health`
- Connect in Claude Desktop → **Settings → Connectors → Add custom connector** →
  `https://<this-space-host>/mcp`, then log in:
  - `analyst` / `analyst123` — role *analyst* (read & enrich)
  - `senior` / `senior123` — role *senior_analyst* (can take actions)

As **analyst**, asking Claude to isolate a host is **denied**; as **senior** it's
**allowed** and written to the audit log.

> First load after the Space has been idle takes ~2 minutes while Keycloak boots.

Source & full self-host guide: see the GitHub repository.
