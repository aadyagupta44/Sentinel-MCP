"""MCP server instance.

All tools, resources, and prompts are registered here.
The server is imported by main.py and mounted on the FastAPI app (HTTP)
or run directly (stdio).
"""

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    name="sentinel-mcp",
    instructions="""You are connected to Sentinel MCP, a production-grade \
SOC (Security Operations Center) server.

## Available Tools

### Investigation (read)
- get_alert — Fetch a single alert by ID with full context
- search_logs — Semantic search across all SIEM logs
- correlate_alerts — Group related alerts into incident clusters
- similar_incidents — Find historically similar past incidents

### Threat Intelligence (read)
- enrich_ioc — Enrich an IP, domain, hash, or URL across all threat intel sources
- threat_hunt — Search backwards through logs for any occurrence of an indicator
- mitre_technique — Look up a MITRE ATT&CK technique by ID

### Identity (read)
- user_context — Get full user profile from Keycloak (groups, MFA, devices)
- recent_logins — Pull login history for a user
- risk_score_user — Compute a 0–100 risk score with breakdown

### Endpoint (read)
- device_processes — Get process creation events on a host
- network_connections — Get network connection events on a host

### Reports (read)
- generate_incident_report — Full orchestrated incident report (calls multiple tools)
- weekly_summary — Past 7 days of alert statistics and trends

### Actions (write — require confirmation)
- isolate_device — Network-isolate a host via Wazuh
- disable_user — Suspend a user account in Keycloak
- block_ip — Add an IP to the block list
- kill_process — Terminate a process on a host

## Important: Write Tool Confirmation
Write tools (isolate_device, disable_user, block_ip, kill_process) require TWO calls:
1. First call returns a proposed action for your review
2. Second call with confirmed=True and the confirmation_token executes it
NEVER skip the confirmation step. Always show the proposal to the analyst first.

## All actions are logged to a tamper-evident audit trail.""",
)
