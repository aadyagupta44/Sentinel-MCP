"""MCP Resources — live data that Claude can read directly without calling a tool.

Resources are ideal for ambient context Claude can incorporate without
prompting: current open alerts, the watchlist, MITRE technique details.

Registered resources:
  sentinel://alerts/active           — current open alert feed
  sentinel://alerts/{alert_id}       — single alert by ID
  sentinel://mitre/{technique_id}    — MITRE ATT&CK technique detail
  sentinel://watchlist/ips           — current blocked IP list
"""

import json
from typing import Any

from sentinel.mcp.server import mcp
from sentinel.tools import mock_data as mock


@mcp.resource("sentinel://alerts/active")
async def active_alerts_resource() -> str:
    """Current open alerts — read this to see what needs investigation right now.

    Returns the live open alert feed. Refreshed on every read.
    Use this to get an overview before starting an investigation session.
    """
    alerts = mock.list_active_alerts()
    return json.dumps(
        {
            "resource": "sentinel://alerts/active",
            "count": len(alerts),
            "alerts": alerts,
            "note": "These are the currently open alerts requiring investigation.",
        },
        indent=2,
        default=str,
    )


@mcp.resource("sentinel://alerts/{alert_id}")
async def single_alert_resource(alert_id: str) -> str:
    """Full alert details for a specific alert ID.

    Same data as get_alert() but accessible as a Resource for ambient context.
    """
    alert = mock.get_alert(alert_id)
    if alert is None:
        return json.dumps(
            {
                "error": f"Alert '{alert_id}' not found",
                "available_ids": list(mock._ALERTS.keys()),
            }
        )
    return json.dumps(alert, indent=2, default=str)


@mcp.resource("sentinel://mitre/{technique_id}")
async def mitre_resource(technique_id: str) -> str:
    """MITRE ATT&CK technique detail — detection and mitigation guidance.

    Available as a Resource so Claude can read technique context while
    reviewing an alert without making a separate tool call.
    """
    from sentinel.tools.intel import _execute_mitre_technique

    result = await _execute_mitre_technique({"technique_id": technique_id})
    return json.dumps(result, indent=2, default=str)


@mcp.resource("sentinel://watchlist/ips")
async def ip_watchlist_resource() -> str:
    """Current blocked IP list — IPs that have been blocked by analysts.

    Read this to check whether an IP you're investigating has already
    been actioned by another analyst.
    """
    # Phase 2: returns mock data. Phase 4: queries Postgres block list table.
    return json.dumps(
        {
            "resource": "sentinel://watchlist/ips",
            "blocked_ips": [
                {
                    "ip": "185.220.101.34",
                    "reason": "Known Emotet C2 server (FeodoTracker)",
                    "blocked_by": "senior@acmecorp.com",
                    "blocked_at": "2026-06-02T09:30:00Z",
                }
            ],
            "note": "Phase 2 mock data. Phase 4 queries the live Postgres block list.",
        },
        indent=2,
    )
