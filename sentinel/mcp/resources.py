"""MCP Resources — live data that Claude can read directly without calling a tool.

Resources are ideal for ambient context Claude can incorporate without
prompting: current open alerts, the watchlist, MITRE technique details.

Registered resources:
  sentinel://alerts/active           — current open alert feed
  sentinel://alerts/{alert_id}       — single alert by ID
  sentinel://mitre/{technique_id}    — MITRE ATT&CK technique detail
  sentinel://watchlist/ips           — current blocked IP list
  sentinel://audit/integrity         — tamper-evident audit chain verification
"""

import json

from sentinel.mcp.server import mcp
from sentinel.tools import mock_data as mock


@mcp.resource("sentinel://audit/integrity")
async def audit_integrity_resource() -> str:
    """Verify the tamper-evident audit log without needing psql/SQL.

    Walks the entire hash-chained audit log and recomputes every row's hash.
    Returns whether the chain is intact, how many rows were checked, and — if
    tampering is detected — the row id where the chain first breaks. This is the
    read-only, self-service answer to "has anyone altered the audit trail?".
    """
    from sentinel.audit.log import verify_chain_integrity
    from sentinel.db.session import get_session_factory

    try:
        factory = get_session_factory()
        async with factory() as session:
            is_valid, rows_checked, error = await verify_chain_integrity(session)
    except Exception as exc:
        return json.dumps(
            {
                "resource": "sentinel://audit/integrity",
                "status": "unavailable",
                "error": str(exc),
            },
            indent=2,
        )
    return json.dumps(
        {
            "resource": "sentinel://audit/integrity",
            "chain_intact": is_valid,
            "rows_checked": rows_checked,
            "tamper_detail": error,
            "note": (
                "chain_intact=true means every audit row's SHA-256 still matches "
                "the recomputed hash chain. false means a row was altered or "
                "removed at tamper_detail."
            ),
        },
        indent=2,
        default=str,
    )


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
    from sentinel.adapters.firewall import get_firewall_adapter

    adapter = get_firewall_adapter()
    blocked = await adapter.list_blocks()

    if adapter.is_mock:
        # Mock mode: no live block-list table to read; return a representative
        # sample so the resource is demonstrable without a database.
        blocked = [
            {
                "ip": "185.220.101.34",
                "reason": "Known Emotet C2 server (FeodoTracker)",
                "blocked_by": "senior@acmecorp.com",
                "blocked_at": "2026-06-02T09:30:00Z",
                "firewall_pushed": True,
            }
        ]

    return json.dumps(
        {
            "resource": "sentinel://watchlist/ips",
            "blocked_ips": blocked,
            "count": len(blocked),
            "source": "mock_sample" if adapter.is_mock else "postgres_blocklist",
        },
        indent=2,
    )
