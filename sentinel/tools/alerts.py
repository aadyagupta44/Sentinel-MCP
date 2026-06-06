"""Alert investigation tools.

get_alert         — FULLY IMPLEMENTED (Phase 2, mock data)
search_logs       — stub (Phase 4: OpenSearch adapter)
correlate_alerts  — stub (Phase 4: OpenSearch adapter)
similar_incidents — stub (Phase 4: OpenSearch adapter)
"""

from typing import Any

from sentinel.mcp.middleware import run_middleware
from sentinel.mcp.server import mcp
from sentinel.tools import mock_data as mock


# ── get_alert ─────────────────────────────────────────────────────────────────

async def _execute_get_alert(args: dict[str, Any]) -> dict[str, Any]:
    alert_id = str(args.get("alert_id", "")).strip()
    if not alert_id:
        return {"error": "alert_id is required", "code": "MISSING_PARAMETER"}

    alert = mock.get_alert(alert_id)
    if alert is None:
        return {
            "error": f"Alert '{alert_id}' not found",
            "code": "NOT_FOUND",
            "hint": "Try ALT-2026-001, ALT-2026-002, or ALT-2026-003",
        }
    return alert


@mcp.tool()
async def get_alert(alert_id: str) -> dict[str, Any]:
    """Fetch a single security alert by ID from the SIEM.

    Call this first when investigating any alert. Returns full context
    including severity, affected user and host, MITRE technique mapping,
    raw log references, and the raw command that triggered the rule.

    After calling this, you will typically want to call:
    - user_context() on the affected_user
    - enrich_ioc() on any source_ip
    - device_processes() on the affected_host
    - mitre_technique() on each technique in mitre_techniques

    Args:
        alert_id: Alert identifier, e.g. "ALT-2026-001"
    """
    return await run_middleware("get_alert", {"alert_id": alert_id}, _execute_get_alert)


# ── search_logs ───────────────────────────────────────────────────────────────

async def _execute_search_logs(args: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "not_yet_implemented",
        "phase": "Phase 4 — OpenSearch adapter",
        "query": args.get("query"),
        "time_window_hours": args.get("time_window_hours", 24),
        "results": [],
        "total_hits": 0,
    }


@mcp.tool()
async def search_logs(
    query: str,
    time_window_hours: int = 24,
    max_results: int = 50,
) -> dict[str, Any]:
    """Search across all SIEM logs with keyword or semantic query.

    Use this to find log events not captured by alert rules — raw login
    attempts, process executions, network connections matching a pattern.
    Sanitises the query before passing to Elasticsearch to prevent injection.

    Args:
        query: Search terms, e.g. "mimikatz" or "failed login 185.220.101.34"
        time_window_hours: How far back to search (default 24h, max 168h)
        max_results: Maximum events to return (default 50, max 500)
    """
    return await run_middleware(
        "search_logs",
        {"query": query, "time_window_hours": time_window_hours, "max_results": max_results},
        _execute_search_logs,
    )


# ── correlate_alerts ──────────────────────────────────────────────────────────

async def _execute_correlate_alerts(args: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "not_yet_implemented",
        "phase": "Phase 4 — OpenSearch adapter",
        "time_window_hours": args.get("time_window_hours", 24),
        "clusters": [],
    }


@mcp.tool()
async def correlate_alerts(time_window_hours: int = 24) -> dict[str, Any]:
    """Group related alerts into incident clusters.

    Clusters alerts that share the same user, host, source IP, or MITRE
    technique within the time window. Returns clusters with a generated
    cluster ID and summary — use these to understand if multiple alerts
    are part of a single attack chain.

    Args:
        time_window_hours: Correlation window in hours (default 24)
    """
    return await run_middleware(
        "correlate_alerts",
        {"time_window_hours": time_window_hours},
        _execute_correlate_alerts,
    )


# ── similar_incidents ─────────────────────────────────────────────────────────

async def _execute_similar_incidents(args: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "not_yet_implemented",
        "phase": "Phase 4 — OpenSearch adapter",
        "alert_id": args.get("alert_id"),
        "similar": [],
    }


@mcp.tool()
async def similar_incidents(alert_id: str, limit: int = 5) -> dict[str, Any]:
    """Find historically similar past incidents by field similarity.

    Matches on same rule name, user department, MITRE technique, and
    host type. Returns ranked past incidents with their resolution outcomes
    — use these to pattern-match against known-good analyst decisions.

    Args:
        alert_id: Alert to find similar incidents for
        limit: Maximum number of similar incidents to return (default 5)
    """
    return await run_middleware(
        "similar_incidents",
        {"alert_id": alert_id, "limit": limit},
        _execute_similar_incidents,
    )
