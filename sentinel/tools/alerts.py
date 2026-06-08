"""Alert investigation tools (Phase 4 — adapter-backed).

get_alert         — OpenSearch adapter
search_logs       — OpenSearch adapter (full-text log search)
correlate_alerts  — OpenSearch adapter + entity-overlap clustering
similar_incidents — OpenSearch adapter + field-similarity ranking
"""

from typing import Any

from sentinel.mcp.middleware import run_middleware
from sentinel.mcp.server import mcp

# ── get_alert ─────────────────────────────────────────────────────────────────


async def _execute_get_alert(args: dict[str, Any]) -> dict[str, Any]:
    alert_id = str(args.get("alert_id", "")).strip()
    if not alert_id:
        return {"error": "alert_id is required", "code": "MISSING_PARAMETER"}

    from sentinel.adapters.opensearch import get_opensearch_adapter

    alert = await get_opensearch_adapter().get_alert(alert_id)
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
    query = str(args.get("query", "")).strip()
    time_window_hours = max(1, min(int(args.get("time_window_hours", 24)), 168))
    max_results = max(1, min(int(args.get("max_results", 50)), 500))

    if not query:
        return {"error": "query is required", "code": "MISSING_PARAMETER"}

    from sentinel.adapters.opensearch import get_opensearch_adapter

    results = await get_opensearch_adapter().search_logs(query, time_window_hours, max_results)
    return {
        "query": query,
        "time_window_hours": time_window_hours,
        "total_hits": len(results),
        "results": results,
    }


@mcp.tool()
async def search_logs(
    query: str,
    time_window_hours: int = 24,
    max_results: int = 50,
) -> dict[str, Any]:
    """Search across all SIEM logs with a keyword query.

    Use this to find log events not captured by alert rules — raw login
    attempts, process executions, network connections matching a pattern.
    The query is passed as a structured match clause, never raw Lucene,
    to prevent query injection.

    Args:
        query: Search terms, e.g. "mimikatz" or "185.220.101.34"
        time_window_hours: How far back to search (default 24h, max 168h)
        max_results: Maximum events to return (default 50, max 500)
    """
    return await run_middleware(
        "search_logs",
        {"query": query, "time_window_hours": time_window_hours, "max_results": max_results},
        _execute_search_logs,
    )


# ── correlate_alerts ──────────────────────────────────────────────────────────


def _alert_entities(alert: dict[str, Any]) -> dict[str, Any]:
    """Extract the entities an alert can be correlated on."""
    return {
        "user": alert.get("affected_user"),
        "host": alert.get("affected_host"),
        "ip": alert.get("source_ip"),
        "techniques": tuple(alert.get("mitre_techniques", []) or []),
    }


async def _execute_correlate_alerts(args: dict[str, Any]) -> dict[str, Any]:
    time_window_hours = max(1, min(int(args.get("time_window_hours", 24)), 720))

    from sentinel.adapters.opensearch import get_opensearch_adapter

    alerts = await get_opensearch_adapter().get_alerts(limit=200)

    # Union-find style clustering: alerts that share any entity land together.
    clusters: list[dict[str, Any]] = []
    for alert in alerts:
        ent = _alert_entities(alert)
        placed = False
        for cluster in clusters:
            shared = _shared_factors(ent, cluster["_entities"])
            if shared:
                cluster["alert_ids"].append(alert["alert_id"])
                cluster["shared_factors"] = sorted(set(cluster["shared_factors"]) | set(shared))
                for key in ("user", "host", "ip"):
                    if ent.get(key):
                        cluster["_entities"].setdefault(key, set()).add(ent[key])
                cluster["_entities"].setdefault("techniques", set()).update(ent["techniques"])
                placed = True
                break
        if not placed:
            clusters.append(
                {
                    "cluster_id": f"CL-{len(clusters) + 1:03d}",
                    "alert_ids": [alert["alert_id"]],
                    "shared_factors": [],
                    "_entities": {
                        "user": {ent["user"]} if ent["user"] else set(),
                        "host": {ent["host"]} if ent["host"] else set(),
                        "ip": {ent["ip"]} if ent["ip"] else set(),
                        "techniques": set(ent["techniques"]),
                    },
                }
            )

    multi = [c for c in clusters if len(c["alert_ids"]) > 1]
    for c in clusters:
        c.pop("_entities", None)
        c["alert_count"] = len(c["alert_ids"])
        c["summary"] = f"{c['alert_count']} alert(s)" + (
            f" linked by {', '.join(c['shared_factors'])}"
            if c["shared_factors"]
            else " (no overlap)"
        )

    return {
        "time_window_hours": time_window_hours,
        "total_alerts": len(alerts),
        "cluster_count": len(clusters),
        "correlated_cluster_count": len(multi),
        "clusters": clusters,
    }


def _shared_factors(a: dict[str, Any], cluster_entities: dict[str, set]) -> list[str]:
    shared: list[str] = []
    for key in ("user", "host", "ip"):
        if a.get(key) and a[key] in cluster_entities.get(key, set()):
            shared.append(key)
    if set(a["techniques"]) & cluster_entities.get("techniques", set()):
        shared.append("mitre_technique")
    return shared


@mcp.tool()
async def correlate_alerts(time_window_hours: int = 24) -> dict[str, Any]:
    """Group related alerts into incident clusters.

    Clusters alerts that share the same user, host, source IP, or MITRE
    technique within the time window. Returns clusters with a generated
    cluster ID and summary — use these to understand whether multiple alerts
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


def _similarity(target: dict[str, Any], candidate: dict[str, Any]) -> tuple[float, list[str]]:
    factors: list[str] = []
    score = 0.0
    if candidate.get("rule_name") == target.get("rule_name"):
        score += 0.4
        factors.append("same_rule")
    shared_tech = set(target.get("mitre_techniques", [])) & set(
        candidate.get("mitre_techniques", [])
    )
    if shared_tech:
        score += 0.3
        factors.append(f"shared_technique:{','.join(sorted(shared_tech))}")
    if candidate.get("severity") == target.get("severity"):
        score += 0.2
        factors.append("same_severity")
    if candidate.get("affected_user") == target.get("affected_user") and target.get(
        "affected_user"
    ):
        score += 0.1
        factors.append("same_user")
    return round(score, 2), factors


async def _execute_similar_incidents(args: dict[str, Any]) -> dict[str, Any]:
    alert_id = str(args.get("alert_id", "")).strip()
    limit = max(1, min(int(args.get("limit", 5)), 25))
    if not alert_id:
        return {"error": "alert_id is required", "code": "MISSING_PARAMETER"}

    from sentinel.adapters.opensearch import get_opensearch_adapter

    adapter = get_opensearch_adapter()
    target = await adapter.get_alert(alert_id)
    if target is None:
        return {"error": f"Alert '{alert_id}' not found", "code": "NOT_FOUND"}

    # Security: Limit search to most recent 200 alerts (approximately 7-30 days
    # depending on alert volume). This prevents unbounded searches across years
    # of data, which could cause performance issues or resource exhaustion.
    pool = await adapter.get_alerts(limit=200)
    ranked: list[dict[str, Any]] = []
    for candidate in pool:
        if candidate.get("alert_id") == alert_id:
            continue
        score, factors = _similarity(target, candidate)
        if score > 0:
            ranked.append(
                {
                    "alert_id": candidate.get("alert_id"),
                    "rule_name": candidate.get("rule_name"),
                    "severity": candidate.get("severity"),
                    "status": candidate.get("status"),
                    "similarity_score": score,
                    "shared_factors": factors,
                }
            )

    ranked.sort(key=lambda r: r["similarity_score"], reverse=True)
    return {
        "alert_id": alert_id,
        "total_candidates": len(pool),
        "similar_count": len(ranked[:limit]),
        "similar": ranked[:limit],
    }


@mcp.tool()
async def similar_incidents(alert_id: str, limit: int = 5) -> dict[str, Any]:
    """Find historically similar past incidents by field similarity.

    Matches on same rule name, shared MITRE technique, severity, and affected
    user. Returns ranked past incidents with a similarity score — use these to
    pattern-match against known-good analyst decisions.

    Args:
        alert_id: Alert to find similar incidents for
        limit: Maximum number of similar incidents to return (default 5)
    """
    return await run_middleware(
        "similar_incidents",
        {"alert_id": alert_id, "limit": limit},
        _execute_similar_incidents,
    )
