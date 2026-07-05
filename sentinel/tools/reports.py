"""Report generation tools (Phase 4).

generate_incident_report — orchestrates get_alert, user_context, recent_logins,
                           device_processes, network_connections, enrich_ioc,
                           similar_incidents, and mitre_technique into one report.
weekly_summary           — OpenSearch aggregation over the past 7 days.
"""

import asyncio
from datetime import UTC, datetime
from typing import Any

from sentinel.config import get_settings
from sentinel.mcp.middleware import run_middleware
from sentinel.mcp.server import mcp

# ── generate_incident_report ──────────────────────────────────────────────────


async def _execute_generate_incident_report(args: dict[str, Any]) -> dict[str, Any]:
    alert_id = str(args.get("alert_id", "")).strip()
    if not alert_id:
        return {"error": "alert_id is required", "code": "MISSING_PARAMETER"}

    # Call sibling tools' execute helpers directly (orchestration — no nested middleware).
    from sentinel.tools.alerts import _execute_get_alert, _execute_similar_incidents
    from sentinel.tools.endpoint import _execute_device_processes, _execute_network_connections
    from sentinel.tools.identity import _execute_recent_logins, _execute_user_context
    from sentinel.tools.intel import _execute_enrich_ioc, _execute_mitre_technique

    alert = await _execute_get_alert({"alert_id": alert_id})
    if alert.get("code") == "NOT_FOUND":
        return {"error": f"Alert '{alert_id}' not found", "code": "NOT_FOUND"}
    if alert.get("code"):
        return alert

    affected_user = alert.get("affected_user")
    affected_host = alert.get("affected_host")
    source_ip = alert.get("source_ip")

    # ── Fan out the independent investigation legs concurrently ───────────────
    # Identity, endpoint, similar-incidents, per-technique MITRE, and the
    # source-IP enrichment don't depend on each other, so gather them rather
    # than awaiting serially — wall-clock becomes the slowest leg, not the sum.
    async def _identity() -> tuple[dict[str, Any], dict[str, Any]]:
        if not affected_user:
            return {}, {}
        return await asyncio.gather(
            _execute_user_context({"email": affected_user}),
            _execute_recent_logins({"email": affected_user, "days": 7}),
        )

    async def _endpoint() -> tuple[dict[str, Any], dict[str, Any]]:
        if not affected_host:
            return {}, {}
        return await asyncio.gather(
            _execute_device_processes({"hostname": affected_host, "time_window_minutes": 120}),
            _execute_network_connections({"hostname": affected_host, "time_window_minutes": 120}),
        )

    async def _source_ioc() -> dict[str, Any] | None:
        if not source_ip:
            return None
        return await _execute_enrich_ioc({"indicator": source_ip, "indicator_type": "ip"})

    async def _mitre() -> list[dict[str, Any]]:
        tids = alert.get("mitre_techniques", []) or []
        return list(
            await asyncio.gather(*(_execute_mitre_technique({"technique_id": t}) for t in tids))
        )

    (
        (user_ctx, logins),
        (processes, network),
        similar,
        techniques,
        source_ioc,
    ) = await asyncio.gather(
        _identity(),
        _endpoint(),
        _execute_similar_incidents({"alert_id": alert_id, "limit": 5}),
        _mitre(),
        _source_ioc(),
    )

    # ── Enrich TI-flagged network destinations (depends on endpoint result) ───
    flagged_ips = [
        c["dst_ip"]
        for c in network.get("connections", [])
        if c.get("threat_intel_flagged") and c.get("dst_ip")
    ]
    dst_iocs = list(
        await asyncio.gather(
            *(_execute_enrich_ioc({"indicator": ip, "indicator_type": "ip"}) for ip in flagged_ips)
        )
    )
    iocs: list[dict[str, Any]] = ([source_ioc] if source_ioc else []) + dst_iocs

    report: dict[str, Any] = {
        "report_id": f"IR-{alert_id}",
        "alert_id": alert_id,
        "generated_at": datetime.now(UTC).isoformat(),
        "severity": alert.get("severity"),
        "status": alert.get("status"),
        "executive_summary": {
            "title": alert.get("rule_name"),
            "affected_user": affected_user,
            "affected_host": affected_host,
            "ioc_count": len(iocs),
            "malicious_ioc_count": sum(1 for i in iocs if i.get("verdict") == "malicious"),
            "technique_count": len(techniques),
        },
        "alert": alert,
        "affected_assets": {
            "user": user_ctx if "error" not in user_ctx else None,
            "host": affected_host,
        },
        "identity": {"recent_logins": logins.get("logins", []) if "error" not in logins else []},
        "endpoint": {
            "processes": processes.get("processes", []),
            "suspicious_process_count": processes.get("suspicious_count", 0),
            "network_connections": network.get("connections", []),
            "flagged_connection_count": network.get("threat_intel_flagged", 0),
        },
        "threat_intelligence": iocs,
        "mitre_attack": techniques,
        "similar_incidents": similar.get("similar", []),
        "recommended_actions": _recommended_actions(alert, iocs),
    }

    # ── Optional narrative ────────────────────────────────────────────────────
    settings = get_settings()
    if settings.report_narrative_enabled and settings.has_anthropic:
        from sentinel.adapters.anthropic_adapter import get_anthropic_adapter

        narrative = await get_anthropic_adapter().generate_incident_narrative(report)
        report["narrative"] = narrative
    else:
        report["narrative_enabled"] = False

    return report


def _recommended_actions(alert: dict[str, Any], iocs: list[dict[str, Any]]) -> list[str]:
    actions: list[str] = []
    if any(i.get("verdict") == "malicious" for i in iocs):
        actions.append(
            "Block confirmed-malicious IPs/domains (block_ip) after verifying "
            "they are not shared infrastructure."
        )
    if alert.get("affected_host"):
        actions.append(
            f"Review processes on {alert['affected_host']}; "
            "isolate_device if active C2 is confirmed."
        )
    if alert.get("severity") in ("high", "critical") and alert.get("affected_user"):
        actions.append(
            f"Assess {alert['affected_user']} for credential compromise; disable_user if confirmed."
        )
    if not actions:
        actions.append("Monitor — no immediate containment indicated by current evidence.")
    return actions


@mcp.tool()
async def generate_incident_report(alert_id: str) -> dict[str, Any]:
    """Generate a complete incident report for an alert.

    Orchestration tool: calls get_alert, user_context, recent_logins,
    device_processes, network_connections, enrich_ioc (for every IOC in the
    alert), similar_incidents, and mitre_technique. Compiles everything into a
    structured report: Executive Summary, Affected Assets, Identity, Endpoint,
    Threat Intelligence, MITRE ATT&CK Mapping, Similar Incidents, and
    Recommended Actions.

    If REPORT_NARRATIVE_ENABLED=true and an Anthropic key is set, a written
    narrative is added. Otherwise the structured data is returned and Claude
    writes the narrative from context.

    Args:
        alert_id: Alert to generate the report for
    """
    return await run_middleware(
        "generate_incident_report",
        {"alert_id": alert_id},
        _execute_generate_incident_report,
    )


# ── weekly_summary ────────────────────────────────────────────────────────────


async def _execute_weekly_summary(args: dict[str, Any]) -> dict[str, Any]:
    from sentinel.adapters.opensearch import get_opensearch_adapter

    adapter = get_opensearch_adapter()
    stats = await adapter.aggregate_alerts(time_window_hours=168)
    # Bound the per-alert breakdown to the same 7-day window as the aggregate,
    # otherwise top_risky_users / top_source_ips reflect the most recent 500
    # alerts of all time rather than the week the summary claims to cover.
    alerts = await adapter.get_alerts(limit=500, time_window_hours=168)

    by_user: dict[str, int] = {}
    by_ip: dict[str, int] = {}
    for a in alerts:
        if a.get("affected_user"):
            by_user[a["affected_user"]] = by_user.get(a["affected_user"], 0) + 1
        if a.get("source_ip"):
            by_ip[a["source_ip"]] = by_ip.get(a["source_ip"], 0) + 1

    top_users = sorted(by_user.items(), key=lambda kv: kv[1], reverse=True)[:5]
    top_ips = sorted(by_ip.items(), key=lambda kv: kv[1], reverse=True)[:10]

    return {
        "period_days": 7,
        "generated_at": datetime.now(UTC).isoformat(),
        "total_alerts": stats.get("total", len(alerts)),
        "by_severity": stats.get("by_severity", {}),
        "open": stats.get("open"),
        "closed": stats.get("closed"),
        "top_risky_users": [{"user": u, "alert_count": c} for u, c in top_users],
        "top_source_ips": [{"ip": ip, "alert_count": c} for ip, c in top_ips],
    }


@mcp.tool()
async def weekly_summary() -> dict[str, Any]:
    """Generate a weekly SOC summary for the past 7 days.

    Computes: total alerts, breakdown by severity, open vs closed counts,
    top risky users, and top source IPs. Returns structured metrics — Claude
    summarises these into a shift handover or management briefing.
    """
    return await run_middleware("weekly_summary", {}, _execute_weekly_summary)
