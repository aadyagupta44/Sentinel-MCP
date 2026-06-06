"""Report generation tools.

generate_incident_report — stub (Phase 4: orchestrates all other tools)
weekly_summary           — stub (Phase 4: OpenSearch aggregation)
"""

from typing import Any

from sentinel.mcp.middleware import run_middleware
from sentinel.mcp.server import mcp


async def _execute_generate_incident_report(args: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "not_yet_implemented",
        "phase": "Phase 4 — orchestrated from all completed tools",
        "alert_id": args.get("alert_id"),
        "note": (
            "In Phase 4, this tool will call get_alert, user_context, recent_logins, "
            "device_processes, network_connections, enrich_ioc (for all IOCs), "
            "similar_incidents, and mitre_technique, then compile a structured report. "
            "If REPORT_NARRATIVE_ENABLED=true, the Anthropic API generates a written narrative."
        ),
    }


@mcp.tool()
async def generate_incident_report(alert_id: str) -> dict[str, Any]:
    """Generate a complete incident report for an alert.

    Orchestration tool: calls get_alert, user_context, recent_logins,
    device_processes, network_connections, enrich_ioc (for all IOCs in the
    alert), similar_incidents, and mitre_technique. Compiles everything into
    a structured report with: Executive Summary, Timeline, Affected Assets,
    Threat Intelligence, MITRE ATT&CK Mapping, and Recommended Actions.

    If REPORT_NARRATIVE_ENABLED=true, the Anthropic API generates a written
    narrative. Otherwise, the structured data is returned and Claude writes
    the narrative from context.

    Args:
        alert_id: Alert to generate the report for
    """
    return await run_middleware(
        "generate_incident_report",
        {"alert_id": alert_id},
        _execute_generate_incident_report,
    )


async def _execute_weekly_summary(args: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": "not_yet_implemented",
        "phase": "Phase 4 — OpenSearch aggregation",
        "note": (
            "In Phase 4, this tool will query Elastic for 7 days of alerts, "
            "compute statistics, and return a structured summary with week-over-week trends."
        ),
    }


@mcp.tool()
async def weekly_summary() -> dict[str, Any]:
    """Generate a weekly SOC summary for the past 7 days.

    Computes: total alerts, breakdown by severity and rule type, top 5 risky
    users, top 10 suspicious IPs, mean time to investigate, open vs closed
    incidents, and week-over-week trend comparison.

    Returns structured metrics. Claude summarises these into a shift handover
    or management briefing.
    """
    return await run_middleware("weekly_summary", {}, _execute_weekly_summary)
