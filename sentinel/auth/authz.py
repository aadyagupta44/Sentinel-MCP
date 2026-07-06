"""Scope + role authorization for the HTTP transport.

Mirrors policies/authz.rego so the HTTP layer fails fast and deterministically
even when the OPA sidecar is unavailable; OPA remains the defence-in-depth check
inside the middleware pipeline.

Rules:
- Every tool requires an OAuth scope: read tools need `soc:read`,
  write/action tools need `soc:write`.
- Write/action tools additionally require the `senior_analyst` or `admin` role
  (a plain `analyst` is read-only).
"""

from sentinel.auth.context import Principal

READ_TOOLS = frozenset(
    {
        "get_alert",
        "search_logs",
        "correlate_alerts",
        "similar_incidents",
        "enrich_ioc",
        "threat_hunt",
        "user_context",
        "recent_logins",
        "risk_score_user",
        "device_processes",
        "network_connections",
        "mitre_technique",
        "generate_incident_report",
        "weekly_summary",
    }
)

WRITE_TOOLS = frozenset(
    {
        "isolate_device",
        "disable_user",
        "block_ip",
        "kill_process",
    }
)

WRITE_ROLES = frozenset({"senior_analyst", "admin"})

READ_SCOPE = "soc:read"
WRITE_SCOPE = "soc:write"


def required_scope(tool_name: str) -> str:
    return WRITE_SCOPE if tool_name in WRITE_TOOLS else READ_SCOPE


def authorize(principal: Principal, tool_name: str) -> tuple[bool, str]:
    """Return (allowed, reason). Reason is a stable machine code on denial."""
    if tool_name not in READ_TOOLS and tool_name not in WRITE_TOOLS:
        return False, "unknown_tool"

    # The public demo authorizes on ROLE alone: identity still comes from a real
    # OAuth 2.1 login, but the demo identity provider issues only standard OIDC
    # scopes (no custom soc:read/soc:write), so the scope gate is skipped there.
    # Real deployments keep the full scope + role check.
    from sentinel.config import get_settings

    if not get_settings().demo_mode:
        scope = required_scope(tool_name)
        if not principal.has_scope(scope):
            return False, f"missing_scope:{scope}"

    if tool_name in WRITE_TOOLS and principal.role not in WRITE_ROLES:
        return False, "write_requires_senior_analyst"

    return True, "authorized"
