"""Identity and user risk tools.

user_context    — FULLY IMPLEMENTED (Phase 2, mock data)
recent_logins   — FULLY IMPLEMENTED (Phase 2, mock data)
risk_score_user — FULLY IMPLEMENTED (Phase 2, mock data)
"""

from typing import Any

from sentinel.mcp.middleware import run_middleware
from sentinel.mcp.server import mcp
from sentinel.tools import mock_data as mock

# ── user_context ──────────────────────────────────────────────────────────────


async def _execute_user_context(args: dict[str, Any]) -> dict[str, Any]:
    email = str(args.get("email", "")).strip().lower()
    if not email or "@" not in email:
        return {"error": "Valid email address is required", "code": "INVALID_PARAMETER"}

    from sentinel.adapters.keycloak import get_keycloak_adapter

    user = await get_keycloak_adapter().get_user(email)
    if user is None:
        return {
            "error": f"User '{email}' not found",
            "code": "NOT_FOUND",
            "hint": (
                "Try alice.hr@acmecorp.com, bob.finance@acmecorp.com, "
                "or charlie.devops@acmecorp.com"
            ),
        }
    return user


@mcp.tool()
async def user_context(email: str) -> dict[str, Any]:
    """Get full user profile: department, groups, MFA status, registered devices.

    Call this whenever you encounter a suspicious user in an alert. The
    group memberships reveal access to sensitive systems. MFA status and
    registered devices show whether the authentication was expected.

    Never returns raw Keycloak tokens or internal user IDs.

    Args:
        email: User's work email address, e.g. "alice.hr@acmecorp.com"
    """
    return await run_middleware("user_context", {"email": email}, _execute_user_context)


# ── recent_logins ─────────────────────────────────────────────────────────────


async def _execute_recent_logins(args: dict[str, Any]) -> dict[str, Any]:
    email = str(args.get("email", "")).strip().lower()
    days = max(1, min(int(args.get("days", 7)), 90))

    if not email or "@" not in email:
        return {"error": "Valid email address is required", "code": "INVALID_PARAMETER"}

    from sentinel.adapters.keycloak import get_keycloak_adapter

    logins = await get_keycloak_adapter().get_login_events(email, days)
    return {
        "email": email,
        "days": days,
        "total_events": len(logins),
        "logins": logins,
    }


@mcp.tool()
async def recent_logins(email: str, days: int = 7) -> dict[str, Any]:
    """Pull login history for a user: timestamps, IPs, countries, devices, MFA.

    Use this to detect impossible travel, unfamiliar devices, missing MFA,
    or logins at unusual hours. Compare the source IPs against enrich_ioc()
    to check for known-bad infrastructure.

    Args:
        email: User's work email address
        days: How many days of history to retrieve (default 7, max 90)
    """
    return await run_middleware(
        "recent_logins", {"email": email, "days": days}, _execute_recent_logins
    )


# ── risk_score_user ───────────────────────────────────────────────────────────


async def _execute_risk_score_user(args: dict[str, Any]) -> dict[str, Any]:
    email = str(args.get("email", "")).strip().lower()
    if not email or "@" not in email:
        return {"error": "Valid email address is required", "code": "INVALID_PARAMETER"}

    return mock.risk_score(email)


@mcp.tool()
async def risk_score_user(email: str) -> dict[str, Any]:
    """Compute a 0-100 risk score for a user with factor breakdown.

    Aggregates: recent failed logins, impossible travel, unfamiliar devices,
    login hours, access to sensitive groups, active alerts, and process
    anomalies on their assigned device.

    Score interpretation:
    - 0-30: Low risk — routine activity
    - 31-60: Medium risk — warrants attention
    - 61-80: High risk — investigate promptly
    - 81-100: Critical risk — immediate response recommended

    Args:
        email: User's work email address
    """
    return await run_middleware("risk_score_user", {"email": email}, _execute_risk_score_user)
