"""Identity and user risk tools.

user_context    — Keycloak adapter
recent_logins   — Keycloak adapter
risk_score_user — derived live from recent_logins + user_context signals
                  (foreign-country logins, missing MFA, known-bad source IPs via
                  enrich_ioc, and sensitive group membership). No longer a mock.
"""

from typing import Any

from sentinel.mcp.middleware import run_middleware
from sentinel.mcp.server import mcp

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


def _level_for(score: int) -> str:
    if score >= 81:
        return "critical"
    if score >= 61:
        return "high"
    if score >= 31:
        return "medium"
    return "low"


async def _execute_risk_score_user(args: dict[str, Any]) -> dict[str, Any]:
    from datetime import UTC, datetime

    email = str(args.get("email", "")).strip().lower()
    if not email or "@" not in email:
        return {"error": "Valid email address is required", "code": "INVALID_PARAMETER"}

    # Pull the real identity + login signals this score is derived from.
    context = await _execute_user_context({"email": email})
    if context.get("code") == "NOT_FOUND":
        return {"email": email, "score": 0, "level": "unknown", "factors": []}

    logins_result = await _execute_recent_logins({"email": email, "days": 14})
    logins = logins_result.get("logins", []) if "error" not in logins_result else []

    score = 0
    factors: list[dict[str, Any]] = []

    # 1. Logins missing MFA
    no_mfa = [login for login in logins if not login.get("mfa_method")]
    if no_mfa:
        score += 15
        factors.append(
            {
                "factor": "login_without_mfa",
                "weight": 15,
                "detail": f"{len(no_mfa)} login(s) with no MFA method recorded",
            }
        )

    # 2. Logins from multiple countries (impossible-travel proxy)
    countries = {login.get("country") for login in logins if login.get("country")}
    if len(countries) > 1:
        score += 25
        factors.append(
            {
                "factor": "multiple_login_countries",
                "weight": 25,
                "detail": f"Logins from {len(countries)} countries: {', '.join(sorted(countries))}",
            }
        )

    # 3. Source IPs that enrich as malicious/suspicious
    from sentinel.tools.enrichment import enrich_indicator

    source_ips = {login.get("ip_address") for login in logins if login.get("ip_address")}
    bad_ips: list[str] = []
    for ip in sorted(source_ips):
        verdict = (await enrich_indicator(ip, "ip")).get("verdict")
        if verdict in ("malicious", "suspicious"):
            bad_ips.append(ip)
    if bad_ips:
        score += 35
        factors.append(
            {
                "factor": "login_from_known_bad_ip",
                "weight": 35,
                "detail": f"Login(s) from flagged IP(s): {', '.join(bad_ips)}",
            }
        )

    # 4. Membership in sensitive / privileged groups
    groups = context.get("groups", []) or []
    sensitive = [g for g in groups if any(k in g.lower() for k in ("sensitive", "admin"))]
    if sensitive:
        score += 10
        factors.append(
            {
                "factor": "access_to_sensitive_systems",
                "weight": 10,
                "detail": f"Member of: {', '.join(sensitive)}",
            }
        )

    score = min(score, 100)
    return {
        "email": email,
        "score": score,
        "level": _level_for(score),
        "factors": factors,
        "assessed_at": datetime.now(UTC).isoformat(),
    }


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
