"""Write tools — require two-step confirmation before execution.

Every write tool follows the same pattern:
  1. First call (no confirmed=True + no confirmation_token):
     Returns a ProposedAction describing exactly what will happen.
     Nothing is executed.
  2. Second call (confirmed=True + valid confirmation_token):
     Validates the token, executes the action, logs to audit trail.

Token TTL is controlled by PENDING_ACTION_TTL_SECONDS (default 600s / 10 min).
"""

from typing import Any

from sentinel.config import get_settings
from sentinel.mcp.middleware import run_middleware
from sentinel.mcp.server import mcp
from sentinel.tools.confirmation import create_proposal, execute_confirmed


# ── isolate_device ────────────────────────────────────────────────────────────

async def _mock_isolate(params: dict[str, Any]) -> dict[str, Any]:
    return {
        "hostname": params["hostname"],
        "action": "isolated",
        "wazuh_agent_id": "agent-mock-001",
        "note": "Mock isolation — Wazuh adapter available in Phase 3",
    }


async def _execute_isolate_device(args: dict[str, Any]) -> dict[str, Any]:
    hostname = str(args.get("hostname", "")).strip()
    reason = str(args.get("reason", "")).strip()
    confirmed = bool(args.get("confirmed", False))
    token = str(args.get("confirmation_token", "")).strip()
    settings = get_settings()

    if not hostname:
        return {"error": "hostname is required", "code": "MISSING_PARAMETER"}
    if not reason:
        return {"error": "reason is required — document why you are isolating this device", "code": "MISSING_PARAMETER"}

    if not confirmed:
        return await create_proposal(
            tool_name="isolate_device",
            analyst_id=settings.analyst_id,
            target=hostname,
            description=f"Isolate host '{hostname}' from all network connectivity via Wazuh agent isolation.",
            warning=(
                f"This will IMMEDIATELY cut all network access for '{hostname}'. "
                "The user will lose internet, VPN, and domain connectivity. "
                "Only proceed if you have confirmed malicious activity on this host."
            ),
            parameters={"hostname": hostname, "reason": reason},
        )

    return await execute_confirmed("isolate_device", token, settings.analyst_id, _mock_isolate)


@mcp.tool()
async def isolate_device(
    hostname: str,
    reason: str,
    confirmed: bool = False,
    confirmation_token: str = "",
) -> dict[str, Any]:
    """Isolate a host from the network via Wazuh agent isolation. WRITE ACTION.

    IMPORTANT: This is a two-step action.
    - First call (no confirmed=True): Returns a proposal describing what will happen.
      Read it carefully. Nothing is executed yet.
    - Second call (confirmed=True + confirmation_token from first call):
      Executes the isolation. All network connectivity is immediately severed.

    Only use when you have strong evidence of active compromise on the host.

    Args:
        hostname: Target hostname to isolate, e.g. "LAPTOP-HR-03"
        reason: Why you are isolating (required for audit log)
        confirmed: Set to True on second call to execute
        confirmation_token: Token from the first call's response
    """
    return await run_middleware(
        "isolate_device",
        {
            "hostname": hostname,
            "reason": reason,
            "confirmed": confirmed,
            "confirmation_token": confirmation_token,
        },
        _execute_isolate_device,
    )


# ── disable_user ──────────────────────────────────────────────────────────────

async def _mock_disable_user(params: dict[str, Any]) -> dict[str, Any]:
    return {
        "email": params["email"],
        "action": "suspended",
        "keycloak_status": "SUSPENDED",
        "note": "Mock suspension — Keycloak adapter available in Phase 3",
    }


async def _execute_disable_user(args: dict[str, Any]) -> dict[str, Any]:
    email = str(args.get("email", "")).strip().lower()
    reason = str(args.get("reason", "")).strip()
    confirmed = bool(args.get("confirmed", False))
    token = str(args.get("confirmation_token", "")).strip()
    settings = get_settings()

    if not email or "@" not in email:
        return {"error": "Valid email address is required", "code": "INVALID_PARAMETER"}
    if not reason:
        return {"error": "reason is required — document why you are disabling this account", "code": "MISSING_PARAMETER"}

    if not confirmed:
        return await create_proposal(
            tool_name="disable_user",
            analyst_id=settings.analyst_id,
            target=email,
            description=f"Suspend user account '{email}' in Keycloak. User will be unable to authenticate.",
            warning=(
                f"Suspending '{email}' will immediately block ALL their access: "
                "SSO, email, VPN, cloud services. Inform HR before suspending. "
                "Use this only for confirmed credential compromise or insider threat."
            ),
            parameters={"email": email, "reason": reason},
        )

    return await execute_confirmed("disable_user", token, settings.analyst_id, _mock_disable_user)


@mcp.tool()
async def disable_user(
    email: str,
    reason: str,
    confirmed: bool = False,
    confirmation_token: str = "",
) -> dict[str, Any]:
    """Suspend a user account in Keycloak. WRITE ACTION.

    Two-step action — see isolate_device for the pattern.
    Suspends the Keycloak account, immediately blocking all SSO-based access.

    Args:
        email: User email to suspend, e.g. "alice.hr@acmecorp.com"
        reason: Why you are suspending (required for audit log)
        confirmed: Set to True on second call to execute
        confirmation_token: Token from the first call's response
    """
    return await run_middleware(
        "disable_user",
        {
            "email": email,
            "reason": reason,
            "confirmed": confirmed,
            "confirmation_token": confirmation_token,
        },
        _execute_disable_user,
    )


# ── block_ip ──────────────────────────────────────────────────────────────────

async def _mock_block_ip(params: dict[str, Any]) -> dict[str, Any]:
    return {
        "ip_address": params["ip_address"],
        "action": "blocked",
        "storage": "postgres_blocklist",
        "note": "Mock block — firewall push available in Phase 4",
    }


async def _execute_block_ip(args: dict[str, Any]) -> dict[str, Any]:
    ip = str(args.get("ip_address", "")).strip()
    reason = str(args.get("reason", "")).strip()
    confirmed = bool(args.get("confirmed", False))
    token = str(args.get("confirmation_token", "")).strip()
    settings = get_settings()

    if not ip:
        return {"error": "ip_address is required", "code": "MISSING_PARAMETER"}
    if not reason:
        return {"error": "reason is required", "code": "MISSING_PARAMETER"}

    if not confirmed:
        return await create_proposal(
            tool_name="block_ip",
            analyst_id=settings.analyst_id,
            target=ip,
            description=f"Add IP '{ip}' to the block list. In production this pushes to the perimeter firewall.",
            warning=(
                f"Blocking '{ip}' will drop all traffic to/from this IP. "
                "Verify this is not a shared IP (CDN, VPN gateway, NAT) that "
                "would affect legitimate users."
            ),
            parameters={"ip_address": ip, "reason": reason},
        )

    return await execute_confirmed("block_ip", token, settings.analyst_id, _mock_block_ip)


@mcp.tool()
async def block_ip(
    ip_address: str,
    reason: str,
    confirmed: bool = False,
    confirmation_token: str = "",
) -> dict[str, Any]:
    """Add an IP address to the block list. WRITE ACTION.

    Two-step action — see isolate_device for the pattern.
    Stores the block in Postgres and (in production) pushes to the firewall.
    Always call enrich_ioc() first to confirm the IP is malicious.

    Args:
        ip_address: IPv4 or IPv6 address to block
        reason: Why you are blocking (required for audit log)
        confirmed: Set to True on second call to execute
        confirmation_token: Token from the first call's response
    """
    return await run_middleware(
        "block_ip",
        {
            "ip_address": ip_address,
            "reason": reason,
            "confirmed": confirmed,
            "confirmation_token": confirmation_token,
        },
        _execute_block_ip,
    )


# ── kill_process ──────────────────────────────────────────────────────────────

async def _mock_kill_process(params: dict[str, Any]) -> dict[str, Any]:
    return {
        "hostname": params["hostname"],
        "pid": params["pid"],
        "action": "terminated",
        "note": "Mock kill — Wazuh active response available in Phase 3",
    }


async def _execute_kill_process(args: dict[str, Any]) -> dict[str, Any]:
    hostname = str(args.get("hostname", "")).strip()
    pid = args.get("pid")
    reason = str(args.get("reason", "")).strip()
    confirmed = bool(args.get("confirmed", False))
    token = str(args.get("confirmation_token", "")).strip()
    settings = get_settings()

    if not hostname:
        return {"error": "hostname is required", "code": "MISSING_PARAMETER"}
    if pid is None or int(pid) <= 0:
        return {"error": "pid must be a positive integer", "code": "INVALID_PARAMETER"}
    if not reason:
        return {"error": "reason is required", "code": "MISSING_PARAMETER"}

    pid_int = int(pid)

    if not confirmed:
        return await create_proposal(
            tool_name="kill_process",
            analyst_id=settings.analyst_id,
            target=f"{hostname}:PID-{pid_int}",
            description=f"Terminate process PID {pid_int} on host '{hostname}' via Wazuh active response.",
            warning=(
                f"Killing PID {pid_int} on '{hostname}' is immediate and irreversible. "
                "PIDs are reused — confirm this PID still belongs to the malicious "
                "process before executing. Use device_processes() to verify."
            ),
            parameters={"hostname": hostname, "pid": pid_int, "reason": reason},
        )

    return await execute_confirmed("kill_process", token, settings.analyst_id, _mock_kill_process)


@mcp.tool()
async def kill_process(
    hostname: str,
    pid: int,
    reason: str,
    confirmed: bool = False,
    confirmation_token: str = "",
) -> dict[str, Any]:
    """Terminate a process on a host via Wazuh active response. WRITE ACTION.

    Two-step action — see isolate_device for the pattern.
    WARNING: PIDs are reused. Always call device_processes() first to verify
    the PID still belongs to the malicious process before confirming.

    Args:
        hostname: Host where the process is running
        pid: Process ID to terminate
        reason: Why you are killing this process (required for audit log)
        confirmed: Set to True on second call to execute
        confirmation_token: Token from the first call's response
    """
    return await run_middleware(
        "kill_process",
        {
            "hostname": hostname,
            "pid": pid,
            "reason": reason,
            "confirmed": confirmed,
            "confirmation_token": confirmation_token,
        },
        _execute_kill_process,
    )
