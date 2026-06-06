"""Write-tool confirmation framework.

Every write tool (isolate_device, disable_user, block_ip, kill_process)
calls these helpers instead of executing directly.

First call  (confirmed=False or no token):
  -> create_proposal() stores a pending action, returns ProposedAction

Second call (confirmed=True + valid token):
  -> execute_confirmed() validates the token, calls the real executor,
     marks the action as executed.

Storage: tries Postgres first (PendingAction table). Falls back to
an in-memory dict when Postgres is unavailable (dev/test without Docker).
"""

import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Awaitable

import structlog

from sentinel.config import get_settings

logger = structlog.get_logger(__name__)

# In-memory fallback — used when Postgres is not running
_mem_store: dict[str, dict[str, Any]] = {}


async def create_proposal(
    tool_name: str,
    analyst_id: str,
    target: str,
    description: str,
    warning: str,
    parameters: dict[str, Any],
) -> dict[str, Any]:
    """Create a pending action proposal. Returns a ProposedAction dict."""
    settings = get_settings()
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=settings.pending_action_ttl_seconds)

    proposal = {
        "action_type": tool_name,
        "description": description,
        "target": target,
        "parameters": parameters,
        "warning": warning,
        "confirmation_token": token,
        "expires_at": expires_at.isoformat(),
        "instructions": (
            f"Review the proposed action above carefully. "
            f"To execute, call {tool_name} again with confirmed=True and "
            f"confirmation_token='{token}'. "
            f"This token expires at {expires_at.strftime('%H:%M UTC')}."
        ),
    }

    # Try to persist to Postgres; fall back to in-memory
    stored = False
    try:
        from sentinel.db.session import get_session_factory
        from sentinel.db.models import PendingAction

        factory = get_session_factory()
        async with factory() as session:
            async with session.begin():
                session.add(PendingAction(
                    token=token,
                    tool_name=tool_name,
                    analyst_id=analyst_id,
                    parameters=parameters,
                    proposal=proposal,
                    expires_at=expires_at,
                    executed=False,
                ))
        stored = True
    except Exception as exc:
        logger.warning("pending_action_db_unavailable", error=str(exc), tool=tool_name)

    if not stored:
        _mem_store[token] = {
            "token": token,
            "tool_name": tool_name,
            "analyst_id": analyst_id,
            "parameters": parameters,
            "proposal": proposal,
            "expires_at": expires_at,
            "executed": False,
        }

    logger.info("proposal_created", tool=tool_name, analyst=analyst_id, token=token[:8] + "...")
    return proposal


async def execute_confirmed(
    tool_name: str,
    confirmation_token: str,
    analyst_id: str,
    executor: Callable[[dict[str, Any]], Awaitable[dict[str, Any]]],
) -> dict[str, Any]:
    """Validate token and execute the confirmed action."""
    now = datetime.now(timezone.utc)

    # Try Postgres first, fall back to in-memory
    pending = await _load_pending(tool_name, confirmation_token)

    if pending is None:
        return {
            "error": "Invalid or expired confirmation token",
            "code": "INVALID_TOKEN",
            "detail": "Token not found. It may have expired or already been used.",
        }

    expires_at = pending.get("expires_at")
    if isinstance(expires_at, str):
        expires_at = datetime.fromisoformat(expires_at)
    if expires_at and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at and now > expires_at:
        await _mark_expired(confirmation_token)
        return {
            "error": "Confirmation token expired",
            "code": "TOKEN_EXPIRED",
            "detail": f"Token expired at {expires_at.isoformat()}. Create a new proposal.",
        }

    if pending.get("executed"):
        return {
            "error": "Action already executed",
            "code": "ALREADY_EXECUTED",
            "detail": "This confirmation token has already been used.",
        }

    if pending.get("tool_name") != tool_name:
        return {
            "error": "Token mismatch",
            "code": "TOKEN_MISMATCH",
            "detail": f"Token was issued for {pending.get('tool_name')}, not {tool_name}.",
        }

    # Execute
    trace_id = str(uuid.uuid4())
    try:
        result = await executor(pending["parameters"])
        await _mark_executed(confirmation_token)
        logger.info("confirmed_action_executed", tool=tool_name, analyst=analyst_id, trace_id=trace_id)
        return {
            "action_type": tool_name,
            "target": pending["parameters"].get("hostname") or pending["parameters"].get("email") or pending["parameters"].get("ip_address", ""),
            "executed_at": now.isoformat(),
            "analyst_id": analyst_id,
            "trace_id": trace_id,
            "result": result,
        }
    except Exception as exc:
        logger.error("confirmed_action_failed", tool=tool_name, error=str(exc))
        return {"error": str(exc), "code": "EXECUTION_FAILED"}


# ── Internal helpers ──────────────────────────────────────────────────────────

async def _load_pending(tool_name: str, token: str) -> dict[str, Any] | None:
    try:
        from sqlalchemy import select
        from sentinel.db.session import get_session_factory
        from sentinel.db.models import PendingAction

        factory = get_session_factory()
        async with factory() as session:
            row = await session.scalar(
                select(PendingAction).where(PendingAction.token == token)
            )
            if row:
                return {
                    "token": row.token,
                    "tool_name": row.tool_name,
                    "analyst_id": row.analyst_id,
                    "parameters": row.parameters,
                    "proposal": row.proposal,
                    "expires_at": row.expires_at,
                    "executed": row.executed,
                }
    except Exception:
        pass
    return _mem_store.get(token)


async def _mark_executed(token: str) -> None:
    try:
        from sqlalchemy import update
        from sentinel.db.session import get_session_factory
        from sentinel.db.models import PendingAction

        factory = get_session_factory()
        async with factory() as session:
            async with session.begin():
                await session.execute(
                    update(PendingAction)
                    .where(PendingAction.token == token)
                    .values(executed=True)
                )
        return
    except Exception:
        pass
    if token in _mem_store:
        _mem_store[token]["executed"] = True


async def _mark_expired(token: str) -> None:
    _mem_store.pop(token, None)
