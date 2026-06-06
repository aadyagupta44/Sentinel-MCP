"""Tool call middleware pipeline.

Every tool call flows through this pipeline regardless of transport:
  1. Sanitise inputs
  2. Policy check (OPA)
  3. Rate limit check (Redis)
  4. Execute tool function
  5. Write audit log (both allowed and denied calls are logged)

The pipeline never raises — it always returns a structured response dict.
Exceptions inside the tool are caught and returned as error objects.
"""

import time
import uuid
from collections.abc import Awaitable, Callable
from typing import Any

import structlog

from sentinel.audit.log import AuditEntry, write_audit_log
from sentinel.config import get_settings
from sentinel.policy.engine import get_opa_engine

logger = structlog.get_logger(__name__)

_SENSITIVE_KEYS = frozenset(
    {"password", "token", "secret", "api_key", "credential", "auth", "key"}
)


async def run_middleware(
    tool_name: str,
    arguments: dict[str, Any],
    execute_fn: Callable[[dict[str, Any]], Awaitable[Any]],
) -> Any:
    """Run the full middleware pipeline for one tool call."""
    settings = get_settings()
    trace_id = str(uuid.uuid4())
    start = time.monotonic()

    analyst_id = settings.analyst_id
    role = settings.analyst_role
    sanitised = _sanitize_inputs(arguments)

    log = logger.bind(tool=tool_name, analyst=analyst_id, trace_id=trace_id)

    # ── 1. Policy check ───────────────────────────────────────────────────────
    opa = get_opa_engine()
    allowed, policy_reason = await opa.is_allowed(tool_name, analyst_id, role)

    if not allowed:
        duration_ms = _elapsed_ms(start)
        await _audit(
            analyst_id, tool_name, sanitised,
            {"allow": False, "reason": policy_reason},
            "denied", duration_ms, trace_id,
        )
        log.warning("tool_denied_by_policy", reason=policy_reason)
        return {
            "error": "Access denied by policy",
            "code": "POLICY_DENIED",
            "reason": policy_reason,
        }

    # ── 2. Rate limit check ───────────────────────────────────────────────────
    if settings.rate_limit_enabled:
        current_count = await _get_rate_count(tool_name, analyst_id)
        within_limit, _ = await opa.check_rate_limit(tool_name, analyst_id, current_count)
        if not within_limit:
            duration_ms = _elapsed_ms(start)
            await _audit(
                analyst_id, tool_name, sanitised,
                {"allow": False, "reason": "rate_limit_exceeded"},
                "rate_limited", duration_ms, trace_id,
            )
            log.warning("tool_rate_limited")
            return {
                "error": "Rate limit exceeded",
                "code": "RATE_LIMIT_EXCEEDED",
                "retry_after_seconds": 60,
            }

    # ── 3. Execute ────────────────────────────────────────────────────────────
    response_code = "success"
    result: Any = None
    try:
        result = await execute_fn(arguments)
    except Exception as exc:
        response_code = "error"
        log.error("tool_execution_error", error=str(exc))
        result = {"error": str(exc), "code": "INTERNAL_ERROR"}

    # ── 4. Audit ──────────────────────────────────────────────────────────────
    duration_ms = _elapsed_ms(start)
    await _audit(
        analyst_id, tool_name, sanitised,
        {"allow": True, "reason": policy_reason},
        response_code, duration_ms, trace_id,
    )

    log.info("tool_called", duration_ms=duration_ms, response_code=response_code)
    return result


def _sanitize_inputs(inputs: dict[str, Any]) -> dict[str, Any]:
    return {
        k: "[REDACTED]" if any(s in k.lower() for s in _SENSITIVE_KEYS) else v
        for k, v in inputs.items()
    }


def _elapsed_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)


async def _audit(
    analyst_id: str,
    tool_name: str,
    input_summary: dict[str, Any],
    policy_result: dict[str, Any],
    response_code: str,
    duration_ms: int,
    trace_id: str,
) -> None:
    try:
        await write_audit_log(
            AuditEntry(
                analyst_id=analyst_id,
                tool_name=tool_name,
                input_summary=input_summary,
                policy_result=policy_result,
                response_code=response_code,
                duration_ms=duration_ms,
                trace_id=trace_id,
            )
        )
    except Exception as exc:
        logger.error("audit_write_failed", error=str(exc), tool=tool_name)


async def _get_rate_count(tool_name: str, analyst_id: str) -> int:
    """Return current request count for this analyst+tool in the past minute.

    Uses Redis sorted-set sliding window. Falls back to 0 if Redis is down
    (fail open on rate limiting — fail closed on policy).
    """
    try:
        import time as _time

        import redis.asyncio as aioredis

        from sentinel.config import get_settings as _gs

        r = aioredis.from_url(_gs().redis_url, decode_responses=True)
        now = _time.time()
        window_start = now - 60
        key = f"rl:{analyst_id}:{tool_name}"

        pipe = r.pipeline()
        pipe.zremrangebyscore(key, "-inf", window_start)
        pipe.zadd(key, {str(now): now})
        pipe.zcard(key)
        pipe.expire(key, 120)
        results = await pipe.execute()
        await r.aclose()
        return int(results[2])
    except Exception as exc:
        logger.warning("redis_rate_limit_error", error=str(exc))
        return 0
