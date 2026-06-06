"""OPA policy engine client.

OPA runs as a sidecar service (docker-compose). This module calls its REST API.
On failure (OPA unreachable), the default is DENY — fail closed, never open.

Set POLICY_ENFORCEMENT=false in .env to bypass for local development.
"""

import httpx
import structlog

from sentinel.config import get_settings

logger = structlog.get_logger(__name__)

_DENY_RESULT: dict[str, object] = {"allow": False, "reason": "opa_unreachable_default_deny"}


class OPAEngine:
    def __init__(self, opa_url: str) -> None:
        self._url = opa_url.rstrip("/")
        self._client = httpx.AsyncClient(timeout=httpx.Timeout(5.0))

    async def evaluate(self, policy_path: str, input_data: dict) -> dict:  # type: ignore[type-arg]
        """POST input to OPA and return the result object.

        Returns empty dict if OPA is unreachable — callers must treat missing
        keys as deny.
        """
        try:
            resp = await self._client.post(
                f"{self._url}/v1/data/{policy_path}",
                json={"input": input_data},
            )
            resp.raise_for_status()
            return resp.json().get("result", {})  # type: ignore[no-any-return]
        except Exception as exc:
            logger.warning("opa_unreachable", error=str(exc), policy=policy_path)
            return {}

    async def is_allowed(
        self,
        tool_name: str,
        analyst_id: str,
        role: str,
    ) -> tuple[bool, str]:
        """Check tool-level authorisation. Returns (allowed, reason)."""
        settings = get_settings()
        if not settings.policy_enforcement:
            logger.warning("policy_enforcement_disabled", tool=tool_name)
            return True, "enforcement_disabled"

        result = await self.evaluate(
            "sentinel/authz",
            {"tool_name": tool_name, "analyst_id": analyst_id, "role": role},
        )
        allowed: bool = bool(result.get("allow", False))
        reason: str = "policy_allow" if allowed else str(result.get("reason", "policy_deny"))
        return allowed, reason

    async def check_rate_limit(
        self,
        tool_name: str,
        analyst_id: str,
        current_count: int,
    ) -> tuple[bool, str]:
        """Check whether current_count is within the configured limit."""
        result = await self.evaluate(
            "sentinel/rate_limit",
            {
                "tool_name": tool_name,
                "analyst_id": analyst_id,
                "count": current_count,
            },
        )
        within_limit: bool = bool(result.get("allow", True))
        reason: str = str(result.get("reason", ""))
        return within_limit, reason

    async def close(self) -> None:
        await self._client.aclose()


_engine: OPAEngine | None = None


def get_opa_engine() -> OPAEngine:
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = OPAEngine(settings.opa_url)
    return _engine
