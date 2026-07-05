"""Firewall adapter — durable IP block list + perimeter firewall push.

This is the real backend for the `block_ip` write tool. Two layers:

  1. Durable block list (system of record): every confirmed block is written
     to the Postgres `blocked_ips` table. This is authoritative and survives a
     firewall outage — the sentinel://watchlist/ips resource reads from here.
  2. Perimeter firewall push (optional): when FIREWALL_ENABLED=true and an API
     key is configured, the block is also pushed to the firewall's REST API so
     traffic is actually dropped at the edge.

Mock mode (MOCK_ADAPTERS=true, the default) touches nothing external and no DB:
it returns a deterministic stub so unit/integration tests stay hermetic.
"""

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from sentinel.adapters.base import BaseAdapter, CircuitOpenError
from sentinel.config import get_settings


class FirewallAdapter(BaseAdapter):
    adapter_name = "firewall"

    def __init__(self) -> None:
        super().__init__()
        settings = get_settings()
        self._base_url = settings.firewall_url.rstrip("/")
        self._api_key = settings.firewall_api_key
        self._enabled = settings.firewall_enabled

    async def block_ip(self, ip: str, reason: str, blocked_by: str) -> dict[str, Any]:
        """Block an IP: persist to the durable block list, then push to the edge.

        Returns a status dict describing what actually happened. Never raises for
        an unreachable firewall — the durable block is what matters, and a failed
        edge push is reported in ``firewall_pushed`` rather than losing the block.
        """
        if self.is_mock:
            return {
                "ip_address": ip,
                "action": "blocked",
                "storage": "mock",
                "firewall_pushed": False,
                "mock": True,
            }

        # ── 1. Durable block list (authoritative) ─────────────────────────────
        persisted = await self._persist_block(ip, reason, blocked_by)

        # ── 2. Perimeter firewall push (best effort) ──────────────────────────
        pushed = False
        push_error: str | None = None
        if self._enabled and self._api_key:
            pushed, push_error = await self._push_to_firewall(ip, reason)
            if pushed:
                await self._mark_pushed(ip)
        elif self._enabled:
            push_error = "firewall_enabled but FIREWALL_API_KEY not configured"

        result: dict[str, Any] = {
            "ip_address": ip,
            "action": "blocked",
            "storage": "postgres_blocklist",
            "persisted": persisted,
            "firewall_pushed": pushed,
        }
        if push_error:
            result["firewall_push_error"] = push_error
        return result

    async def list_blocks(self, limit: int = 200) -> list[dict[str, Any]]:
        """Return the current active block list for the watchlist resource."""
        if self.is_mock:
            return []

        from sentinel.db.models import BlockedIP
        from sentinel.db.session import get_session_factory

        try:
            factory = get_session_factory()
            async with factory() as session:
                rows = (
                    await session.execute(
                        select(BlockedIP)
                        .where(BlockedIP.active.is_(True))
                        .order_by(BlockedIP.blocked_at.desc())
                        .limit(limit)
                    )
                ).scalars()
                return [
                    {
                        "ip": row.ip_address,
                        "reason": row.reason,
                        "blocked_by": row.blocked_by,
                        "blocked_at": row.blocked_at.isoformat() if row.blocked_at else None,
                        "firewall_pushed": row.firewall_pushed,
                    }
                    for row in rows
                ]
        except Exception as exc:
            self._log.warning("firewall_list_blocks_failed", error=str(exc))
            return []

    # ── internals ─────────────────────────────────────────────────────────────

    async def _persist_block(self, ip: str, reason: str, blocked_by: str) -> bool:
        """Upsert the block into Postgres. Re-blocking an IP refreshes its row."""
        from sentinel.db.models import BlockedIP
        from sentinel.db.session import get_session_factory

        try:
            factory = get_session_factory()
            async with factory() as session:
                stmt = pg_insert(BlockedIP).values(
                    ip_address=ip,
                    reason=reason,
                    blocked_by=blocked_by,
                    blocked_at=datetime.now(UTC),
                    active=True,
                    firewall_pushed=False,
                )
                stmt = stmt.on_conflict_do_update(
                    index_elements=["ip_address"],
                    set_={
                        "reason": reason,
                        "blocked_by": blocked_by,
                        "blocked_at": datetime.now(UTC),
                        "active": True,
                    },
                )
                await session.execute(stmt)
                await session.commit()
            return True
        except Exception as exc:
            self._log.error("firewall_persist_failed", error=str(exc), ip=ip)
            return False

    async def _mark_pushed(self, ip: str) -> None:
        from sentinel.db.models import BlockedIP
        from sentinel.db.session import get_session_factory

        try:
            factory = get_session_factory()
            async with factory() as session:
                row = (
                    await session.execute(
                        select(BlockedIP).where(BlockedIP.ip_address == ip)
                    )
                ).scalar_one_or_none()
                if row is not None:
                    row.firewall_pushed = True
                    await session.commit()
        except Exception as exc:
            self._log.warning("firewall_mark_pushed_failed", error=str(exc), ip=ip)

    async def _push_to_firewall(self, ip: str, reason: str) -> tuple[bool, str | None]:
        """Push the block rule to the firewall REST API. Returns (ok, error)."""
        if self._breaker.is_open():
            return False, "circuit_open"
        try:
            resp = await self._call(
                "POST",
                f"{self._base_url}/api/v1/block",
                span_name="block_ip",
                headers={
                    "Authorization": f"Bearer {self._api_key}",
                    "Content-Type": "application/json",
                },
                json={"ip": ip, "reason": reason, "direction": "both"},
            )
            resp.raise_for_status()
            return True, None
        except CircuitOpenError:
            return False, "circuit_open"
        except Exception as exc:
            self._log.warning("firewall_push_failed", error=str(exc), ip=ip)
            return False, str(exc)


_adapter: FirewallAdapter | None = None


def get_firewall_adapter() -> FirewallAdapter:
    global _adapter
    if _adapter is None:
        _adapter = FirewallAdapter()
    return _adapter
