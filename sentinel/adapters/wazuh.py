"""Wazuh EDR adapter — process events, network events, agent isolation.

Uses Wazuh REST API (v4) with API key authentication.
Optional — only active if WAZUH_ENABLED=true.
Resource-heavy to run locally (8GB+ RAM). Mock adapter is default.

Wraps: list agents, search process events, search network events,
       isolate agent, kill process via active response.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from sentinel.adapters.base import BaseAdapter, CircuitOpenError
from sentinel.config import get_settings
from sentinel.tools import mock_data as mock


class WazuhAdapter(BaseAdapter):
    adapter_name = "wazuh"

    def __init__(self) -> None:
        super().__init__()
        settings = get_settings()
        self._base_url = settings.wazuh_url.rstrip("/")
        self._api_key = settings.wazuh_api_key
        self._enabled = settings.wazuh_enabled
        self._headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    def _is_available(self) -> bool:
        return self.is_mock or self._enabled

    async def get_processes(
        self, hostname: str, time_window_minutes: int = 60
    ) -> list[dict[str, Any]]:
        if self.is_mock:
            return mock.device_processes(hostname, time_window_minutes)
        if not self._enabled:
            return []

        agent_id = await self._get_agent_id(hostname)
        if not agent_id:
            return []

        since = datetime.now(UTC) - timedelta(minutes=time_window_minutes)
        return await self._search_events(
            agent_id=agent_id,
            event_type="process",
            since=since,
        )

    async def get_network_connections(
        self, hostname: str, time_window_minutes: int = 60
    ) -> list[dict[str, Any]]:
        if self.is_mock:
            return mock.network_connections(hostname, time_window_minutes)
        if not self._enabled:
            return []

        agent_id = await self._get_agent_id(hostname)
        if not agent_id:
            return []

        since = datetime.now(UTC) - timedelta(minutes=time_window_minutes)
        return await self._search_events(
            agent_id=agent_id,
            event_type="network",
            since=since,
        )

    async def isolate_agent(self, hostname: str) -> dict[str, Any]:
        """Isolate a Wazuh agent from the network."""
        if self.is_mock:
            return {"hostname": hostname, "action": "isolated", "mock": True}
        if not self._enabled:
            return {"error": "Wazuh not enabled", "code": "WAZUH_DISABLED"}

        agent_id = await self._get_agent_id(hostname)
        if not agent_id:
            return {
                "error": f"Agent not found for hostname '{hostname}'",
                "code": "AGENT_NOT_FOUND",
            }

        if self._breaker.is_open():
            raise CircuitOpenError(self.adapter_name)

        try:
            resp = await self._call(
                "PUT",
                f"{self._base_url}/agents/{agent_id}/group/default",
                span_name="isolate_agent",
                headers=self._headers,
                params={"force_single_group": True},
            )
            resp.raise_for_status()
            return {"hostname": hostname, "agent_id": agent_id, "action": "isolated"}
        except CircuitOpenError:
            raise
        except Exception as exc:
            self._log.warning("wazuh_isolate_failed", error=str(exc), hostname=hostname)
            return {"error": str(exc), "code": "WAZUH_ERROR"}

    async def kill_process(self, hostname: str, pid: int) -> dict[str, Any]:
        """Terminate a process via Wazuh active response."""
        if self.is_mock:
            return {"hostname": hostname, "pid": pid, "action": "killed", "mock": True}
        if not self._enabled:
            return {"error": "Wazuh not enabled", "code": "WAZUH_DISABLED"}

        agent_id = await self._get_agent_id(hostname)
        if not agent_id:
            return {
                "error": f"Agent not found for hostname '{hostname}'",
                "code": "AGENT_NOT_FOUND",
            }

        if self._breaker.is_open():
            raise CircuitOpenError(self.adapter_name)

        try:
            resp = await self._call(
                "PUT",
                f"{self._base_url}/active-response",
                span_name="kill_process",
                headers=self._headers,
                json={
                    "command": "kill-process",
                    "arguments": [str(pid)],
                    "alert": {"id": agent_id},
                },
                params={"agents_list": agent_id},
            )
            resp.raise_for_status()
            return {"hostname": hostname, "pid": pid, "action": "killed"}
        except CircuitOpenError:
            raise
        except Exception as exc:
            self._log.warning("wazuh_kill_failed", error=str(exc), hostname=hostname, pid=pid)
            return {"error": str(exc), "code": "WAZUH_ERROR"}

    async def _get_agent_id(self, hostname: str) -> str | None:
        if self._breaker.is_open():
            return None
        try:
            resp = await self._call(
                "GET",
                f"{self._base_url}/agents",
                span_name="get_agent",
                headers=self._headers,
                params={"name": hostname, "select": "id,name"},
            )
            resp.raise_for_status()
            items = resp.json().get("data", {}).get("affected_items", [])
            return items[0]["id"] if items else None
        except Exception as exc:
            self._log.warning("wazuh_get_agent_failed", error=str(exc), hostname=hostname)
            return None

    async def _search_events(
        self, agent_id: str, event_type: str, since: datetime
    ) -> list[dict[str, Any]]:
        if self._breaker.is_open():
            raise CircuitOpenError(self.adapter_name)
        try:
            resp = await self._call(
                "GET",
                f"{self._base_url}/agents/{agent_id}/syscheck",
                span_name=f"search_{event_type}",
                headers=self._headers,
                params={"date": since.isoformat(), "type": event_type, "limit": 500},
            )
            resp.raise_for_status()
            items: list[dict[str, Any]] = resp.json().get("data", {}).get("affected_items", [])
            return items
        except CircuitOpenError:
            raise
        except Exception as exc:
            self._log.warning("wazuh_search_failed", error=str(exc), event_type=event_type)
            return []


_adapter: WazuhAdapter | None = None


def get_wazuh_adapter() -> WazuhAdapter:
    global _adapter
    if _adapter is None:
        _adapter = WazuhAdapter()
    return _adapter
