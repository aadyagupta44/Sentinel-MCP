"""Wazuh EDR adapter tests — respx-mocked, no real network.

Wazuh resolves an agent id (via _call GET /agents) before each operation, then
performs the operation via _call. Optional adapter: gated on `_enabled`
(WAZUH_ENABLED). Tests enable it by setting `adapter._enabled = True`.
"""

from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from httpx import ConnectError, Response

from sentinel.adapters.base import CircuitOpenError
from sentinel.adapters.wazuh import WazuhAdapter, get_wazuh_adapter

AGENTS_URL = "https://localhost:55000/agents"
SYSCHECK_URL = "https://localhost:55000/agents/001/syscheck"
GROUP_URL = "https://localhost:55000/agents/001/group/default"
ACTIVE_RESPONSE_URL = "https://localhost:55000/active-response"

HOST = "ws-01"


def _agents_ok(respx_mock):
    respx_mock.get(AGENTS_URL).mock(
        return_value=Response(200, json={"data": {"affected_items": [{"id": "001", "name": HOST}]}})
    )


def _enable(adapter):
    adapter._enabled = True


# ── Mock mode ─────────────────────────────────────────────────────────────────


class TestWazuhMockMode:
    async def test_get_processes_mock(self):
        adapter = WazuhAdapter()
        assert isinstance(await adapter.get_processes(HOST), list)
        await adapter.close()

    async def test_get_network_connections_mock(self):
        adapter = WazuhAdapter()
        assert isinstance(await adapter.get_network_connections(HOST), list)
        await adapter.close()

    async def test_isolate_agent_mock(self):
        adapter = WazuhAdapter()
        result = await adapter.isolate_agent(HOST)
        assert result["action"] == "isolated"
        assert result["mock"] is True
        await adapter.close()

    async def test_kill_process_mock(self):
        adapter = WazuhAdapter()
        result = await adapter.kill_process(HOST, 1234)
        assert result["action"] == "killed"
        assert result["mock"] is True
        await adapter.close()

    def test_is_available_in_mock(self):
        adapter = WazuhAdapter()
        assert adapter._is_available() is True


# ── Disabled (live, no WAZUH_ENABLED) ─────────────────────────────────────────


class TestWazuhDisabled:
    async def test_get_processes_disabled(self, live_mode):
        adapter = WazuhAdapter()
        assert adapter._enabled is False
        assert adapter._is_available() is False
        assert await adapter.get_processes(HOST) == []
        await adapter.close()

    async def test_get_network_connections_disabled(self, live_mode):
        adapter = WazuhAdapter()
        assert await adapter.get_network_connections(HOST) == []
        await adapter.close()

    async def test_isolate_agent_disabled(self, live_mode):
        adapter = WazuhAdapter()
        result = await adapter.isolate_agent(HOST)
        assert result["code"] == "WAZUH_DISABLED"
        await adapter.close()

    async def test_kill_process_disabled(self, live_mode):
        adapter = WazuhAdapter()
        result = await adapter.kill_process(HOST, 1)
        assert result["code"] == "WAZUH_DISABLED"
        await adapter.close()


# ── Enabled live path ─────────────────────────────────────────────────────────


class TestWazuhEnabled:
    async def test_get_processes_success(self, respx_mock, live_mode):
        _agents_ok(respx_mock)
        respx_mock.get(SYSCHECK_URL).mock(
            return_value=Response(
                200, json={"data": {"affected_items": [{"pid": 9, "name": "evil.exe"}]}}
            )
        )
        adapter = WazuhAdapter()
        _enable(adapter)
        result = await adapter.get_processes(HOST, time_window_minutes=30)
        assert result == [{"pid": 9, "name": "evil.exe"}]
        await adapter.close()

    async def test_get_network_connections_success(self, respx_mock, live_mode):
        _agents_ok(respx_mock)
        respx_mock.get(SYSCHECK_URL).mock(
            return_value=Response(200, json={"data": {"affected_items": [{"dst": "1.2.3.4"}]}})
        )
        adapter = WazuhAdapter()
        _enable(adapter)
        result = await adapter.get_network_connections(HOST)
        assert result == [{"dst": "1.2.3.4"}]
        await adapter.close()

    async def test_get_processes_agent_not_found(self, respx_mock, live_mode):
        respx_mock.get(AGENTS_URL).mock(
            return_value=Response(200, json={"data": {"affected_items": []}})
        )
        adapter = WazuhAdapter()
        _enable(adapter)
        assert await adapter.get_processes(HOST) == []
        await adapter.close()

    async def test_get_network_connections_agent_not_found(self, respx_mock, live_mode):
        respx_mock.get(AGENTS_URL).mock(
            return_value=Response(200, json={"data": {"affected_items": []}})
        )
        adapter = WazuhAdapter()
        _enable(adapter)
        assert await adapter.get_network_connections(HOST) == []
        await adapter.close()

    async def test_search_events_error_returns_empty(self, respx_mock, live_mode):
        _agents_ok(respx_mock)
        respx_mock.get(SYSCHECK_URL).mock(side_effect=ConnectError("boom"))
        adapter = WazuhAdapter()
        _enable(adapter)
        assert await adapter.get_processes(HOST) == []
        await adapter.close()

    async def test_isolate_agent_success(self, respx_mock, live_mode):
        _agents_ok(respx_mock)
        respx_mock.put(GROUP_URL).mock(return_value=Response(200, json={}))
        adapter = WazuhAdapter()
        _enable(adapter)
        result = await adapter.isolate_agent(HOST)
        assert result["action"] == "isolated"
        assert result["agent_id"] == "001"
        await adapter.close()

    async def test_isolate_agent_not_found(self, respx_mock, live_mode):
        respx_mock.get(AGENTS_URL).mock(
            return_value=Response(200, json={"data": {"affected_items": []}})
        )
        adapter = WazuhAdapter()
        _enable(adapter)
        result = await adapter.isolate_agent(HOST)
        assert result["code"] == "AGENT_NOT_FOUND"
        await adapter.close()

    async def test_isolate_agent_transport_error(self, respx_mock, live_mode):
        _agents_ok(respx_mock)
        respx_mock.put(GROUP_URL).mock(side_effect=ConnectError("boom"))
        adapter = WazuhAdapter()
        _enable(adapter)
        result = await adapter.isolate_agent(HOST)
        assert result["code"] == "WAZUH_ERROR"
        await adapter.close()

    async def test_kill_process_success(self, respx_mock, live_mode):
        _agents_ok(respx_mock)
        respx_mock.put(ACTIVE_RESPONSE_URL).mock(return_value=Response(200, json={}))
        adapter = WazuhAdapter()
        _enable(adapter)
        result = await adapter.kill_process(HOST, 4321)
        assert result["action"] == "killed"
        assert result["pid"] == 4321
        await adapter.close()

    async def test_kill_process_not_found(self, respx_mock, live_mode):
        respx_mock.get(AGENTS_URL).mock(
            return_value=Response(200, json={"data": {"affected_items": []}})
        )
        adapter = WazuhAdapter()
        _enable(adapter)
        result = await adapter.kill_process(HOST, 1)
        assert result["code"] == "AGENT_NOT_FOUND"
        await adapter.close()

    async def test_kill_process_transport_error(self, respx_mock, live_mode):
        _agents_ok(respx_mock)
        respx_mock.put(ACTIVE_RESPONSE_URL).mock(side_effect=ConnectError("boom"))
        adapter = WazuhAdapter()
        _enable(adapter)
        result = await adapter.kill_process(HOST, 1)
        assert result["code"] == "WAZUH_ERROR"
        await adapter.close()


# ── _get_agent_id helper ──────────────────────────────────────────────────────


class TestWazuhGetAgentId:
    async def test_returns_none_when_circuit_open(self, live_mode):
        adapter = WazuhAdapter()
        _enable(adapter)
        for _ in range(5):
            await adapter._breaker.record_failure()
        assert await adapter._get_agent_id(HOST) is None
        await adapter.close()

    async def test_returns_none_on_error(self, respx_mock, live_mode):
        respx_mock.get(AGENTS_URL).mock(side_effect=ConnectError("boom"))
        adapter = WazuhAdapter()
        _enable(adapter)
        assert await adapter._get_agent_id(HOST) is None
        await adapter.close()


# ── Circuit breaker (contract) + guards ───────────────────────────────────────


class TestWazuhCircuitBreaker:
    async def test_circuit_opens_after_five_failures(self, respx_mock, live_mode):
        respx_mock.get(SYSCHECK_URL).mock(side_effect=ConnectError("down"))
        adapter = WazuhAdapter()
        _enable(adapter)
        since = datetime.now(UTC)
        for _ in range(5):
            assert await adapter._search_events("001", "process", since) == []
        assert adapter._breaker.is_open()
        with pytest.raises(CircuitOpenError):
            await adapter._search_events("001", "process", since)
        await adapter.close()

    async def test_search_events_circuit_open_error_from_call_propagates(self, live_mode):
        adapter = WazuhAdapter()
        _enable(adapter)
        adapter._call = AsyncMock(side_effect=CircuitOpenError("x"))
        since = datetime.now(UTC)
        with pytest.raises(CircuitOpenError):
            await adapter._search_events("001", "process", since)
        await adapter.close()

    async def test_isolate_agent_circuit_open_guard(self, live_mode):
        adapter = WazuhAdapter()
        _enable(adapter)
        adapter._get_agent_id = AsyncMock(return_value="001")
        for _ in range(5):
            await adapter._breaker.record_failure()
        with pytest.raises(CircuitOpenError):
            await adapter.isolate_agent(HOST)
        await adapter.close()

    async def test_isolate_agent_circuit_open_error_from_call_propagates(self, live_mode):
        adapter = WazuhAdapter()
        _enable(adapter)
        adapter._get_agent_id = AsyncMock(return_value="001")
        adapter._call = AsyncMock(side_effect=CircuitOpenError("x"))
        with pytest.raises(CircuitOpenError):
            await adapter.isolate_agent(HOST)
        await adapter.close()

    async def test_kill_process_circuit_open_guard(self, live_mode):
        adapter = WazuhAdapter()
        _enable(adapter)
        adapter._get_agent_id = AsyncMock(return_value="001")
        for _ in range(5):
            await adapter._breaker.record_failure()
        with pytest.raises(CircuitOpenError):
            await adapter.kill_process(HOST, 1)
        await adapter.close()

    async def test_kill_process_circuit_open_error_from_call_propagates(self, live_mode):
        adapter = WazuhAdapter()
        _enable(adapter)
        adapter._get_agent_id = AsyncMock(return_value="001")
        adapter._call = AsyncMock(side_effect=CircuitOpenError("x"))
        with pytest.raises(CircuitOpenError):
            await adapter.kill_process(HOST, 1)
        await adapter.close()


def test_get_wazuh_adapter_is_singleton():
    assert get_wazuh_adapter() is get_wazuh_adapter()
