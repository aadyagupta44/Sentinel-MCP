"""Firewall adapter tests — respx-mocked, no real network or database.

The firewall adapter has two layers: a durable Postgres block list (system of
record) and an optional perimeter-firewall REST push. Tests stub the DB layer
(_persist_block / _mark_pushed / list_blocks) so they stay hermetic, and use
respx for the firewall push. Optional adapter: the push is gated on
`_enabled` (FIREWALL_ENABLED) plus a configured API key.
"""

from unittest.mock import AsyncMock

from httpx import ConnectError, Response

from sentinel.adapters.firewall import FirewallAdapter, get_firewall_adapter

BLOCK_URL = "https://localhost:8443/api/v1/block"

IP = "185.220.101.34"
REASON = "Known Emotet C2"
BY = "senior@acmecorp.com"


# ── Mock mode ─────────────────────────────────────────────────────────────────


class TestFirewallMockMode:
    async def test_block_ip_mock_returns_stub(self):
        adapter = FirewallAdapter()
        result = await adapter.block_ip(IP, REASON, BY)
        assert result["action"] == "blocked"
        assert result["mock"] is True
        assert result["firewall_pushed"] is False
        await adapter.close()

    async def test_list_blocks_mock_is_empty(self):
        adapter = FirewallAdapter()
        assert await adapter.list_blocks() == []
        await adapter.close()


# ── Live mode: durable persistence, firewall disabled ─────────────────────────


class TestFirewallDisabled:
    async def test_block_persists_but_does_not_push(self, live_mode):
        adapter = FirewallAdapter()
        assert adapter._enabled is False
        adapter._persist_block = AsyncMock(return_value=True)

        result = await adapter.block_ip(IP, REASON, BY)

        assert result["action"] == "blocked"
        assert result["storage"] == "postgres_blocklist"
        assert result["persisted"] is True
        assert result["firewall_pushed"] is False
        adapter._persist_block.assert_awaited_once_with(IP, REASON, BY)
        await adapter.close()


# ── Live mode: firewall enabled ───────────────────────────────────────────────


def _enable(adapter):
    adapter._enabled = True
    adapter._api_key = "test-key"


class TestFirewallEnabled:
    async def test_block_pushes_to_firewall_on_success(self, respx_mock, live_mode):
        respx_mock.post(BLOCK_URL).mock(return_value=Response(200, json={"ok": True}))
        adapter = FirewallAdapter()
        _enable(adapter)
        adapter._persist_block = AsyncMock(return_value=True)
        adapter._mark_pushed = AsyncMock()

        result = await adapter.block_ip(IP, REASON, BY)

        assert result["firewall_pushed"] is True
        assert "firewall_push_error" not in result
        adapter._mark_pushed.assert_awaited_once_with(IP)
        await adapter.close()

    async def test_block_survives_firewall_transport_error(self, respx_mock, live_mode):
        respx_mock.post(BLOCK_URL).mock(side_effect=ConnectError("edge down"))
        adapter = FirewallAdapter()
        _enable(adapter)
        adapter._persist_block = AsyncMock(return_value=True)

        result = await adapter.block_ip(IP, REASON, BY)

        # The durable block still succeeds; only the edge push failed.
        assert result["action"] == "blocked"
        assert result["persisted"] is True
        assert result["firewall_pushed"] is False
        assert "firewall_push_error" in result
        await adapter.close()

    async def test_enabled_without_api_key_reports_error(self, live_mode):
        adapter = FirewallAdapter()
        adapter._enabled = True
        adapter._api_key = ""  # enabled but misconfigured
        adapter._persist_block = AsyncMock(return_value=True)

        result = await adapter.block_ip(IP, REASON, BY)

        assert result["firewall_pushed"] is False
        assert "API_KEY not configured" in result["firewall_push_error"]
        await adapter.close()

    async def test_push_skipped_when_circuit_open(self, live_mode):
        adapter = FirewallAdapter()
        _enable(adapter)
        adapter._persist_block = AsyncMock(return_value=True)
        for _ in range(5):
            await adapter._breaker.record_failure()

        result = await adapter.block_ip(IP, REASON, BY)

        assert result["firewall_pushed"] is False
        assert result["firewall_push_error"] == "circuit_open"
        await adapter.close()


def test_get_firewall_adapter_is_singleton():
    assert get_firewall_adapter() is get_firewall_adapter()
