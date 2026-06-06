"""ip-api.com adapter tests — respx-mocked, no real network.

Contract covered for the live HTTP path:
  1. success path returns the correct structure
  2. transport error triggers retry (3 attempts) then degrades gracefully
  3. circuit breaker opens after 5 failures
Plus the mock-mode branches, the ``status == "fail"`` branch and the
CircuitOpenError-propagate guard for full coverage.

Uses the ``respx_mock`` fixture (NOT the decorator). The lookup URL carries a
``?fields=...`` query string; routes are registered without it (respx matches
regardless of query params).
"""

import pytest
from httpx import ConnectError, Response

from sentinel.adapters.base import CircuitOpenError
from sentinel.adapters.ipapi import IPApiAdapter, get_ipapi_adapter

IP = "1.2.3.4"
URL = f"http://ip-api.com/json/{IP}"


# ── Mock mode (suite default) ─────────────────────────────────────────────────


class TestIPApiMockMode:
    async def test_known_ip_returns_mock(self):
        adapter = IPApiAdapter()
        result = await adapter.lookup("185.220.101.34")
        assert result["status"] == "success"
        assert result["country"] == "Germany"
        assert result["proxy"] is True
        await adapter.close()

    async def test_unknown_ip_returns_default_shape(self):
        adapter = IPApiAdapter()
        result = await adapter.lookup("203.0.113.9")
        assert result["status"] == "success"
        assert result["query"] == "203.0.113.9"
        assert result["country"] == "Unknown"
        assert result["countryCode"] == "XX"
        await adapter.close()


# ── Live HTTP path: success / fail / error ────────────────────────────────────


class TestIPApiLive:
    async def test_success(self, respx_mock, live_mode):
        respx_mock.get(URL).mock(
            return_value=Response(
                200,
                json={"status": "success", "query": IP, "country": "Testland", "countryCode": "TL"},
            )
        )
        adapter = IPApiAdapter()
        result = await adapter.lookup(IP)
        assert result["status"] == "success"
        assert result["country"] == "Testland"
        await adapter.close()

    async def test_fail_status_returns_fail_shape(self, respx_mock, live_mode):
        respx_mock.get(URL).mock(
            return_value=Response(
                200, json={"status": "fail", "message": "private range", "query": IP}
            )
        )
        adapter = IPApiAdapter()
        result = await adapter.lookup(IP)
        assert result == {"status": "fail", "query": IP}
        await adapter.close()

    async def test_transport_error_retries_then_degrades(self, respx_mock, live_mode):
        route = respx_mock.get(URL).mock(side_effect=ConnectError("boom"))
        adapter = IPApiAdapter()
        result = await adapter.lookup(IP)
        assert result["status"] == "error"
        assert result["query"] == IP
        assert "error" in result
        assert route.call_count == 3  # tenacity retried 3 times before giving up
        await adapter.close()


# ── Circuit breaker ───────────────────────────────────────────────────────────


class TestIPApiCircuitBreaker:
    async def test_circuit_opens_after_five_failures(self, respx_mock, live_mode):
        respx_mock.get(URL).mock(side_effect=ConnectError("down"))
        adapter = IPApiAdapter()
        for _ in range(5):
            await adapter.lookup(IP)
        assert adapter._breaker.is_open()
        with pytest.raises(CircuitOpenError):
            await adapter.lookup(IP)
        await adapter.close()

    async def test_circuit_open_error_from_call_propagates(self, live_mode, monkeypatch):
        # Covers the `except CircuitOpenError: raise` guard inside the try block,
        # which the top-level is_open() check would otherwise short-circuit.
        adapter = IPApiAdapter()

        async def _raise(*_a, **_k):
            raise CircuitOpenError("opened mid-call")

        monkeypatch.setattr(adapter, "_call", _raise)
        with pytest.raises(CircuitOpenError):
            await adapter.lookup(IP)
        await adapter.close()


# ── Singleton accessor ────────────────────────────────────────────────────────


def test_get_ipapi_adapter_is_singleton():
    assert get_ipapi_adapter() is get_ipapi_adapter()
