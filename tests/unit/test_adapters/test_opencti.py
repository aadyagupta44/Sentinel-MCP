"""OpenCTI adapter tests — respx-mocked, no real network.

OpenCTI is an OPTIONAL adapter (active only when OPENCTI_ENABLED=true and a
token is configured). To exercise the live GraphQL path we construct the
adapter in ``live_mode`` then force ``_enabled``/``_token`` on.

Contract covered for the live HTTP path:
  1. success path returns the correct structure
  2. transport error triggers retry (3 attempts) then degrades gracefully ({})
  3. circuit breaker opens after 5 failures
Plus mock-mode, the disabled branch, and the CircuitOpenError-propagate guard
for full coverage.
"""

import pytest
from httpx import ConnectError, Response

from sentinel.adapters.base import CircuitOpenError
from sentinel.adapters.opencti import OpenCTIAdapter, get_opencti_adapter

GRAPHQL_URL = "http://localhost:8082/graphql"


def _enable(adapter):
    adapter._enabled = True
    adapter._token = "test-token"
    return adapter


# ── Mock mode (suite default) ─────────────────────────────────────────────────


class TestOpenCTIMockMode:
    async def test_search_indicator_returns_mock(self):
        adapter = OpenCTIAdapter()
        result = await adapter.search_indicator("1.2.3.4")
        assert result == {"indicators": [], "source": "opencti_mock"}
        await adapter.close()


# ── Disabled branch (live, but not enabled) ───────────────────────────────────


class TestOpenCTIDisabled:
    async def test_disabled_returns_empty(self, respx_mock, live_mode):
        adapter = OpenCTIAdapter()  # no token configured → _enabled False
        assert adapter._enabled is False
        result = await adapter.search_indicator("1.2.3.4")
        assert result == {}
        await adapter.close()


# ── Live HTTP path: success ───────────────────────────────────────────────────


class TestOpenCTISuccess:
    async def test_success(self, respx_mock, live_mode):
        node = {
            "id": "indicator--abc",
            "name": "Evil IP",
            "description": "bad",
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
            "valid_from": "2026-01-01",
            "valid_until": "2026-12-31",
            "x_opencti_score": 80,
            "createdBy": {"name": "analyst"},
            "objectLabel": {"edges": [{"node": {"value": "malware"}}]},
        }
        respx_mock.post(GRAPHQL_URL).mock(
            return_value=Response(200, json={"data": {"indicators": {"edges": [{"node": node}]}}})
        )
        adapter = _enable(OpenCTIAdapter())
        result = await adapter.search_indicator("1.2.3.4")
        assert result == {"indicators": [node], "total": 1}
        await adapter.close()


# ── Live HTTP path: transport error → retry → graceful degradation ────────────


class TestOpenCTIGracefulDegradation:
    async def test_transport_error_retries_then_degrades(self, respx_mock, live_mode):
        route = respx_mock.post(GRAPHQL_URL).mock(side_effect=ConnectError("boom"))
        adapter = _enable(OpenCTIAdapter())
        result = await adapter.search_indicator("1.2.3.4")
        assert result == {}
        assert route.call_count == 3  # tenacity retried 3 times before giving up
        await adapter.close()


# ── Live HTTP path: circuit breaker ───────────────────────────────────────────


class TestOpenCTICircuitBreaker:
    async def test_circuit_opens_after_five_failures(self, respx_mock, live_mode):
        respx_mock.post(GRAPHQL_URL).mock(side_effect=ConnectError("down"))
        adapter = _enable(OpenCTIAdapter())

        for _ in range(5):
            assert await adapter.search_indicator("1.2.3.4") == {}

        assert adapter._breaker.is_open()
        with pytest.raises(CircuitOpenError):
            await adapter.search_indicator("1.2.3.4")
        await adapter.close()

    async def test_circuit_open_error_from_call_propagates(self, live_mode, monkeypatch):
        # Covers the `except CircuitOpenError: raise` guard inside the try block,
        # which the top-level is_open() check would otherwise short-circuit.
        adapter = _enable(OpenCTIAdapter())

        async def _raise(*_a, **_k):
            raise CircuitOpenError("opened mid-call")

        monkeypatch.setattr(adapter, "_call", _raise)
        with pytest.raises(CircuitOpenError):
            await adapter.search_indicator("1.2.3.4")
        await adapter.close()


# ── Singleton accessor ────────────────────────────────────────────────────────


def test_get_opencti_adapter_is_singleton():
    assert get_opencti_adapter() is get_opencti_adapter()
