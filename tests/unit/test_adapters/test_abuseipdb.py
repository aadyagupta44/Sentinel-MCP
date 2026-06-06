"""AbuseIPDB adapter tests — respx-mocked, no real network.

Optional adapter gated on ABUSEIPDB_API_KEY. Single method ``check_ip``. Covers:
- mock-mode known + unknown IP
- disabled (no key) branch → {}
- enabled live path 3-test contract: success, transport error x3 → {}, circuit breaker
- the ``except CircuitOpenError: raise`` guard
"""

import pytest
from httpx import ConnectError, Response

from sentinel.adapters.abuseipdb import AbuseIPDBAdapter, get_abuseipdb_adapter
from sentinel.adapters.base import CircuitOpenError

CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
IP = "1.2.3.4"


def _enable(adapter):
    adapter._enabled = True
    adapter._api_key = "test-key"
    return adapter


# ── Mock mode (suite default) ─────────────────────────────────────────────────


class TestAbuseIPDBMockMode:
    async def test_known_ip_returns_mock(self):
        adapter = AbuseIPDBAdapter()
        result = await adapter.check_ip("185.220.101.34")
        assert result["abuseConfidenceScore"] == 100
        await adapter.close()

    async def test_unknown_ip_returns_default(self):
        adapter = AbuseIPDBAdapter()
        result = await adapter.check_ip(IP)
        assert result["abuseConfidenceScore"] == 0
        assert result["countryCode"] == "XX"
        await adapter.close()


# ── Disabled (live mode, no API key) ──────────────────────────────────────────


class TestAbuseIPDBDisabled:
    async def test_check_ip_disabled(self, live_mode):
        adapter = AbuseIPDBAdapter()
        adapter._enabled = False
        assert await adapter.check_ip(IP) == {}
        await adapter.close()


# ── Enabled live HTTP path ────────────────────────────────────────────────────


class TestAbuseIPDBSuccess:
    async def test_check_ip_success(self, respx_mock, live_mode):
        respx_mock.get(CHECK_URL).mock(
            return_value=Response(
                200, json={"data": {"abuseConfidenceScore": 75, "countryCode": "DE"}}
            )
        )
        adapter = _enable(AbuseIPDBAdapter())
        result = await adapter.check_ip(IP, max_age_days=30)
        assert result["abuseConfidenceScore"] == 75
        assert result["countryCode"] == "DE"
        await adapter.close()


# ── Transport error → retry x3 → graceful {} ──────────────────────────────────


class TestAbuseIPDBGracefulDegradation:
    async def test_transport_error_retries_then_empty(self, respx_mock, live_mode):
        route = respx_mock.get(CHECK_URL).mock(side_effect=ConnectError("boom"))
        adapter = _enable(AbuseIPDBAdapter())
        result = await adapter.check_ip(IP)
        assert result == {}
        assert route.call_count == 3
        await adapter.close()


# ── Circuit breaker ───────────────────────────────────────────────────────────


class TestAbuseIPDBCircuitBreaker:
    async def test_circuit_opens_after_five_failures(self, respx_mock, live_mode):
        respx_mock.get(CHECK_URL).mock(side_effect=ConnectError("down"))
        adapter = _enable(AbuseIPDBAdapter())
        for _ in range(5):
            assert await adapter.check_ip(IP) == {}
        assert adapter._breaker.is_open()
        with pytest.raises(CircuitOpenError):
            await adapter.check_ip(IP)
        await adapter.close()

    async def test_circuit_open_error_from_call_propagates(self, live_mode, monkeypatch):
        # Covers the `except CircuitOpenError: raise` guard inside check_ip.
        adapter = _enable(AbuseIPDBAdapter())

        async def _raise(*_a, **_k):
            raise CircuitOpenError("opened mid-call")

        monkeypatch.setattr(adapter, "_call", _raise)
        with pytest.raises(CircuitOpenError):
            await adapter.check_ip(IP)
        await adapter.close()


def test_get_abuseipdb_adapter_is_singleton():
    assert get_abuseipdb_adapter() is get_abuseipdb_adapter()
