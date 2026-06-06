"""AlienVault OTX adapter tests — respx-mocked, no real network.

Optional adapter gated on ALIENVAULT_OTX_API_KEY. Covers:
- mock-mode branch of every public method
- disabled (no key) branch of every public method → {}
- the shared ``_lookup`` 3-test contract on the enabled live path:
    (a) success → json, (b) transport error → retry x3 → {}, (c) circuit breaker
- 404 branch
- the ``except CircuitOpenError: raise`` guard
"""

import urllib.parse

import pytest
from httpx import ConnectError, Response

from sentinel.adapters.alienvault import AlienVaultAdapter, get_alienvault_adapter
from sentinel.adapters.base import CircuitOpenError

_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"
IP = "1.2.3.4"
DOMAIN = "evil.example"
HASH = "44d88612fea8a8f36de82e1278abb02f"
URL = "http://evil.example/x?a=b"

IP_URL = f"{_BASE_URL}/IPv4/{IP}/general"
DOMAIN_URL = f"{_BASE_URL}/domain/{DOMAIN}/general"
HASH_URL = f"{_BASE_URL}/file/{HASH}/general"
URL_URL = f"{_BASE_URL}/url/{urllib.parse.quote(URL, safe='')}/general"


def _enable(adapter):
    """Force the optional adapter into the enabled live HTTP code path."""
    adapter._enabled = True
    adapter._api_key = "test-key"
    return adapter


# ── Mock mode (suite default) ─────────────────────────────────────────────────


class TestAlienVaultMockMode:
    async def test_lookup_ip_known(self):
        adapter = AlienVaultAdapter()
        result = await adapter.lookup_ip("185.220.101.34")
        assert result["general"]["pulse_count"] == 47
        await adapter.close()

    async def test_lookup_ip_default(self):
        adapter = AlienVaultAdapter()
        result = await adapter.lookup_ip(IP)
        assert result["general"]["indicator"] == IP
        assert result["general"]["pulse_count"] == 0
        await adapter.close()

    async def test_lookup_domain_default(self):
        adapter = AlienVaultAdapter()
        result = await adapter.lookup_domain(DOMAIN)
        assert result["general"]["indicator"] == DOMAIN
        await adapter.close()

    async def test_lookup_hash_known(self):
        adapter = AlienVaultAdapter()
        result = await adapter.lookup_hash(HASH.upper())
        assert "Emotet" in result["general"]["malware_families"]
        await adapter.close()

    async def test_lookup_hash_default(self):
        adapter = AlienVaultAdapter()
        result = await adapter.lookup_hash("deadbeef")
        assert result["general"]["indicator"] == "deadbeef"
        await adapter.close()

    async def test_lookup_url_default(self):
        adapter = AlienVaultAdapter()
        result = await adapter.lookup_url(URL)
        assert result["general"]["indicator"] == URL
        await adapter.close()


# ── Disabled (live mode, no API key) → every method returns {} ────────────────


class TestAlienVaultDisabled:
    async def test_lookup_ip_disabled(self, live_mode):
        adapter = AlienVaultAdapter()
        adapter._enabled = False
        assert await adapter.lookup_ip(IP) == {}
        await adapter.close()

    async def test_lookup_domain_disabled(self, live_mode):
        adapter = AlienVaultAdapter()
        adapter._enabled = False
        assert await adapter.lookup_domain(DOMAIN) == {}
        await adapter.close()

    async def test_lookup_hash_disabled(self, live_mode):
        adapter = AlienVaultAdapter()
        adapter._enabled = False
        assert await adapter.lookup_hash(HASH) == {}
        await adapter.close()

    async def test_lookup_url_disabled(self, live_mode):
        adapter = AlienVaultAdapter()
        adapter._enabled = False
        assert await adapter.lookup_url(URL) == {}
        await adapter.close()


# ── Enabled live HTTP path: success (one per method to cover URL builders) ─────


class TestAlienVaultSuccess:
    async def test_lookup_ip_success(self, respx_mock, live_mode):
        respx_mock.get(IP_URL).mock(
            return_value=Response(200, json={"general": {"indicator": IP, "pulse_count": 5}})
        )
        adapter = _enable(AlienVaultAdapter())
        result = await adapter.lookup_ip(IP)
        assert result["general"]["pulse_count"] == 5
        await adapter.close()

    async def test_lookup_domain_success(self, respx_mock, live_mode):
        respx_mock.get(DOMAIN_URL).mock(
            return_value=Response(200, json={"general": {"indicator": DOMAIN}})
        )
        adapter = _enable(AlienVaultAdapter())
        result = await adapter.lookup_domain(DOMAIN)
        assert result["general"]["indicator"] == DOMAIN
        await adapter.close()

    async def test_lookup_hash_success(self, respx_mock, live_mode):
        respx_mock.get(HASH_URL).mock(
            return_value=Response(200, json={"general": {"indicator": HASH}})
        )
        adapter = _enable(AlienVaultAdapter())
        result = await adapter.lookup_hash(HASH)
        assert result["general"]["indicator"] == HASH
        await adapter.close()

    async def test_lookup_url_success(self, respx_mock, live_mode):
        respx_mock.get(URL_URL).mock(
            return_value=Response(200, json={"general": {"indicator": URL}})
        )
        adapter = _enable(AlienVaultAdapter())
        result = await adapter.lookup_url(URL)
        assert result["general"]["indicator"] == URL
        await adapter.close()

    async def test_lookup_404_returns_empty(self, respx_mock, live_mode):
        respx_mock.get(IP_URL).mock(return_value=Response(404, json={}))
        adapter = _enable(AlienVaultAdapter())
        assert await adapter.lookup_ip(IP) == {}
        await adapter.close()


# ── Transport error → retry x3 → graceful {} ──────────────────────────────────


class TestAlienVaultGracefulDegradation:
    async def test_transport_error_retries_then_empty(self, respx_mock, live_mode):
        route = respx_mock.get(IP_URL).mock(side_effect=ConnectError("boom"))
        adapter = _enable(AlienVaultAdapter())
        result = await adapter.lookup_ip(IP)
        assert result == {}
        assert route.call_count == 3
        await adapter.close()


# ── Circuit breaker ───────────────────────────────────────────────────────────


class TestAlienVaultCircuitBreaker:
    async def test_circuit_opens_after_five_failures(self, respx_mock, live_mode):
        respx_mock.get(IP_URL).mock(side_effect=ConnectError("down"))
        adapter = _enable(AlienVaultAdapter())
        for _ in range(5):
            assert await adapter.lookup_ip(IP) == {}
        assert adapter._breaker.is_open()
        with pytest.raises(CircuitOpenError):
            await adapter.lookup_ip(IP)
        await adapter.close()

    async def test_circuit_open_error_from_call_propagates(self, live_mode, monkeypatch):
        # Covers the `except CircuitOpenError: raise` guard inside _lookup.
        adapter = _enable(AlienVaultAdapter())

        async def _raise(*_a, **_k):
            raise CircuitOpenError("opened mid-call")

        monkeypatch.setattr(adapter, "_call", _raise)
        with pytest.raises(CircuitOpenError):
            await adapter.lookup_ip(IP)
        await adapter.close()


# ── Construction with API key present (covers headers.update line) ────────────


class TestAlienVaultEnabledConstruction:
    async def test_enabled_at_construction_sets_header(self, monkeypatch):
        from sentinel.config import get_settings

        monkeypatch.setenv("MOCK_ADAPTERS", "false")
        monkeypatch.setenv("ALIENVAULT_OTX_API_KEY", "real-key")
        get_settings.cache_clear()
        try:
            adapter = AlienVaultAdapter()
            assert adapter._enabled is True
            assert adapter._client.headers["X-OTX-API-KEY"] == "real-key"
            await adapter.close()
        finally:
            get_settings.cache_clear()


def test_get_alienvault_adapter_is_singleton():
    assert get_alienvault_adapter() is get_alienvault_adapter()
