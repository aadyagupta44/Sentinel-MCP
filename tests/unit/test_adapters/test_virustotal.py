"""VirusTotal adapter tests — respx-mocked, no real network.

VirusTotal is an OPTIONAL adapter, gated on ``VIRUSTOTAL_API_KEY``. Tests cover:
- mock-mode branch of every public method
- disabled branch (no key) of every public method
- the live HTTP ``_get`` path: success, 404 → {}, transport error → {},
  circuit breaker (5 ConnectError → open → 6th raises), and the
  ``except CircuitOpenError: raise`` guard
- the token-bucket ``_acquire_token`` wait branch and decrement branch

Uses the ``respx_mock`` fixture (assert_all_called=False) and the ``live_mode``
fixture from conftest.
"""

import base64

import pytest
from httpx import ConnectError, Response

from sentinel.adapters.base import CircuitOpenError
from sentinel.adapters.virustotal import VirusTotalAdapter, get_virustotal_adapter

_BASE = "https://www.virustotal.com/api/v3"
IP = "8.8.8.8"
HASH = "44d88612fea8a8f36de82e1278abb02f"
DOMAIN = "example.com"
URL = "http://evil.com"
URL_ID = base64.urlsafe_b64encode(URL.encode()).decode().rstrip("=")

IP_URL = f"{_BASE}/ip_addresses/{IP}"
HASH_URL = f"{_BASE}/files/{HASH}"
DOMAIN_URL = f"{_BASE}/domains/{DOMAIN}"
URL_URL = f"{_BASE}/urls/{URL_ID}"


def _enable(adapter: VirusTotalAdapter) -> VirusTotalAdapter:
    """Force the optional adapter into the enabled live state."""
    adapter._enabled = True
    adapter._api_key = "test-key"
    return adapter


# ── Mock mode (suite default) ─────────────────────────────────────────────────


class TestVirusTotalMockMode:
    async def test_analyze_ip_known(self):
        adapter = VirusTotalAdapter()
        result = await adapter.analyze_ip("8.8.8.8")
        assert result["data"]["id"] == "8.8.8.8"
        await adapter.close()

    async def test_analyze_ip_unknown_shape(self):
        adapter = VirusTotalAdapter()
        result = await adapter.analyze_ip("203.0.113.9")
        assert result["data"]["attributes"]["last_analysis_stats"]["malicious"] == 0
        await adapter.close()

    async def test_analyze_hash_known(self):
        adapter = VirusTotalAdapter()
        result = await adapter.analyze_hash(HASH.upper())  # exercises .lower()
        assert result["data"]["type"] == "file"
        await adapter.close()

    async def test_analyze_hash_unknown_shape(self):
        adapter = VirusTotalAdapter()
        result = await adapter.analyze_hash("deadbeef")
        assert result["data"]["attributes"]["reputation"] == 0
        await adapter.close()

    async def test_analyze_domain(self):
        adapter = VirusTotalAdapter()
        result = await adapter.analyze_domain(DOMAIN)
        assert result["data"]["attributes"]["last_analysis_stats"]["malicious"] == 0
        await adapter.close()

    async def test_analyze_url(self):
        adapter = VirusTotalAdapter()
        result = await adapter.analyze_url(URL)
        assert result["data"]["attributes"]["reputation"] == 0
        await adapter.close()


# ── Disabled branch (live mode, no API key) ───────────────────────────────────


class TestVirusTotalDisabled:
    async def test_analyze_ip_disabled(self, live_mode):
        adapter = VirusTotalAdapter()
        assert adapter._enabled is False
        assert await adapter.analyze_ip(IP) == {}
        await adapter.close()

    async def test_analyze_hash_disabled(self, live_mode):
        adapter = VirusTotalAdapter()
        assert await adapter.analyze_hash(HASH) == {}
        await adapter.close()

    async def test_analyze_domain_disabled(self, live_mode):
        adapter = VirusTotalAdapter()
        assert await adapter.analyze_domain(DOMAIN) == {}
        await adapter.close()

    async def test_analyze_url_disabled(self, live_mode):
        adapter = VirusTotalAdapter()
        assert await adapter.analyze_url(URL) == {}
        await adapter.close()


# ── Live HTTP path: success ───────────────────────────────────────────────────


class TestVirusTotalSuccess:
    async def test_analyze_ip_success(self, respx_mock, live_mode):
        respx_mock.get(IP_URL).mock(
            return_value=Response(200, json={"data": {"id": IP, "type": "ip_address"}})
        )
        adapter = _enable(VirusTotalAdapter())
        result = await adapter.analyze_ip(IP)
        assert result["data"]["id"] == IP
        # default token bucket (4 tokens) → decrement else-branch
        assert adapter._tokens == 3.0
        await adapter.close()

    async def test_analyze_hash_success(self, respx_mock, live_mode):
        respx_mock.get(HASH_URL).mock(
            return_value=Response(200, json={"data": {"id": HASH, "type": "file"}})
        )
        adapter = _enable(VirusTotalAdapter())
        result = await adapter.analyze_hash(HASH)
        assert result["data"]["type"] == "file"
        await adapter.close()

    async def test_analyze_domain_success(self, respx_mock, live_mode):
        respx_mock.get(DOMAIN_URL).mock(
            return_value=Response(200, json={"data": {"id": DOMAIN, "type": "domain"}})
        )
        adapter = _enable(VirusTotalAdapter())
        result = await adapter.analyze_domain(DOMAIN)
        assert result["data"]["id"] == DOMAIN
        await adapter.close()

    async def test_analyze_url_success(self, respx_mock, live_mode):
        respx_mock.get(URL_URL).mock(
            return_value=Response(200, json={"data": {"id": URL_ID, "type": "url"}})
        )
        adapter = _enable(VirusTotalAdapter())
        result = await adapter.analyze_url(URL)
        assert result["data"]["id"] == URL_ID
        await adapter.close()

    async def test_404_returns_empty(self, respx_mock, live_mode):
        respx_mock.get(IP_URL).mock(return_value=Response(404, json={}))
        adapter = _enable(VirusTotalAdapter())
        assert await adapter.analyze_ip(IP) == {}
        await adapter.close()


# ── Token bucket: rate-limit wait branch ──────────────────────────────────────


class TestVirusTotalRateLimit:
    async def test_acquire_token_wait_branch(self, respx_mock, live_mode):
        # tokens=0 → enters `if self._tokens < 1:` → awaits asyncio.sleep
        # (instant via _fast_retry) → sets tokens back to 0.
        respx_mock.get(IP_URL).mock(return_value=Response(200, json={"data": {"id": IP}}))
        adapter = _enable(VirusTotalAdapter())
        adapter._tokens = 0
        result = await adapter.analyze_ip(IP)
        assert result["data"]["id"] == IP
        assert adapter._tokens == 0
        await adapter.close()


# ── Live HTTP path: transport error → retry → graceful degradation ────────────


class TestVirusTotalGracefulDegradation:
    async def test_transport_error_retries_then_empty(self, respx_mock, live_mode):
        route = respx_mock.get(IP_URL).mock(side_effect=ConnectError("boom"))
        adapter = _enable(VirusTotalAdapter())
        result = await adapter.analyze_ip(IP)
        assert result == {}
        assert route.call_count == 3  # tenacity retried 3 times
        await adapter.close()


# ── Live HTTP path: circuit breaker ───────────────────────────────────────────


class TestVirusTotalCircuitBreaker:
    async def test_circuit_opens_after_five_failures(self, respx_mock, live_mode):
        respx_mock.get(IP_URL).mock(side_effect=ConnectError("down"))
        adapter = _enable(VirusTotalAdapter())
        # Plenty of tokens so the bucket never blocks the failing calls.
        adapter._tokens = 100
        for _ in range(5):
            assert await adapter.analyze_ip(IP) == {}
        assert adapter._breaker.is_open()
        with pytest.raises(CircuitOpenError):
            await adapter.analyze_ip(IP)
        await adapter.close()

    async def test_circuit_open_error_from_call_propagates(self, live_mode, monkeypatch):
        # Covers the `except CircuitOpenError: raise` guard inside _get's try.
        adapter = _enable(VirusTotalAdapter())

        async def _raise(*_a, **_k):
            raise CircuitOpenError("opened mid-call")

        monkeypatch.setattr(adapter, "_call", _raise)
        with pytest.raises(CircuitOpenError):
            await adapter.analyze_ip(IP)
        await adapter.close()


# ── Singleton accessor ────────────────────────────────────────────────────────


def test_get_virustotal_adapter_is_singleton():
    assert get_virustotal_adapter() is get_virustotal_adapter()
