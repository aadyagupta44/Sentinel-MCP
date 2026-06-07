"""URLScan.io adapter tests — respx-mocked, no real network.

URLScan is an OPTIONAL adapter, gated on ``URLSCAN_API_KEY``. Tests cover:
- mock-mode branch of every public method
- disabled branch (no key) of every public method
- live HTTP path: success, exception → {}, circuit breaker, and the
  ``except CircuitOpenError: raise`` guard for each method
- special branches: scan 429 → {"error": "rate_limited"} and get_result 404 → {}

Uses the ``respx_mock`` fixture (assert_all_called=False) and ``live_mode``.
"""

import pytest
from httpx import ConnectError, Response

from sentinel.adapters.base import CircuitOpenError
from sentinel.adapters.urlscan import URLScanAdapter, get_urlscan_adapter

_BASE = "https://urlscan.io/api/v1"
SEARCH_URL = f"{_BASE}/search/"
SCAN_URL = f"{_BASE}/scan/"
UUID = "abc-123"
RESULT_URL = f"{_BASE}/result/{UUID}/"


def _enable(adapter: URLScanAdapter) -> URLScanAdapter:
    adapter._enabled = True
    adapter._api_key = "test-key"
    return adapter


# ── Mock mode (suite default) ─────────────────────────────────────────────────


class TestURLScanMockMode:
    async def test_search_mock(self):
        adapter = URLScanAdapter()
        result = await adapter.search("example.com")
        assert result == {"results": [], "total": 0, "query": "example.com"}
        await adapter.close()

    async def test_scan_mock(self):
        adapter = URLScanAdapter()
        result = await adapter.scan("http://x.com", visibility="public")
        assert result["uuid"] == "mock-scan-uuid"
        assert result["visibility"] == "public"
        await adapter.close()

    async def test_get_result_mock(self):
        adapter = URLScanAdapter()
        result = await adapter.get_result(UUID)
        assert result["task"]["uuid"] == UUID
        assert result["verdicts"]["overall"]["malicious"] is False
        await adapter.close()


# ── Disabled branch (live mode, no API key) ───────────────────────────────────


class TestURLScanDisabled:
    async def test_search_disabled(self, live_mode):
        adapter = URLScanAdapter()
        assert adapter._enabled is False
        assert await adapter.search("q") == {}
        await adapter.close()

    async def test_scan_disabled(self, live_mode):
        adapter = URLScanAdapter()
        assert await adapter.scan("http://x.com") == {}
        await adapter.close()

    async def test_get_result_disabled(self, live_mode):
        adapter = URLScanAdapter()
        assert await adapter.get_result(UUID) == {}
        await adapter.close()


# ── Live HTTP path: success ───────────────────────────────────────────────────


class TestURLScanSuccess:
    async def test_search_success(self, respx_mock, live_mode):
        respx_mock.get(SEARCH_URL).mock(
            return_value=Response(200, json={"results": [{"page": {"url": "x"}}], "total": 1})
        )
        adapter = _enable(URLScanAdapter())
        result = await adapter.search("example.com", size=200)  # exercises min(size, 100)
        assert result["total"] == 1
        await adapter.close()

    async def test_scan_success(self, respx_mock, live_mode):
        respx_mock.post(SCAN_URL).mock(
            return_value=Response(200, json={"uuid": UUID, "result": "url"})
        )
        adapter = _enable(URLScanAdapter())
        result = await adapter.scan("http://x.com")
        assert result["uuid"] == UUID
        await adapter.close()

    async def test_get_result_success(self, respx_mock, live_mode):
        respx_mock.get(RESULT_URL).mock(
            return_value=Response(200, json={"task": {"uuid": UUID}, "verdicts": {}})
        )
        adapter = _enable(URLScanAdapter())
        result = await adapter.get_result(UUID)
        assert result["task"]["uuid"] == UUID
        await adapter.close()


# ── Special branches ──────────────────────────────────────────────────────────


class TestURLScanSpecialBranches:
    async def test_scan_rate_limited_429(self, respx_mock, live_mode):
        respx_mock.post(SCAN_URL).mock(return_value=Response(429, json={}))
        adapter = _enable(URLScanAdapter())
        result = await adapter.scan("http://x.com")
        assert result == {"error": "rate_limited"}
        await adapter.close()

    async def test_get_result_404_returns_empty(self, respx_mock, live_mode):
        respx_mock.get(RESULT_URL).mock(return_value=Response(404, json={}))
        adapter = _enable(URLScanAdapter())
        assert await adapter.get_result(UUID) == {}
        await adapter.close()


# ── Live HTTP path: transport error → retry → graceful degradation ────────────


class TestURLScanGracefulDegradation:
    async def test_search_error_returns_empty(self, respx_mock, live_mode):
        route = respx_mock.get(SEARCH_URL).mock(side_effect=ConnectError("boom"))
        adapter = _enable(URLScanAdapter())
        assert await adapter.search("q") == {}
        assert route.call_count == 3
        await adapter.close()

    async def test_scan_error_returns_empty(self, respx_mock, live_mode):
        route = respx_mock.post(SCAN_URL).mock(side_effect=ConnectError("boom"))
        adapter = _enable(URLScanAdapter())
        assert await adapter.scan("http://x.com") == {}
        assert route.call_count == 3
        await adapter.close()

    async def test_get_result_error_returns_empty(self, respx_mock, live_mode):
        route = respx_mock.get(RESULT_URL).mock(side_effect=ConnectError("boom"))
        adapter = _enable(URLScanAdapter())
        assert await adapter.get_result(UUID) == {}
        assert route.call_count == 3
        await adapter.close()


# ── Live HTTP path: circuit breaker ───────────────────────────────────────────


class TestURLScanCircuitBreaker:
    async def test_search_circuit_opens_after_five_failures(self, respx_mock, live_mode):
        respx_mock.get(SEARCH_URL).mock(side_effect=ConnectError("down"))
        adapter = _enable(URLScanAdapter())
        for _ in range(5):
            assert await adapter.search("q") == {}
        assert adapter._breaker.is_open()
        with pytest.raises(CircuitOpenError):
            await adapter.search("q")
        await adapter.close()

    async def test_scan_raises_when_circuit_open(self, live_mode):
        adapter = _enable(URLScanAdapter())
        for _ in range(5):
            await adapter._breaker.record_failure()
        with pytest.raises(CircuitOpenError):
            await adapter.scan("http://x.com")
        await adapter.close()

    async def test_get_result_raises_when_circuit_open(self, live_mode):
        adapter = _enable(URLScanAdapter())
        for _ in range(5):
            await adapter._breaker.record_failure()
        with pytest.raises(CircuitOpenError):
            await adapter.get_result(UUID)
        await adapter.close()

    async def test_search_circuit_open_error_from_call_propagates(self, live_mode, monkeypatch):
        adapter = _enable(URLScanAdapter())

        async def _raise(*_a, **_k):
            raise CircuitOpenError("opened mid-call")

        monkeypatch.setattr(adapter, "_call", _raise)
        with pytest.raises(CircuitOpenError):
            await adapter.search("q")
        await adapter.close()

    async def test_scan_circuit_open_error_from_call_propagates(self, live_mode, monkeypatch):
        adapter = _enable(URLScanAdapter())

        async def _raise(*_a, **_k):
            raise CircuitOpenError("opened mid-call")

        monkeypatch.setattr(adapter, "_call", _raise)
        with pytest.raises(CircuitOpenError):
            await adapter.scan("http://x.com")
        await adapter.close()

    async def test_get_result_circuit_open_error_from_call_propagates(self, live_mode, monkeypatch):
        adapter = _enable(URLScanAdapter())

        async def _raise(*_a, **_k):
            raise CircuitOpenError("opened mid-call")

        monkeypatch.setattr(adapter, "_call", _raise)
        with pytest.raises(CircuitOpenError):
            await adapter.get_result(UUID)
        await adapter.close()


# ── Singleton accessor ────────────────────────────────────────────────────────


def test_get_urlscan_adapter_is_singleton():
    assert get_urlscan_adapter() is get_urlscan_adapter()
