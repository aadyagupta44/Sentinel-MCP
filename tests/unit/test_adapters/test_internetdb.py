"""Shodan InternetDB adapter tests — respx-mocked, no real network.

Covers the standard 3-test contract plus the Postgres cache read/write paths
(faked session factory) for full coverage.
"""

import pytest
from httpx import ConnectError, Response

from sentinel.adapters.base import CircuitOpenError
from sentinel.adapters.internetdb import InternetDBAdapter, get_internetdb_adapter

IP = "1.2.3.4"
URL = f"https://internetdb.shodan.io/{IP}"


# ── Faked DB session factory (so cache branches are covered) ──────────────────


class _FakeRow:
    def __init__(self, data):
        self.data = data


class _FakeBegin:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False


class _FakeSession:
    def __init__(self, row=None):
        self._row = row

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def scalar(self, *_a, **_k):
        return self._row

    def begin(self):
        return _FakeBegin()

    async def execute(self, *_a, **_k):
        return None


def _patch_factory(monkeypatch, row=None):
    def sessionmaker():
        return _FakeSession(row)

    monkeypatch.setattr("sentinel.db.session.get_session_factory", lambda: sessionmaker)


# ── Mock mode ─────────────────────────────────────────────────────────────────


class TestInternetDBMockMode:
    async def test_known_ip_returns_mock(self):
        adapter = InternetDBAdapter()
        result = await adapter.lookup("185.220.101.34")
        assert result["ip"] == "185.220.101.34"
        assert 9001 in result["ports"]
        await adapter.close()

    async def test_unknown_ip_returns_empty_shape(self):
        adapter = InternetDBAdapter()
        result = await adapter.lookup("203.0.113.9")
        assert result == {
            "ip": "203.0.113.9",
            "ports": [],
            "cpes": [],
            "cves": [],
            "hostnames": [],
            "tags": [],
        }
        await adapter.close()


# ── Live HTTP path ────────────────────────────────────────────────────────────


class TestInternetDBLive:
    async def test_success(self, respx_mock, live_mode, monkeypatch):
        _patch_factory(monkeypatch, row=None)  # cache miss
        respx_mock.get(URL).mock(
            return_value=Response(
                200,
                json={
                    "ip": IP,
                    "ports": [22, 80],
                    "cpes": [],
                    "cves": ["CVE-2021-1"],
                    "hostnames": [],
                    "tags": [],
                },
            )
        )
        adapter = InternetDBAdapter()
        result = await adapter.lookup(IP)
        assert result["ports"] == [22, 80]
        assert result["cves"] == ["CVE-2021-1"]
        await adapter.close()

    async def test_cache_hit_skips_http(self, live_mode, monkeypatch):
        cached = {
            "ip": IP,
            "ports": [443],
            "cpes": [],
            "cves": [],
            "hostnames": [],
            "tags": ["cached"],
        }
        _patch_factory(monkeypatch, row=_FakeRow(cached))
        adapter = InternetDBAdapter()
        result = await adapter.lookup(IP)
        assert result == cached  # returned from cache, no HTTP route needed
        await adapter.close()

    async def test_404_returns_empty_shape(self, respx_mock, live_mode, monkeypatch):
        _patch_factory(monkeypatch, row=None)
        respx_mock.get(URL).mock(return_value=Response(404))
        adapter = InternetDBAdapter()
        result = await adapter.lookup(IP)
        assert result["ports"] == []
        await adapter.close()

    async def test_transport_error_retries_then_degrades(self, respx_mock, live_mode, monkeypatch):
        _patch_factory(monkeypatch, row=None)
        route = respx_mock.get(URL).mock(side_effect=ConnectError("boom"))
        adapter = InternetDBAdapter()
        result = await adapter.lookup(IP)
        assert result["ip"] == IP
        assert "error" in result
        assert route.call_count == 3
        await adapter.close()

    async def test_cache_store_failure_is_swallowed(self, respx_mock, live_mode, monkeypatch):
        # No factory patch → real get_session_factory tries Postgres and fails;
        # both _get_cached and _store_cached must swallow the error.
        respx_mock.get(URL).mock(
            return_value=Response(
                200,
                json={"ip": IP, "ports": [], "cpes": [], "cves": [], "hostnames": [], "tags": []},
            )
        )
        adapter = InternetDBAdapter()
        result = await adapter.lookup(IP)
        assert result["ip"] == IP
        await adapter.close()


# ── Circuit breaker ───────────────────────────────────────────────────────────


class TestInternetDBCircuitBreaker:
    async def test_circuit_opens_after_five_failures(self, respx_mock, live_mode, monkeypatch):
        _patch_factory(monkeypatch, row=None)
        respx_mock.get(URL).mock(side_effect=ConnectError("down"))
        adapter = InternetDBAdapter()
        for _ in range(5):
            await adapter.lookup(IP)
        assert adapter._breaker.is_open()
        with pytest.raises(CircuitOpenError):
            await adapter.lookup(IP)
        await adapter.close()

    async def test_circuit_open_error_from_call_propagates(self, live_mode, monkeypatch):
        # Covers the `except CircuitOpenError: raise` guard inside the try block,
        # which the top-level is_open() check would otherwise short-circuit.
        _patch_factory(monkeypatch, row=None)
        adapter = InternetDBAdapter()

        async def _raise(*_a, **_k):
            raise CircuitOpenError("opened mid-call")

        monkeypatch.setattr(adapter, "_call", _raise)
        with pytest.raises(CircuitOpenError):
            await adapter.lookup(IP)
        await adapter.close()


def test_get_internetdb_adapter_is_singleton():
    assert get_internetdb_adapter() is get_internetdb_adapter()
