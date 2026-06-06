"""CIRCL Hash Lookup adapter tests — respx-mocked, no real network.

Contract covered for the live HTTP path:
  1. success path returns the correct structure
  2. transport error triggers retry (3 attempts) then degrades gracefully
  3. circuit breaker opens after 5 failures
Plus the mock-mode branches, the unsupported-length branch (no HTTP call), the
404 branch, and the CircuitOpenError-propagate guard. ``_detect_algo`` is
exercised across md5/sha1/sha256/None lengths.

Uses the ``respx_mock`` fixture (NOT the decorator).
"""

import pytest
from httpx import ConnectError, Response

from sentinel.adapters.base import CircuitOpenError
from sentinel.adapters.circl import CIRCLAdapter, get_circl_adapter

MD5 = "a" * 32  # 32 hex chars → md5
SHA1 = "b" * 40  # 40 hex chars → sha1
SHA256 = "c" * 64  # 64 hex chars → sha256
KNOWN_MD5 = "44d88612fea8a8f36de82e1278abb02f"  # key in _MOCK_DATA
URL = f"https://hashlookup.circl.lu/lookup/md5/{MD5}"


# ── Mock mode (suite default) ─────────────────────────────────────────────────


class TestCIRCLMockMode:
    async def test_known_hash_returns_mock(self):
        adapter = CIRCLAdapter()
        result = await adapter.lookup(KNOWN_MD5)
        assert result["KnownMalicious"] == 1
        assert result["source"] == "MalwareBazaar"
        await adapter.close()

    async def test_unknown_hash_returns_default_shape(self):
        adapter = CIRCLAdapter()
        result = await adapter.lookup("deadbeef" * 4)  # 32 chars, not in mock
        assert result == {"KnownMalicious": 0, "KnownBenign": 0}
        await adapter.close()


# ── _detect_algo ──────────────────────────────────────────────────────────────


class TestDetectAlgo:
    def test_md5(self):
        assert CIRCLAdapter._detect_algo("a" * 32) == "md5"

    def test_sha1(self):
        assert CIRCLAdapter._detect_algo("a" * 40) == "sha1"

    def test_sha256(self):
        assert CIRCLAdapter._detect_algo("a" * 64) == "sha256"

    def test_unsupported_length(self):
        assert CIRCLAdapter._detect_algo("abc") is None


# ── Live HTTP path: unsupported / success / 404 / error ───────────────────────


class TestCIRCLLive:
    async def test_unsupported_length_makes_no_http_call(self, live_mode):
        # No route registered: must short-circuit before any HTTP call.
        adapter = CIRCLAdapter()
        result = await adapter.lookup("abc")
        assert result == {"error": "unsupported hash length", "hash": "abc"}
        await adapter.close()

    async def test_success(self, respx_mock, live_mode):
        respx_mock.get(URL).mock(
            return_value=Response(200, json={"md5": MD5, "KnownMalicious": 1, "source": "test"})
        )
        adapter = CIRCLAdapter()
        result = await adapter.lookup(MD5)
        assert result["KnownMalicious"] == 1
        assert result["source"] == "test"
        await adapter.close()

    async def test_404_returns_empty_shape(self, respx_mock, live_mode):
        respx_mock.get(URL).mock(return_value=Response(404))
        adapter = CIRCLAdapter()
        result = await adapter.lookup(MD5)
        assert result == {"KnownMalicious": 0, "KnownBenign": 0, "hash": MD5}
        await adapter.close()

    async def test_transport_error_retries_then_degrades(self, respx_mock, live_mode):
        route = respx_mock.get(URL).mock(side_effect=ConnectError("boom"))
        adapter = CIRCLAdapter()
        result = await adapter.lookup(MD5)
        assert result == {}
        assert route.call_count == 3  # tenacity retried 3 times before giving up
        await adapter.close()


# ── Circuit breaker ───────────────────────────────────────────────────────────


class TestCIRCLCircuitBreaker:
    async def test_circuit_opens_after_five_failures(self, respx_mock, live_mode):
        respx_mock.get(URL).mock(side_effect=ConnectError("down"))
        adapter = CIRCLAdapter()
        for _ in range(5):
            await adapter.lookup(MD5)
        assert adapter._breaker.is_open()
        with pytest.raises(CircuitOpenError):
            await adapter.lookup(MD5)
        await adapter.close()

    async def test_circuit_open_error_from_call_propagates(self, live_mode, monkeypatch):
        # Covers the `except CircuitOpenError: raise` guard inside the try block,
        # which the top-level is_open() check would otherwise short-circuit.
        adapter = CIRCLAdapter()

        async def _raise(*_a, **_k):
            raise CircuitOpenError("opened mid-call")

        monkeypatch.setattr(adapter, "_call", _raise)
        with pytest.raises(CircuitOpenError):
            await adapter.lookup(MD5)
        await adapter.close()


# ── Singleton accessor ────────────────────────────────────────────────────────


def test_get_circl_adapter_is_singleton():
    assert get_circl_adapter() is get_circl_adapter()
