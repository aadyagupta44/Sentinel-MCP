"""abuse.ch adapter tests — respx-mocked, no real network.

Covers:
  - Mock mode: feed seeding + in-memory predicates + per-indicator lookups
  - Live mode: feed downloads (success + per-feed failure isolation + URLhaus
    parse edge cases) and per-indicator API lookups (success + error → {})
  - ensure_loaded() idempotency and the circuit breaker contract.
"""

from httpx import ConnectError, Response

from sentinel.adapters.abuse_ch import AbuseCHAdapter, get_abuse_ch_adapter

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
URLHAUS_FEED = "https://urlhaus.abuse.ch/downloads/text/"
BAZAAR_FEED = "https://bazaar.abuse.ch/export/csv/recent/"
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
BAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"

KNOWN_HASH = "44d88612fea8a8f36de82e1278abb02f"


# ── Mock mode (suite default) ─────────────────────────────────────────────────


class TestAbuseCHMockMode:
    async def test_ensure_loaded_seeds_feeds(self):
        adapter = AbuseCHAdapter()
        await adapter.ensure_loaded()
        assert adapter._loaded is True
        assert adapter._last_refresh is not None
        await adapter.close()

    async def test_is_malicious_ip(self):
        adapter = AbuseCHAdapter()
        assert await adapter.is_malicious_ip("185.220.101.34") is True
        assert await adapter.is_malicious_ip("8.8.8.8") is False
        await adapter.close()

    async def test_is_malicious_host(self):
        adapter = AbuseCHAdapter()
        assert await adapter.is_malicious_host("MALWARE-C2.example.com") is True
        assert await adapter.is_malicious_host("good.example.com") is False
        await adapter.close()

    async def test_is_malicious_hash(self):
        adapter = AbuseCHAdapter()
        assert await adapter.is_malicious_hash(KNOWN_HASH.upper()) is True
        assert await adapter.is_malicious_hash("deadbeef") is False
        await adapter.close()

    async def test_lookup_url_mock(self):
        adapter = AbuseCHAdapter()
        result = await adapter.lookup_url("http://evil.example.net/x")
        assert result == {"query_status": "not_in_database", "url": "http://evil.example.net/x"}
        await adapter.close()

    async def test_lookup_hash_found_mock(self):
        adapter = AbuseCHAdapter()
        result = await adapter.lookup_hash(KNOWN_HASH.upper())
        assert result["query_status"] == "hash_found"
        assert result["malware_family"] == "Emotet"
        await adapter.close()

    async def test_lookup_hash_not_found_mock(self):
        adapter = AbuseCHAdapter()
        result = await adapter.lookup_hash("unknownhash")
        assert result == {"query_status": "hash_not_found"}
        await adapter.close()

    async def test_lookup_ioc_mock(self):
        adapter = AbuseCHAdapter()
        result = await adapter.lookup_ioc("185.220.101.34")
        assert result == {"query_status": "no_result", "ioc": "185.220.101.34"}
        await adapter.close()

    async def test_refresh_mock(self):
        adapter = AbuseCHAdapter()
        await adapter.refresh()
        assert adapter._loaded is True
        assert "185.220.101.34" in adapter._feodo_ips
        await adapter.close()

    async def test_ensure_loaded_idempotent(self):
        adapter = AbuseCHAdapter()
        await adapter.ensure_loaded()
        first = adapter._last_refresh
        await adapter.ensure_loaded()  # early return, no second refresh
        assert adapter._last_refresh is first
        await adapter.close()


# ── Live HTTP path: feed downloads ────────────────────────────────────────────


class TestAbuseCHFeedDownloads:
    async def test_refresh_all_feeds_success(self, respx_mock, live_mode):
        respx_mock.get(FEODO_URL).mock(
            return_value=Response(
                200,
                text="# comment line\n\n185.220.101.34 2026-01-01\n91.108.56.181\n",
            )
        )
        respx_mock.get(URLHAUS_FEED).mock(
            return_value=Response(
                200,
                # blank/comment line, a valid URL, a line with no netloc, and
                # a malformed IPv6 URL that makes urlparse raise (inner except).
                text="# header\n\nhttp://evil.example.net:8080/path\nnot-a-url-no-netloc\nhttp://[oops\n",
            )
        )
        respx_mock.get(BAZAAR_FEED).mock(
            return_value=Response(
                200,
                # BOM + DictReader header + rows with sha256/md5
                text="﻿sha256_hash,md5_hash\nAABBCC,DDEEFF\n,112233\n",
            )
        )
        adapter = AbuseCHAdapter()
        await adapter.refresh()

        assert "185.220.101.34" in adapter._feodo_ips
        assert "91.108.56.181" in adapter._feodo_ips
        assert "evil.example.net" in adapter._urlhaus_hosts
        assert "aabbcc" in adapter._bazaar_hashes
        assert "ddeeff" in adapter._bazaar_hashes
        assert "112233" in adapter._bazaar_hashes
        assert adapter._loaded is True
        await adapter.close()

    async def test_feodotracker_download_failure_keeps_existing(self, respx_mock, live_mode):
        # Feodo fails; other two succeed → gather isolation holds.
        respx_mock.get(FEODO_URL).mock(side_effect=ConnectError("down"))
        respx_mock.get(URLHAUS_FEED).mock(
            return_value=Response(200, text="http://evil.example.net/")
        )
        respx_mock.get(BAZAAR_FEED).mock(
            return_value=Response(200, text="sha256_hash,md5_hash\nABC,\n")
        )
        adapter = AbuseCHAdapter()
        adapter._feodo_ips = frozenset({"1.1.1.1"})  # pre-existing kept on failure
        await adapter.refresh()
        assert adapter._feodo_ips == frozenset({"1.1.1.1"})
        assert "evil.example.net" in adapter._urlhaus_hosts
        await adapter.close()

    async def test_urlhaus_download_failure_keeps_existing(self, respx_mock, live_mode):
        respx_mock.get(FEODO_URL).mock(return_value=Response(200, text="2.2.2.2\n"))
        respx_mock.get(URLHAUS_FEED).mock(side_effect=ConnectError("down"))
        respx_mock.get(BAZAAR_FEED).mock(
            return_value=Response(200, text="sha256_hash,md5_hash\nABC,\n")
        )
        adapter = AbuseCHAdapter()
        adapter._urlhaus_hosts = frozenset({"keep.example.com"})
        await adapter.refresh()
        assert adapter._urlhaus_hosts == frozenset({"keep.example.com"})
        assert "2.2.2.2" in adapter._feodo_ips
        await adapter.close()

    async def test_bazaar_download_failure_keeps_existing(self, respx_mock, live_mode):
        respx_mock.get(FEODO_URL).mock(return_value=Response(200, text="3.3.3.3\n"))
        respx_mock.get(URLHAUS_FEED).mock(
            return_value=Response(200, text="http://evil.example.net/")
        )
        respx_mock.get(BAZAAR_FEED).mock(side_effect=ConnectError("down"))
        adapter = AbuseCHAdapter()
        adapter._bazaar_hashes = frozenset({"keepthishash"})
        await adapter.refresh()
        assert adapter._bazaar_hashes == frozenset({"keepthishash"})
        assert "3.3.3.3" in adapter._feodo_ips
        await adapter.close()

    async def test_feodotracker_http_error_status(self, respx_mock, live_mode):
        # raise_for_status() → exception branch (covers non-network failure).
        respx_mock.get(FEODO_URL).mock(return_value=Response(500, text="err"))
        respx_mock.get(URLHAUS_FEED).mock(return_value=Response(200, text=""))
        respx_mock.get(BAZAAR_FEED).mock(return_value=Response(200, text="sha256_hash,md5_hash\n"))
        adapter = AbuseCHAdapter()
        await adapter.refresh()
        assert adapter._feodo_ips == frozenset()
        await adapter.close()


# ── Live HTTP path: per-indicator API lookups ─────────────────────────────────


class TestAbuseCHLookupURL:
    async def test_success(self, respx_mock, live_mode):
        respx_mock.post(URLHAUS_API).mock(
            return_value=Response(200, json={"query_status": "ok", "url_status": "online"})
        )
        adapter = AbuseCHAdapter()
        result = await adapter.lookup_url("http://x/")
        assert result["query_status"] == "ok"
        await adapter.close()

    async def test_error_returns_empty(self, respx_mock, live_mode):
        respx_mock.post(URLHAUS_API).mock(side_effect=ConnectError("boom"))
        adapter = AbuseCHAdapter()
        assert await adapter.lookup_url("http://x/") == {}
        assert adapter._breaker._failure_count == 1
        await adapter.close()


class TestAbuseCHLookupHash:
    async def test_success(self, respx_mock, live_mode):
        respx_mock.post(BAZAAR_API).mock(
            return_value=Response(200, json={"query_status": "ok", "data": []})
        )
        adapter = AbuseCHAdapter()
        result = await adapter.lookup_hash(KNOWN_HASH)
        assert result["query_status"] == "ok"
        await adapter.close()

    async def test_error_returns_empty(self, respx_mock, live_mode):
        respx_mock.post(BAZAAR_API).mock(side_effect=ConnectError("boom"))
        adapter = AbuseCHAdapter()
        assert await adapter.lookup_hash(KNOWN_HASH) == {}
        await adapter.close()


class TestAbuseCHLookupIOC:
    async def test_success(self, respx_mock, live_mode):
        respx_mock.post(THREATFOX_API).mock(
            return_value=Response(200, json={"query_status": "ok", "data": []})
        )
        adapter = AbuseCHAdapter()
        result = await adapter.lookup_ioc("185.220.101.34")
        assert result["query_status"] == "ok"
        await adapter.close()

    async def test_error_returns_empty(self, respx_mock, live_mode):
        respx_mock.post(THREATFOX_API).mock(side_effect=ConnectError("boom"))
        adapter = AbuseCHAdapter()
        assert await adapter.lookup_ioc("185.220.101.34") == {}
        await adapter.close()


# ── Circuit breaker ───────────────────────────────────────────────────────────


class TestAbuseCHCircuitBreaker:
    async def test_breaker_opens_after_five_failures(self, respx_mock, live_mode):
        respx_mock.post(THREATFOX_API).mock(side_effect=ConnectError("down"))
        adapter = AbuseCHAdapter()
        for _ in range(5):
            assert await adapter.lookup_ioc("x") == {}
        assert adapter._breaker.is_open()
        await adapter.close()


# ── Singleton accessor ────────────────────────────────────────────────────────


def test_get_abuse_ch_adapter_is_singleton():
    assert get_abuse_ch_adapter() is get_abuse_ch_adapter()
