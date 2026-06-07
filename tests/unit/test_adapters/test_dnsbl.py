"""DNSBL adapter tests — socket-mocked, no real DNS queries.

DNSBL is not an httpx/BaseAdapter, so there is no circuit breaker. The contract
here is: (1) success path returns correct structure, (2) NXDOMAIN/errors degrade
gracefully. ``socket.gethostbyname_ex`` is monkeypatched so nothing hits the network.
"""

import socket

from sentinel.adapters.dnsbl import DNSBLAdapter, get_dnsbl_adapter

# ── Mock mode ─────────────────────────────────────────────────────────────────


class TestDNSBLMockMode:
    async def test_listed_ip(self):
        adapter = DNSBLAdapter()
        result = await adapter.check_ip("185.220.101.34")
        assert result["listed"] is True
        assert result["zones"]["spamhaus_zen"]["return_codes"] == ["127.0.0.4"]

    async def test_clean_ip(self):
        adapter = DNSBLAdapter()
        result = await adapter.check_ip("8.8.8.8")
        assert result["listed"] is False
        assert "Clean" in result["summary"]


# ── Live path (socket mocked) ─────────────────────────────────────────────────


class TestDNSBLLive:
    async def test_listed_with_known_return_code(self, live_mode, monkeypatch):
        monkeypatch.setattr(socket, "gethostbyname_ex", lambda q: ("host", [], ["127.0.0.4"]))
        adapter = DNSBLAdapter()
        result = await adapter.check_ip("1.2.3.4")
        assert result["listed"] is True
        zone = result["zones"]["spamhaus_zen"]
        assert zone["return_codes"] == ["127.0.0.4"]
        assert zone["meanings"] == ["XBL — exploits / botnet"]
        assert result["summary"] == "listed"

    async def test_listed_with_unknown_return_code(self, live_mode, monkeypatch):
        monkeypatch.setattr(socket, "gethostbyname_ex", lambda q: ("host", [], ["127.0.0.99"]))
        adapter = DNSBLAdapter()
        result = await adapter.check_ip("1.2.3.4")
        # Unknown codes fall back to the raw code string as their "meaning".
        assert result["zones"]["spamhaus_zen"]["meanings"] == ["127.0.0.99"]

    async def test_empty_addrs_yields_no_codes(self, live_mode, monkeypatch):
        monkeypatch.setattr(socket, "gethostbyname_ex", lambda q: ())
        adapter = DNSBLAdapter()
        result = await adapter.check_ip("1.2.3.4")
        assert result["zones"]["spamhaus_zen"]["return_codes"] == []

    async def test_nxdomain_is_clean(self, live_mode, monkeypatch):
        def _raise(_q):
            raise socket.gaierror("NXDOMAIN")

        monkeypatch.setattr(socket, "gethostbyname_ex", _raise)
        adapter = DNSBLAdapter()
        result = await adapter.check_ip("1.2.3.4")
        assert result["listed"] is False
        assert result["summary"] == "clean"

    async def test_malformed_ip_returns_not_listed(self, live_mode, monkeypatch):
        monkeypatch.setattr(socket, "gethostbyname_ex", lambda q: ("host", [], ["127.0.0.4"]))
        adapter = DNSBLAdapter()
        result = await adapter.check_ip("not-an-ip")
        assert result["listed"] is False

    async def test_unexpected_error_is_swallowed(self, live_mode, monkeypatch):
        def _boom(_q):
            raise ValueError("unexpected")

        monkeypatch.setattr(socket, "gethostbyname_ex", _boom)
        adapter = DNSBLAdapter()
        result = await adapter.check_ip("1.2.3.4")
        assert result["listed"] is False
        assert "error" in result["zones"]["spamhaus_zen"]


def test_get_dnsbl_adapter_is_singleton():
    assert get_dnsbl_adapter() is get_dnsbl_adapter()
