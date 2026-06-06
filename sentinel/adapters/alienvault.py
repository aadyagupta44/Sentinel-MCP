"""AlienVault OTX adapter — threat pulses, malware families, related IOCs.

Uses the OTX REST API directly via httpx (async, consistent with all other adapters).
Free tier: 10,000 requests/day. Requires email signup at otx.alienvault.com.
Optional — skipped gracefully if ALIENVAULT_OTX_API_KEY is not set.
"""

from typing import Any

from sentinel.adapters.base import BaseAdapter, CircuitOpenError
from sentinel.config import get_settings

_BASE_URL = "https://otx.alienvault.com/api/v1/indicators"

_MOCK_DATA: dict[str, dict[str, Any]] = {
    "185.220.101.34": {
        "general": {
            "indicator": "185.220.101.34",
            "type": "IPv4",
            "pulse_count": 47,
            "malware_families": ["Emotet", "TrickBot"],
            "tags": ["botnet", "c2", "tor"],
            "country_name": "Germany",
            "asn": "AS58220",
        },
        "reputation": 3,
    },
    "44d88612fea8a8f36de82e1278abb02f": {
        "general": {
            "indicator": "44d88612fea8a8f36de82e1278abb02f",
            "type": "FileHash-MD5",
            "pulse_count": 12,
            "malware_families": ["Emotet"],
            "tags": ["dropper", "loader"],
        },
        "reputation": 3,
    },
}


class AlienVaultAdapter(BaseAdapter):
    adapter_name = "alienvault"

    def __init__(self) -> None:
        super().__init__()
        settings = get_settings()
        self._api_key = settings.alienvault_otx_api_key
        self._enabled = bool(self._api_key)
        if self._enabled:
            self._client.headers.update({"X-OTX-API-KEY": self._api_key})

    async def lookup_ip(self, ip: str) -> dict[str, Any]:
        if self.is_mock:
            return _MOCK_DATA.get(
                ip,
                {
                    "general": {
                        "indicator": ip,
                        "pulse_count": 0,
                        "malware_families": [],
                        "tags": [],
                    }
                },
            )
        if not self._enabled:
            return {}

        return await self._lookup(f"{_BASE_URL}/IPv4/{ip}/general", ip)

    async def lookup_domain(self, domain: str) -> dict[str, Any]:
        if self.is_mock:
            return {
                "general": {
                    "indicator": domain,
                    "pulse_count": 0,
                    "malware_families": [],
                    "tags": [],
                }
            }
        if not self._enabled:
            return {}

        return await self._lookup(f"{_BASE_URL}/domain/{domain}/general", domain)

    async def lookup_hash(self, hash_value: str) -> dict[str, Any]:
        if self.is_mock:
            return _MOCK_DATA.get(
                hash_value.lower(),
                {
                    "general": {
                        "indicator": hash_value,
                        "pulse_count": 0,
                        "malware_families": [],
                        "tags": [],
                    }
                },
            )
        if not self._enabled:
            return {}

        return await self._lookup(f"{_BASE_URL}/file/{hash_value}/general", hash_value)

    async def lookup_url(self, url: str) -> dict[str, Any]:
        if self.is_mock:
            return {
                "general": {"indicator": url, "pulse_count": 0, "malware_families": [], "tags": []}
            }
        if not self._enabled:
            return {}

        import urllib.parse

        encoded = urllib.parse.quote(url, safe="")
        return await self._lookup(f"{_BASE_URL}/url/{encoded}/general", url)

    async def _lookup(self, url: str, indicator: str) -> dict[str, Any]:
        if self._breaker.is_open():
            raise CircuitOpenError(self.adapter_name)

        try:
            resp = await self._call("GET", url, span_name="lookup")
            if resp.status_code == 404:
                return {}
            resp.raise_for_status()
            return resp.json()
        except CircuitOpenError:
            raise
        except Exception as exc:
            self._log.warning("otx_lookup_failed", error=str(exc), indicator=indicator[:30])
            return {}


_adapter: AlienVaultAdapter | None = None


def get_alienvault_adapter() -> AlienVaultAdapter:
    global _adapter
    if _adapter is None:
        _adapter = AlienVaultAdapter()
    return _adapter
