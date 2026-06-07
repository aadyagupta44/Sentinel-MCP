"""VirusTotal adapter — malware analysis and IOC reputation.

Uses VirusTotal API v3 directly via httpx.
Free tier: 4 requests/minute, 500/day. Requires signup at virustotal.com.
Optional — skipped gracefully if VIRUSTOTAL_API_KEY is not set.

Rate limiting: token bucket per-adapter instance (4 tokens/minute).
"""

import asyncio
import time
from typing import Any

from sentinel.adapters.base import BaseAdapter, CircuitOpenError
from sentinel.config import get_settings

_BASE_URL = "https://www.virustotal.com/api/v3"
_RATE_LIMIT_PER_MIN = 4

_MOCK_DATA: dict[str, dict[str, Any]] = {
    "185.220.101.34": {
        "data": {
            "id": "185.220.101.34",
            "type": "ip_address",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 18,
                    "suspicious": 2,
                    "harmless": 55,
                    "undetected": 5,
                },
                "last_analysis_date": 1748822400,
                "country": "DE",
                "as_owner": "netzbetrieb GmbH",
                "reputation": -47,
                "tags": ["tor", "vpn"],
            },
        }
    },
    "44d88612fea8a8f36de82e1278abb02f": {
        "data": {
            "id": "44d88612fea8a8f36de82e1278abb02f",
            "type": "file",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 62,
                    "suspicious": 3,
                    "harmless": 0,
                    "undetected": 10,
                },
                "meaningful_name": "emotet_dropper.exe",
                "type_description": "Win32 EXE",
                "reputation": -100,
                "tags": ["emotet", "trojan", "dropper"],
            },
        }
    },
    "8.8.8.8": {
        "data": {
            "id": "8.8.8.8",
            "type": "ip_address",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 80,
                    "undetected": 0,
                },
                "country": "US",
                "as_owner": "Google LLC",
                "reputation": 50,
                "tags": [],
            },
        }
    },
}


class VirusTotalAdapter(BaseAdapter):
    adapter_name = "virustotal"

    def __init__(self) -> None:
        super().__init__()
        settings = get_settings()
        self._api_key = settings.virustotal_api_key
        self._enabled = bool(self._api_key)
        # Token bucket for rate limiting (4 req/min)
        self._tokens = float(_RATE_LIMIT_PER_MIN)
        self._last_refill = time.monotonic()
        self._rate_lock = asyncio.Lock()

    async def _acquire_token(self) -> None:
        async with self._rate_lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(
                float(_RATE_LIMIT_PER_MIN),
                self._tokens + elapsed * (_RATE_LIMIT_PER_MIN / 60.0),
            )
            self._last_refill = now
            if self._tokens < 1:
                wait = (1 - self._tokens) / (_RATE_LIMIT_PER_MIN / 60.0)
                self._log.debug("virustotal_rate_limit_wait", wait_seconds=round(wait, 2))
                await asyncio.sleep(wait)
                self._tokens = 0
            else:
                self._tokens -= 1

    async def analyze_ip(self, ip: str) -> dict[str, Any]:
        if self.is_mock:
            return _MOCK_DATA.get(
                ip,
                {
                    "data": {
                        "attributes": {"last_analysis_stats": {"malicious": 0}, "reputation": 0}
                    }
                },
            )
        if not self._enabled:
            return {}

        await self._acquire_token()
        return await self._get(f"{_BASE_URL}/ip_addresses/{ip}", ip)

    async def analyze_hash(self, hash_value: str) -> dict[str, Any]:
        if self.is_mock:
            return _MOCK_DATA.get(
                hash_value.lower(),
                {
                    "data": {
                        "attributes": {"last_analysis_stats": {"malicious": 0}, "reputation": 0}
                    }
                },
            )
        if not self._enabled:
            return {}

        await self._acquire_token()
        return await self._get(f"{_BASE_URL}/files/{hash_value}", hash_value)

    async def analyze_domain(self, domain: str) -> dict[str, Any]:
        if self.is_mock:
            return {
                "data": {"attributes": {"last_analysis_stats": {"malicious": 0}, "reputation": 0}}
            }
        if not self._enabled:
            return {}

        await self._acquire_token()
        return await self._get(f"{_BASE_URL}/domains/{domain}", domain)

    async def analyze_url(self, url: str) -> dict[str, Any]:
        if self.is_mock:
            return {
                "data": {"attributes": {"last_analysis_stats": {"malicious": 0}, "reputation": 0}}
            }
        if not self._enabled:
            return {}

        import base64

        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        await self._acquire_token()
        return await self._get(f"{_BASE_URL}/urls/{url_id}", url)

    async def _get(self, url: str, indicator: str) -> dict[str, Any]:
        if self._breaker.is_open():
            raise CircuitOpenError(self.adapter_name)

        try:
            resp = await self._call(
                "GET",
                url,
                span_name="analyze",
                headers={"x-apikey": self._api_key},
            )
            if resp.status_code == 404:
                return {}
            resp.raise_for_status()
            return resp.json()
        except CircuitOpenError:
            raise
        except Exception as exc:
            self._log.warning(
                "virustotal_analyze_failed", error=str(exc), indicator=str(indicator)[:30]
            )
            return {}


_adapter: VirusTotalAdapter | None = None


def get_virustotal_adapter() -> VirusTotalAdapter:
    global _adapter
    if _adapter is None:
        _adapter = VirusTotalAdapter()
    return _adapter
