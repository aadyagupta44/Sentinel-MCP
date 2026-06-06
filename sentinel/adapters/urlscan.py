"""URLScan.io adapter — URL analysis, screenshots, DOM inspection.

Free tier: 100 scans/day, 10,000 searches/day. Requires signup at urlscan.io.
Optional — skipped gracefully if URLSCAN_API_KEY is not set.

search() — finds past scans matching a query (no scan credit used)
scan()   — submits a new URL for scanning (uses scan credit)
get()    — retrieves results of a past scan by UUID
"""

from typing import Any

from sentinel.adapters.base import BaseAdapter, CircuitOpenError
from sentinel.config import get_settings

_BASE_URL = "https://urlscan.io/api/v1"


class URLScanAdapter(BaseAdapter):
    adapter_name = "urlscan"

    def __init__(self) -> None:
        super().__init__()
        settings = get_settings()
        self._api_key = settings.urlscan_api_key
        self._enabled = bool(self._api_key)

    async def search(self, query: str, size: int = 10) -> dict[str, Any]:
        """Search past scans — uses search credits, not scan credits."""
        if self.is_mock:
            return {"results": [], "total": 0, "query": query}
        if not self._enabled:
            return {}

        if self._breaker.is_open():
            raise CircuitOpenError(self.adapter_name)

        try:
            resp = await self._call(
                "GET",
                f"{_BASE_URL}/search/",
                span_name="search",
                params={"q": query, "size": min(size, 100)},
                headers={"API-Key": self._api_key},
            )
            resp.raise_for_status()
            return resp.json()
        except CircuitOpenError:
            raise
        except Exception as exc:
            self._log.warning("urlscan_search_failed", error=str(exc))
            return {}

    async def scan(self, url: str, visibility: str = "private") -> dict[str, Any]:
        """Submit a URL for scanning. Returns scan UUID."""
        if self.is_mock:
            return {
                "uuid": "mock-scan-uuid",
                "result": "https://urlscan.io/result/mock-scan-uuid/",
                "visibility": visibility,
            }
        if not self._enabled:
            return {}

        if self._breaker.is_open():
            raise CircuitOpenError(self.adapter_name)

        try:
            resp = await self._call(
                "POST",
                f"{_BASE_URL}/scan/",
                span_name="scan",
                json={"url": url, "visibility": visibility},
                headers={"API-Key": self._api_key, "Content-Type": "application/json"},
            )
            if resp.status_code == 429:
                self._log.warning("urlscan_rate_limited")
                return {"error": "rate_limited"}
            resp.raise_for_status()
            return resp.json()
        except CircuitOpenError:
            raise
        except Exception as exc:
            self._log.warning("urlscan_scan_failed", error=str(exc))
            return {}

    async def get_result(self, uuid: str) -> dict[str, Any]:
        """Retrieve completed scan result by UUID."""
        if self.is_mock:
            return {
                "task": {"uuid": uuid},
                "verdicts": {"overall": {"malicious": False, "score": 0}},
            }
        if not self._enabled:
            return {}

        if self._breaker.is_open():
            raise CircuitOpenError(self.adapter_name)

        try:
            resp = await self._call("GET", f"{_BASE_URL}/result/{uuid}/", span_name="get_result")
            if resp.status_code == 404:
                return {}
            resp.raise_for_status()
            return resp.json()
        except CircuitOpenError:
            raise
        except Exception as exc:
            self._log.warning("urlscan_get_result_failed", error=str(exc))
            return {}


_adapter: URLScanAdapter | None = None


def get_urlscan_adapter() -> URLScanAdapter:
    global _adapter
    if _adapter is None:
        _adapter = URLScanAdapter()
    return _adapter
