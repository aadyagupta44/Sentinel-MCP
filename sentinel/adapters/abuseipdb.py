"""AbuseIPDB adapter — IP abuse confidence score and report history.

Free tier: 1,000 checks/day. Requires email signup at abuseipdb.com.
Optional — skipped gracefully if ABUSEIPDB_API_KEY is not set.

Returns: confidence score (0-100), usage type, country, ISP, total reports.
A score >= 80 is a strong signal of malicious activity.
"""

from typing import Any

from sentinel.adapters.base import BaseAdapter, CircuitOpenError
from sentinel.config import get_settings

_BASE_URL = "https://api.abuseipdb.com/api/v2"

_MOCK_DATA: dict[str, dict[str, Any]] = {
    "185.220.101.34": {
        "abuseConfidenceScore": 100,
        "countryCode": "DE",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "netzbetrieb GmbH",
        "domain": "netzbetrieb.de",
        "totalReports": 1842,
        "numDistinctUsers": 312,
        "lastReportedAt": "2026-06-02T09:01:00Z",
        "isPublic": True,
        "isWhitelisted": False,
    },
    "91.108.4.51": {
        "abuseConfidenceScore": 42,
        "countryCode": "NL",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "LeaseWeb Netherlands B.V.",
        "domain": "leaseweb.com",
        "totalReports": 87,
        "numDistinctUsers": 24,
        "lastReportedAt": "2026-05-28T14:22:00Z",
        "isPublic": True,
        "isWhitelisted": False,
    },
    "8.8.8.8": {
        "abuseConfidenceScore": 0,
        "countryCode": "US",
        "usageType": "Content Delivery Network",
        "isp": "Google LLC",
        "domain": "google.com",
        "totalReports": 0,
        "numDistinctUsers": 0,
        "lastReportedAt": None,
        "isPublic": True,
        "isWhitelisted": True,
    },
}


class AbuseIPDBAdapter(BaseAdapter):
    adapter_name = "abuseipdb"

    def __init__(self) -> None:
        super().__init__()
        settings = get_settings()
        self._api_key = settings.abuseipdb_api_key
        self._enabled = bool(self._api_key)

    async def check_ip(self, ip: str, max_age_days: int = 90) -> dict[str, Any]:
        if self.is_mock:
            return _MOCK_DATA.get(
                ip,
                {
                    "abuseConfidenceScore": 0,
                    "countryCode": "XX",
                    "usageType": "Unknown",
                    "isp": "",
                    "totalReports": 0,
                },
            )
        if not self._enabled:
            return {}

        if self._breaker.is_open():
            raise CircuitOpenError(self.adapter_name)

        try:
            resp = await self._call(
                "GET",
                f"{_BASE_URL}/check",
                span_name="check_ip",
                params={"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""},
                headers={
                    "Key": self._api_key,
                    "Accept": "application/json",
                },
            )
            resp.raise_for_status()
            data: dict[str, Any] = resp.json().get("data", {})
            return data
        except CircuitOpenError:
            raise
        except Exception as exc:
            self._log.warning("abuseipdb_check_failed", error=str(exc), ip=ip)
            return {}


_adapter: AbuseIPDBAdapter | None = None


def get_abuseipdb_adapter() -> AbuseIPDBAdapter:
    global _adapter
    if _adapter is None:
        _adapter = AbuseIPDBAdapter()
    return _adapter
