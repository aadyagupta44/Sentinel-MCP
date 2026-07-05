"""ip-api.com adapter — IP geolocation, ASN, VPN/datacenter/Tor flags.

Endpoint: http://ip-api.com/json/{ip}?fields=...
No API key required for HTTP (non-HTTPS). Rate limit: 45 req/min.
Provides: country, city, ASN, org, ISP, datacenter, proxy, Tor flags.

Note: Uses HTTP (not HTTPS) — the free tier doesn't support HTTPS.
For production with higher rate limits, use the paid tier with HTTPS.
"""

from typing import Any

from sentinel.adapters.base import BaseAdapter, CircuitOpenError

_BASE_URL = "http://ip-api.com/json"
_FIELDS = (
    "status,message,country,countryCode,region,city,zip,lat,lon,timezone,"
    "isp,org,as,asname,query,proxy,hosting,mobile"
)

_MOCK_DATA: dict[str, dict[str, Any]] = {
    "185.220.101.34": {
        "status": "success",
        "country": "Germany",
        "countryCode": "DE",
        "city": "Frankfurt am Main",
        "isp": "netzbetrieb GmbH",
        "org": "AS58220 netzbetrieb GmbH",
        "as": "AS58220",
        "asname": "AS58220",
        "query": "185.220.101.34",
        "proxy": True,
        "hosting": True,
        "mobile": False,
    },
    "91.108.4.51": {
        "status": "success",
        "country": "Netherlands",
        "countryCode": "NL",
        "city": "Amsterdam",
        "isp": "LeaseWeb Netherlands B.V.",
        "org": "AS60781 LeaseWeb Netherlands B.V.",
        "as": "AS60781",
        "asname": "AS60781",
        "query": "91.108.4.51",
        "proxy": True,
        "hosting": True,
        "mobile": False,
    },
    "8.8.8.8": {
        "status": "success",
        "country": "United States",
        "countryCode": "US",
        "city": "Mountain View",
        "isp": "Google LLC",
        "org": "AS15169 Google LLC",
        "as": "AS15169",
        "asname": "AS15169",
        "query": "8.8.8.8",
        "proxy": False,
        "hosting": True,
        "mobile": False,
    },
}


class IPApiAdapter(BaseAdapter):
    adapter_name = "ipapi"

    async def lookup(self, ip: str) -> dict[str, Any]:
        if self.is_mock:
            return _MOCK_DATA.get(
                ip,
                {
                    "status": "success",
                    "query": ip,
                    "country": "Unknown",
                    "countryCode": "XX",
                    "org": "",
                    "as": "",
                    "proxy": False,
                    "hosting": False,
                },
            )

        if self._breaker.is_open():
            raise CircuitOpenError(self.adapter_name)

        url = f"{_BASE_URL}/{ip}?fields={_FIELDS}"
        try:
            resp = await self._call("GET", url, span_name="lookup")
            resp.raise_for_status()
            data: dict[str, Any] = resp.json()
            if data.get("status") == "fail":
                self._log.warning("ipapi_fail", message=data.get("message"), ip=ip)
                return {"status": "fail", "query": ip}
            return data
        except CircuitOpenError:
            raise
        except Exception as exc:
            self._log.warning("ipapi_lookup_failed", error=str(exc), ip=ip)
            return {"status": "error", "query": ip, "error": str(exc)}


_adapter: IPApiAdapter | None = None


def get_ipapi_adapter() -> IPApiAdapter:
    global _adapter
    if _adapter is None:
        _adapter = IPApiAdapter()
    return _adapter
