"""Shodan InternetDB adapter — open ports, CVEs, tags for any IP.

Endpoint: https://internetdb.shodan.io/{ip}
No API key, no authentication required.
Returns: open ports, CPEs, CVEs, hostnames, tags.

Results cached in Postgres ThreatIntelCache for 7 days to minimise calls.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

from sentinel.adapters.base import BaseAdapter, CircuitOpenError

_BASE_URL = "https://internetdb.shodan.io"
_CACHE_TTL_DAYS = 7

# Mock data for known test IPs
_MOCK_DATA: dict[str, dict[str, Any]] = {
    "185.220.101.34": {
        "ip": "185.220.101.34",
        "ports": [443, 9001, 9030],
        "cpes": [],
        "cves": [],
        "hostnames": [],
        "tags": ["tor"],
    },
    "91.108.4.51": {
        "ip": "91.108.4.51",
        "ports": [80, 443, 1194],
        "cpes": [],
        "cves": [],
        "hostnames": ["vpn.example.com"],
        "tags": ["vpn"],
    },
    "8.8.8.8": {
        "ip": "8.8.8.8",
        "ports": [53],
        "cpes": [],
        "cves": [],
        "hostnames": ["dns.google"],
        "tags": ["dns"],
    },
}


class InternetDBAdapter(BaseAdapter):
    adapter_name = "internetdb"

    async def lookup(self, ip: str) -> dict[str, Any]:
        if self.is_mock:
            return _MOCK_DATA.get(ip, {"ip": ip, "ports": [], "cpes": [], "cves": [], "hostnames": [], "tags": []})

        # Try cache first
        cached = await self._get_cached(ip)
        if cached is not None:
            return cached

        if self._breaker.is_open():
            raise CircuitOpenError(self.adapter_name)

        url = f"{_BASE_URL}/{ip}"
        try:
            resp = await self._call("GET", url, span_name="lookup")
            if resp.status_code == 404:
                await self._breaker.record_success()
                result: dict[str, Any] = {"ip": ip, "ports": [], "cpes": [], "cves": [], "hostnames": [], "tags": []}
                await self._store_cached(ip, result)
                return result
            resp.raise_for_status()
            data = resp.json()
            await self._store_cached(ip, data)
            return data
        except CircuitOpenError:
            raise
        except Exception as exc:
            self._log.warning("internetdb_lookup_failed", error=str(exc), ip=ip)
            return {"ip": ip, "ports": [], "cpes": [], "cves": [], "hostnames": [], "tags": [], "error": str(exc)}

    async def _get_cached(self, ip: str) -> dict[str, Any] | None:
        try:
            from sqlalchemy import select
            from sentinel.db.session import get_session_factory
            from sentinel.db.models import ThreatIntelCache

            async with get_session_factory()() as session:
                row = await session.scalar(
                    select(ThreatIntelCache).where(
                        ThreatIntelCache.indicator == ip,
                        ThreatIntelCache.source == self.adapter_name,
                        ThreatIntelCache.expires_at > datetime.now(timezone.utc),
                    )
                )
                if row:
                    return dict(row.data)
        except Exception:
            pass
        return None

    async def _store_cached(self, ip: str, data: dict[str, Any]) -> None:
        try:
            from sqlalchemy.dialects.postgresql import insert
            from sentinel.db.session import get_session_factory
            from sentinel.db.models import ThreatIntelCache

            now = datetime.now(timezone.utc)
            expires = now + timedelta(days=_CACHE_TTL_DAYS)
            async with get_session_factory()() as session:
                async with session.begin():
                    await session.execute(
                        insert(ThreatIntelCache).values(
                            indicator=ip,
                            source=self.adapter_name,
                            data=data,
                            cached_at=now,
                            expires_at=expires,
                        ).on_conflict_do_update(
                            index_elements=["indicator", "source"],
                            set_={"data": data, "cached_at": now, "expires_at": expires},
                        )
                    )
        except Exception as exc:
            self._log.debug("internetdb_cache_store_failed", error=str(exc))


_adapter: InternetDBAdapter | None = None


def get_internetdb_adapter() -> InternetDBAdapter:
    global _adapter
    if _adapter is None:
        _adapter = InternetDBAdapter()
    return _adapter
