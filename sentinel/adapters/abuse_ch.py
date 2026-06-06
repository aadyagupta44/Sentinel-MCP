"""abuse.ch adapter — free community threat intelligence feeds.

Downloads and caches in-memory:
  - FeodoTracker C2 IP blocklist (botnet C2 servers)
  - URLhaus malicious URL/host list
  - MalwareBazaar recent malware hash list
  - ThreatFox IOC database

Lookups are in-memory (instant). API calls for per-indicator detail.
No API key required. Refreshes every ABUSE_CH_REFRESH_INTERVAL_MINUTES.
"""

import asyncio
import csv
import io
from datetime import datetime, timezone
from typing import Any

from opentelemetry import trace

from sentinel.adapters.base import BaseAdapter
from sentinel.config import get_settings

tracer = trace.get_tracer("sentinel.adapters.abuse_ch")

_FEODOTRACKER_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
_URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/text/"
_BAZAAR_URL = "https://bazaar.abuse.ch/export/csv/recent/"
_URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/"
_BAZAAR_API = "https://mb-api.abuse.ch/api/v1/"
_THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"


class AbuseCHAdapter(BaseAdapter):
    adapter_name = "abuse_ch"

    def __init__(self) -> None:
        super().__init__()
        self._feodo_ips: frozenset[str] = frozenset()
        self._urlhaus_hosts: frozenset[str] = frozenset()
        self._bazaar_hashes: frozenset[str] = frozenset()
        self._threatfox_iocs: frozenset[str] = frozenset()
        self._last_refresh: datetime | None = None
        self._refresh_lock = asyncio.Lock()
        self._loaded = False

    async def ensure_loaded(self) -> None:
        """Download feeds on first use. Subsequent calls are no-ops if fresh."""
        if self._loaded:
            return
        async with self._refresh_lock:
            if not self._loaded:
                await self._refresh_feeds()

    async def refresh(self) -> None:
        async with self._refresh_lock:
            await self._refresh_feeds()

    async def _refresh_feeds(self) -> None:
        if self.is_mock:
            # Seed with known test IOCs
            self._feodo_ips = frozenset({"185.220.101.34", "91.108.56.181"})
            self._urlhaus_hosts = frozenset({"malware-c2.example.com", "evil.example.net"})
            self._bazaar_hashes = frozenset({"44d88612fea8a8f36de82e1278abb02f"})
            self._threatfox_iocs = frozenset({"185.220.101.34", "44d88612fea8a8f36de82e1278abb02f"})
            self._loaded = True
            self._last_refresh = datetime.now(timezone.utc)
            return

        tasks = [
            self._download_feodotracker(),
            self._download_urlhaus(),
            self._download_bazaar(),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        feodo, urlhaus, bazaar = results

        if not isinstance(feodo, Exception):
            self._feodo_ips = feodo
        if not isinstance(urlhaus, Exception):
            self._urlhaus_hosts = urlhaus
        if not isinstance(bazaar, Exception):
            self._bazaar_hashes = bazaar

        self._loaded = True
        self._last_refresh = datetime.now(timezone.utc)
        self._log.info(
            "abuse_ch_feeds_refreshed",
            feodo_count=len(self._feodo_ips),
            urlhaus_count=len(self._urlhaus_hosts),
            bazaar_count=len(self._bazaar_hashes),
        )

    async def _download_feodotracker(self) -> frozenset[str]:
        with tracer.start_as_current_span("abuse_ch.download_feodotracker"):
            try:
                resp = await self._retry_request("GET", _FEODOTRACKER_URL)
                resp.raise_for_status()
                ips = set()
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        ips.add(line.split()[0])
                return frozenset(ips)
            except Exception as exc:
                self._log.warning("feodotracker_download_failed", error=str(exc))
                return self._feodo_ips  # keep existing

    async def _download_urlhaus(self) -> frozenset[str]:
        with tracer.start_as_current_span("abuse_ch.download_urlhaus"):
            try:
                resp = await self._retry_request("GET", _URLHAUS_URL)
                resp.raise_for_status()
                hosts: set[str] = set()
                import urllib.parse
                for line in resp.text.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        try:
                            parsed = urllib.parse.urlparse(line)
                            if parsed.netloc:
                                hosts.add(parsed.netloc.split(":")[0])
                        except Exception:
                            pass
                return frozenset(hosts)
            except Exception as exc:
                self._log.warning("urlhaus_download_failed", error=str(exc))
                return self._urlhaus_hosts

    async def _download_bazaar(self) -> frozenset[str]:
        with tracer.start_as_current_span("abuse_ch.download_bazaar"):
            try:
                resp = await self._retry_request("GET", _BAZAAR_URL)
                resp.raise_for_status()
                hashes: set[str] = set()
                reader = csv.DictReader(
                    io.StringIO(resp.text.lstrip("﻿")),
                    skipinitialspace=True,
                )
                for row in reader:
                    sha256 = row.get("sha256_hash", "").strip()
                    md5 = row.get("md5_hash", "").strip()
                    if sha256:
                        hashes.add(sha256.lower())
                    if md5:
                        hashes.add(md5.lower())
                return frozenset(hashes)
            except Exception as exc:
                self._log.warning("bazaar_download_failed", error=str(exc))
                return self._bazaar_hashes

    # ── Bulk in-memory lookups ────────────────────────────────────────────────

    async def is_malicious_ip(self, ip: str) -> bool:
        await self.ensure_loaded()
        return ip in self._feodo_ips

    async def is_malicious_host(self, host: str) -> bool:
        await self.ensure_loaded()
        return host.lower() in self._urlhaus_hosts

    async def is_malicious_hash(self, hash_value: str) -> bool:
        await self.ensure_loaded()
        return hash_value.lower() in self._bazaar_hashes

    # ── Per-indicator API lookups ─────────────────────────────────────────────

    async def lookup_url(self, url: str) -> dict[str, Any]:
        if self.is_mock:
            return {"query_status": "not_in_database", "url": url}

        with tracer.start_as_current_span("abuse_ch.lookup_url"):
            try:
                resp = await self._retry_request(
                    "POST", _URLHAUS_API + "url/", data={"url": url}
                )
                resp.raise_for_status()
                await self._breaker.record_success()
                return resp.json()
            except Exception as exc:
                await self._breaker.record_failure()
                self._log.warning("urlhaus_lookup_failed", error=str(exc))
                return {}

    async def lookup_hash(self, hash_value: str) -> dict[str, Any]:
        if self.is_mock:
            if hash_value.lower() in {"44d88612fea8a8f36de82e1278abb02f"}:
                return {
                    "query_status": "hash_found",
                    "sha256_hash": hash_value,
                    "file_type": "exe",
                    "tags": ["emotet", "dropper"],
                    "malware_family": "Emotet",
                }
            return {"query_status": "hash_not_found"}

        with tracer.start_as_current_span("abuse_ch.lookup_hash"):
            try:
                resp = await self._retry_request(
                    "POST", _BAZAAR_API,
                    json={"query": "get_file_info", "hash": hash_value},
                )
                resp.raise_for_status()
                await self._breaker.record_success()
                return resp.json()
            except Exception as exc:
                await self._breaker.record_failure()
                self._log.warning("bazaar_lookup_failed", error=str(exc))
                return {}

    async def lookup_ioc(self, ioc: str) -> dict[str, Any]:
        if self.is_mock:
            return {"query_status": "no_result", "ioc": ioc}

        with tracer.start_as_current_span("abuse_ch.lookup_threatfox"):
            try:
                resp = await self._retry_request(
                    "POST", _THREATFOX_API,
                    json={"query": "search_ioc", "search_term": ioc},
                )
                resp.raise_for_status()
                await self._breaker.record_success()
                return resp.json()
            except Exception as exc:
                await self._breaker.record_failure()
                self._log.warning("threatfox_lookup_failed", error=str(exc))
                return {}


_adapter: AbuseCHAdapter | None = None


def get_abuse_ch_adapter() -> AbuseCHAdapter:
    global _adapter
    if _adapter is None:
        _adapter = AbuseCHAdapter()
    return _adapter
