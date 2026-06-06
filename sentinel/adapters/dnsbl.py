"""DNSBL adapter — DNS-based IP reputation (Spamhaus ZEN).

Uses DNS queries — no HTTP, no API key, no rate limit concerns.
Spamhaus ZEN combines SBL (spam), XBL (exploits), and PBL (policy).
A listed IP returns an A record in the 127.0.0.x range; NXDOMAIN = clean.

Return codes:
  127.0.0.2  — SBL (spam source)
  127.0.0.4  — XBL (botnet/malware)
  127.0.0.10 — PBL ISP (end-user IP not expected to send mail)
  127.0.0.11 — PBL Spamhaus (same)
"""

import asyncio
import socket
from typing import Any

import structlog

from sentinel.config import get_settings

logger = structlog.get_logger("sentinel.adapters.dnsbl")

_DNSBL_ZONES = {
    "spamhaus_zen": "zen.spamhaus.org",
}

_RETURN_CODE_MEANINGS = {
    "127.0.0.2": "SBL — spam source",
    "127.0.0.4": "XBL — exploits / botnet",
    "127.0.0.10": "PBL — end-user ISP range",
    "127.0.0.11": "PBL — Spamhaus managed",
}

_MOCK_LISTED = {"185.220.101.34", "91.108.4.51"}


class DNSBLAdapter:
    """Not an httpx-based adapter — DNS queries only."""

    def __init__(self) -> None:
        settings = get_settings()
        self._mock = settings.mock_adapters
        self._log = logger

    async def check_ip(self, ip: str) -> dict[str, Any]:
        """Check an IPv4 address against Spamhaus ZEN.

        Returns:
            {
                "listed": bool,
                "zones": {"spamhaus_zen": {"listed": bool, "return_codes": [...],
                                           "meanings": [...]}},
                "summary": str,
            }
        """
        if self._mock:
            listed = ip in _MOCK_LISTED
            return {
                "listed": listed,
                "zones": {
                    "spamhaus_zen": {
                        "listed": listed,
                        "return_codes": ["127.0.0.4"] if listed else [],
                        "meanings": ["XBL — exploits / botnet"] if listed else [],
                    }
                },
                "summary": f"{'Listed' if listed else 'Clean'} on Spamhaus ZEN",
            }

        results: dict[str, Any] = {"listed": False, "zones": {}, "summary": "clean"}
        any_listed = False

        for zone_name, zone_host in _DNSBL_ZONES.items():
            zone_result = await self._check_zone(ip, zone_host)
            results["zones"][zone_name] = zone_result
            if zone_result["listed"]:
                any_listed = True

        results["listed"] = any_listed
        results["summary"] = "listed" if any_listed else "clean"
        return results

    async def _check_zone(self, ip: str, zone: str) -> dict[str, Any]:
        # Reverse the IP octets for DNSBL query
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return {"listed": False, "return_codes": [], "meanings": []}
            reversed_ip = ".".join(reversed(parts))
            query = f"{reversed_ip}.{zone}"

            loop = asyncio.get_event_loop()
            try:
                addrs = await loop.run_in_executor(None, socket.gethostbyname_ex, query)
                return_codes = addrs[2] if addrs else []
                meanings = [_RETURN_CODE_MEANINGS.get(rc, rc) for rc in return_codes]
                return {"listed": True, "return_codes": return_codes, "meanings": meanings}
            except socket.gaierror:
                # NXDOMAIN — not listed
                return {"listed": False, "return_codes": [], "meanings": []}
        except Exception as exc:
            self._log.warning("dnsbl_check_failed", error=str(exc), ip=ip, zone=zone)
            return {"listed": False, "return_codes": [], "meanings": [], "error": str(exc)}


_adapter: DNSBLAdapter | None = None


def get_dnsbl_adapter() -> DNSBLAdapter:
    global _adapter
    if _adapter is None:
        _adapter = DNSBLAdapter()
    return _adapter
