"""Threat intelligence tools (Phase 4).

enrich_ioc      — multi-source composite verdict (curated mock composite;
                  the individual source adapters are implemented + tested in Phase 3)
threat_hunt     — OpenSearch adapter (full-archive indicator search)
mitre_technique — MITRE adapter (local STIX 2.1 ATT&CK dataset)
"""

from typing import Any

from sentinel.mcp.middleware import run_middleware
from sentinel.mcp.server import mcp
from sentinel.tools import mock_data as mock

_VALID_IOC_TYPES = {"ip", "domain", "hash", "url"}


# ── enrich_ioc ────────────────────────────────────────────────────────────────


async def _execute_enrich_ioc(args: dict[str, Any]) -> dict[str, Any]:
    indicator = str(args.get("indicator", "")).strip()
    indicator_type = str(args.get("indicator_type", "")).strip().lower()

    if not indicator:
        return {"error": "indicator is required", "code": "MISSING_PARAMETER"}
    if indicator_type not in _VALID_IOC_TYPES:
        return {
            "error": f"indicator_type must be one of: {', '.join(sorted(_VALID_IOC_TYPES))}",
            "code": "INVALID_PARAMETER",
        }

    return mock.enrich_ioc(indicator, indicator_type)


@mcp.tool()
async def enrich_ioc(
    indicator: str,
    indicator_type: str,
) -> dict[str, Any]:
    """Enrich an IOC across all threat intel sources and return a composite verdict.

    Fans out to: abuse.ch feeds (URLhaus, MalwareBazaar, FeodoTracker, ThreatFox),
    Shodan InternetDB, ip-api.com, CIRCL Hash Lookup, Spamhaus DNSBL. Optional
    sources (if API keys are set): VirusTotal, AbuseIPDB, AlienVault OTX, URLScan.

    Always call this when you find an IP, domain, hash, or URL in an alert.
    The composite verdict tells you immediately whether to escalate.

    Verdict scale: malicious > suspicious > unknown > clean
    Confidence: 0.0 (no data) to 1.0 (multiple independent sources confirm)

    Args:
        indicator: The value to enrich, e.g. "185.220.101.34" or "44d88612..."
        indicator_type: One of: ip, domain, hash, url
    """
    return await run_middleware(
        "enrich_ioc",
        {"indicator": indicator, "indicator_type": indicator_type},
        _execute_enrich_ioc,
    )


# ── threat_hunt ───────────────────────────────────────────────────────────────


async def _execute_threat_hunt(args: dict[str, Any]) -> dict[str, Any]:
    indicator = str(args.get("indicator", "")).strip()
    look_back_days = max(1, min(int(args.get("look_back_days", 30)), 365))
    if not indicator:
        return {"error": "indicator is required", "code": "MISSING_PARAMETER"}

    from sentinel.adapters.opensearch import get_opensearch_adapter

    hits = await get_opensearch_adapter().search_logs(
        indicator, time_window_hours=look_back_days * 24, max_results=500
    )
    appearances = [
        {
            "timestamp": h.get("timestamp"),
            "host": h.get("host"),
            "source": h.get("source"),
            "event_type": h.get("event_type"),
            "message": h.get("message"),
        }
        for h in hits
    ]
    timestamps = sorted(a["timestamp"] for a in appearances if a.get("timestamp"))
    hosts = sorted({a["host"] for a in appearances if a.get("host")})
    return {
        "indicator": indicator,
        "look_back_days": look_back_days,
        "total_appearances": len(appearances),
        "first_seen": timestamps[0] if timestamps else None,
        "last_seen": timestamps[-1] if timestamps else None,
        "affected_hosts": hosts,
        "appearances": appearances,
    }


@mcp.tool()
async def threat_hunt(indicator: str, look_back_days: int = 30) -> dict[str, Any]:
    """Search backwards through ALL stored logs for every occurrence of an indicator.

    Unlike search_logs (which searches recent alert-relevant events), threat_hunt
    searches the full log archive including events that never triggered an alert.
    Use this to determine when an IOC first appeared in your environment and
    which systems it has touched. Returns a chronological timeline of appearances.

    Args:
        indicator: IP address, file hash, username, hostname, or domain
        look_back_days: How far back to search (default 30, max 365)
    """
    return await run_middleware(
        "threat_hunt",
        {"indicator": indicator, "look_back_days": look_back_days},
        _execute_threat_hunt,
    )


# ── mitre_technique ───────────────────────────────────────────────────────────


async def _execute_mitre_technique(args: dict[str, Any]) -> dict[str, Any]:
    tid = str(args.get("technique_id", "")).strip().upper()
    if not tid.startswith("T") or not any(c.isdigit() for c in tid):
        return {
            "error": f"'{tid}' is not a valid MITRE ATT&CK technique ID",
            "code": "INVALID_PARAMETER",
            "examples": ["T1059.001", "T1078", "T1003.001"],
        }

    from sentinel.adapters.mitre import get_mitre_adapter

    technique = await get_mitre_adapter().get_technique(tid)
    if technique is None:
        return {
            "error": f"Technique '{tid}' not found in the ATT&CK dataset",
            "code": "NOT_FOUND",
            "examples": ["T1059.001", "T1078", "T1110.001", "T1003.001"],
        }
    return technique


@mcp.tool()
async def mitre_technique(technique_id: str) -> dict[str, Any]:
    """Look up a MITRE ATT&CK technique: name, tactic, detection, mitigation.

    Uses the local STIX 2.1 Enterprise ATT&CK dataset — no API call at lookup
    time, always fast. Use this after get_alert() to understand what the
    attacker was trying to do and what defensive actions are recommended.

    Args:
        technique_id: MITRE technique ID, e.g. "T1059.001" or "T1078"
    """
    return await run_middleware(
        "mitre_technique", {"technique_id": technique_id}, _execute_mitre_technique
    )
