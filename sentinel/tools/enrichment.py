"""Live multi-source IOC enrichment composite (closes the Phase 4 gap).

`enrich_ioc` fans out to the Phase-3 source adapters **concurrently**
(`asyncio.gather`) and merges their results into a single composite verdict.
This works in both modes:

  - mock mode (`MOCK_ADAPTERS=true`): adapters return seeded data, so the
    composite is deterministic for the known test IOCs.
  - live mode (`MOCK_ADAPTERS=false`): the same code path makes real API
    calls; optional sources (VirusTotal, AbuseIPDB, OTX, URLScan) contribute
    only when their API keys are configured, otherwise they return {} and are
    silently skipped.

Verdict scale: malicious > suspicious > clean > unknown.
Confidence: 0.0 (no usable data) → 1.0 (clean, fully identified, no bad signal).

The merge classifies each source into one of {malicious, suspicious, clean,
none} and counts independent confirmations. The output shape matches the
historical mock contract so downstream consumers (generate_incident_report)
are unchanged.
"""

import asyncio
from datetime import UTC, datetime
from typing import Any


async def enrich_indicator(indicator: str, indicator_type: str) -> dict[str, Any]:
    """Fan out to all relevant sources for this indicator type and merge."""
    if indicator_type == "ip":
        details = await _enrich_ip(indicator)
    elif indicator_type == "hash":
        details = await _enrich_hash(indicator)
    elif indicator_type == "domain":
        details = await _enrich_domain(indicator)
    else:  # url
        details = await _enrich_url(indicator)

    verdict, confidence, tags, sources_hit, ident = _merge(details)
    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "verdict": verdict,
        "confidence": confidence,
        "tags": sorted(set(tags)),
        "country": ident.get("country"),
        "asn": ident.get("asn"),
        "org": ident.get("org"),
        "sources_checked": list(details.keys()),
        "sources_hit": sources_hit,
        "details": details,
        "enriched_at": datetime.now(UTC).isoformat(),
    }


# ── Per-type fan-out ──────────────────────────────────────────────────────────


async def _enrich_ip(ip: str) -> dict[str, Any]:
    from sentinel.adapters.abuse_ch import get_abuse_ch_adapter
    from sentinel.adapters.abuseipdb import get_abuseipdb_adapter
    from sentinel.adapters.alienvault import get_alienvault_adapter
    from sentinel.adapters.dnsbl import get_dnsbl_adapter
    from sentinel.adapters.internetdb import get_internetdb_adapter
    from sentinel.adapters.ipapi import get_ipapi_adapter
    from sentinel.adapters.virustotal import get_virustotal_adapter

    results: list[Any] = await asyncio.gather(
        get_abuse_ch_adapter().is_malicious_ip(ip),
        get_internetdb_adapter().lookup(ip),
        get_ipapi_adapter().lookup(ip),
        get_dnsbl_adapter().check_ip(ip),
        get_abuseipdb_adapter().check_ip(ip),
        get_alienvault_adapter().lookup_ip(ip),
        get_virustotal_adapter().analyze_ip(ip),
        return_exceptions=True,
    )
    feodo, internetdb, ipapi, dnsbl, abuseipdb, otx, vt = results
    return {
        "abuse_ch_feodotracker": {"listed": _ok(feodo, False)},
        "internetdb": _ok(internetdb, {}),
        "ipapi": _ok(ipapi, {}),
        "dnsbl_spamhaus": _ok(dnsbl, {}),
        "abuseipdb": _ok(abuseipdb, {}),
        "alienvault_otx": _ok(otx, {}),
        "virustotal": _ok(vt, {}),
    }


async def _enrich_hash(hash_value: str) -> dict[str, Any]:
    from sentinel.adapters.abuse_ch import get_abuse_ch_adapter
    from sentinel.adapters.alienvault import get_alienvault_adapter
    from sentinel.adapters.circl import get_circl_adapter
    from sentinel.adapters.virustotal import get_virustotal_adapter

    results: list[Any] = await asyncio.gather(
        get_abuse_ch_adapter().lookup_hash(hash_value),
        get_circl_adapter().lookup(hash_value),
        get_alienvault_adapter().lookup_hash(hash_value),
        get_virustotal_adapter().analyze_hash(hash_value),
        return_exceptions=True,
    )
    bazaar, circl, otx, vt = results
    return {
        "abuse_ch_malwarebazaar": _ok(bazaar, {}),
        "circl_hashlookup": _ok(circl, {}),
        "alienvault_otx": _ok(otx, {}),
        "virustotal": _ok(vt, {}),
    }


async def _enrich_domain(domain: str) -> dict[str, Any]:
    from sentinel.adapters.abuse_ch import get_abuse_ch_adapter
    from sentinel.adapters.alienvault import get_alienvault_adapter
    from sentinel.adapters.urlscan import get_urlscan_adapter
    from sentinel.adapters.virustotal import get_virustotal_adapter

    results: list[Any] = await asyncio.gather(
        get_abuse_ch_adapter().is_malicious_host(domain),
        get_alienvault_adapter().lookup_domain(domain),
        get_virustotal_adapter().analyze_domain(domain),
        get_urlscan_adapter().search(domain),
        return_exceptions=True,
    )
    urlhaus, otx, vt, scan = results
    return {
        "abuse_ch_urlhaus": {"listed": _ok(urlhaus, False)},
        "alienvault_otx": _ok(otx, {}),
        "virustotal": _ok(vt, {}),
        "urlscan": _ok(scan, {}),
    }


async def _enrich_url(url: str) -> dict[str, Any]:
    from sentinel.adapters.abuse_ch import get_abuse_ch_adapter
    from sentinel.adapters.alienvault import get_alienvault_adapter
    from sentinel.adapters.urlscan import get_urlscan_adapter
    from sentinel.adapters.virustotal import get_virustotal_adapter

    results: list[Any] = await asyncio.gather(
        get_abuse_ch_adapter().lookup_url(url),
        get_alienvault_adapter().lookup_url(url),
        get_virustotal_adapter().analyze_url(url),
        get_urlscan_adapter().search(url),
        return_exceptions=True,
    )
    urlhaus, otx, vt, scan = results
    return {
        "abuse_ch_urlhaus": _ok(urlhaus, {}),
        "alienvault_otx": _ok(otx, {}),
        "virustotal": _ok(vt, {}),
        "urlscan": _ok(scan, {}),
    }


def _ok(value: Any, default: Any) -> Any:
    """Treat a gathered exception (adapter failed/circuit open) as no data."""
    return default if isinstance(value, BaseException) else value


# ── Merge / scoring ───────────────────────────────────────────────────────────

# Per source: returns (signal, tags, identity) where signal is one of
# "malicious" | "suspicious" | "clean" | "none". "clean" means the source had
# usable data and saw nothing bad; "none" means the source had no usable data.


def _merge(details: dict[str, Any]) -> tuple[str, float, list[str], list[str], dict[str, Any]]:
    n_mal = n_susp = n_clean = 0
    tags: list[str] = []
    sources_hit: list[str] = []
    ident: dict[str, Any] = {"country": None, "asn": None, "org": None}

    for source, raw in details.items():
        signal, src_tags, src_ident = _classify(source, raw)
        tags.extend(src_tags)
        for key, val in src_ident.items():
            if val and not ident.get(key):
                ident[key] = val
        if signal == "malicious":
            n_mal += 1
            sources_hit.append(source)
        elif signal == "suspicious":
            n_susp += 1
            sources_hit.append(source)
        elif signal == "clean":
            n_clean += 1

    if n_mal >= 1:
        return "malicious", min(0.99, round(0.6 + 0.13 * n_mal, 2)), tags, sources_hit, ident
    if n_susp >= 1:
        return "suspicious", min(0.8, round(0.4 + 0.1 * n_susp, 2)), tags, sources_hit, ident
    if n_clean >= 1:
        return "clean", 1.0, tags, sources_hit, ident
    return "unknown", 0.0, tags, sources_hit, ident


def _classify(source: str, raw: Any) -> tuple[str, list[str], dict[str, Any]]:
    if not isinstance(raw, dict):
        return "none", [], {}

    if source in ("abuse_ch_feodotracker", "abuse_ch_urlhaus"):
        if raw.get("listed"):
            return "malicious", ["abuse.ch-listed"], {}
        # abuse.ch per-IOC lookup style (lookup_hash/lookup_url) below
        status = str(raw.get("query_status", ""))
        if status in ("hash_found", "ok"):
            fam = raw.get("malware_family")
            return "malicious", _as_tags(raw.get("tags")) + ([fam] if fam else []), {}
        return "none", [], {}

    if source == "abuse_ch_malwarebazaar":
        if str(raw.get("query_status")) == "hash_found":
            fam = raw.get("malware_family")
            return "malicious", _as_tags(raw.get("tags")) + ([fam] if fam else []), {}
        return "none", [], {}

    if source == "internetdb":
        tags = _as_tags(raw.get("tags"))
        has_data = bool(raw.get("ports") or tags or raw.get("cves"))
        if "tor" in tags:
            return "suspicious", tags, {}
        if raw.get("cves"):
            return "suspicious", tags, {}
        return ("clean" if has_data else "none"), tags, {}

    if source == "ipapi":
        country = raw.get("country")
        ccode = raw.get("countryCode")
        identified = bool(
            country and country not in ("Unknown", "") and ccode not in ("XX", "", None)
        )
        ident = (
            {"country": ccode, "asn": raw.get("as"), "org": raw.get("org")} if identified else {}
        )
        if raw.get("proxy"):
            tags = ["proxy"] + (["tor"] if raw.get("tor") else [])
            return "suspicious", tags, ident
        return ("clean" if identified else "none"), [], ident

    if source == "dnsbl_spamhaus":
        # A blocklist hit is strong evidence; a miss is NOT positive evidence of
        # cleanliness (absence from one blocklist proves nothing), so it
        # contributes no signal.
        if raw.get("listed"):
            return "malicious", ["dnsbl-listed"], {}
        return "none", [], {}

    if source == "abuseipdb":
        score = int(raw.get("abuseConfidenceScore", 0) or 0)
        has_data = bool(raw.get("isp") or raw.get("totalReports") or score)
        ident = {"country": raw.get("countryCode"), "org": raw.get("isp")} if raw.get("isp") else {}
        if score >= 80:
            return "malicious", ["abuseipdb-high"], ident
        if score >= 25:
            return "suspicious", ["abuseipdb-elevated"], ident
        return ("clean" if has_data else "none"), [], ident

    if source == "alienvault_otx":
        general = raw.get("general", {}) if isinstance(raw.get("general"), dict) else {}
        pulses = int(general.get("pulse_count", 0) or 0)
        families = general.get("malware_families") or []
        tags = _as_tags(general.get("tags")) + list(families)
        if pulses > 0 and families:
            return "malicious", tags, {}
        if pulses > 0:
            return "suspicious", tags, {}
        return "none", [], {}

    if source == "circl_hashlookup":
        if int(raw.get("KnownMalicious", 0) or 0) >= 1:
            return "malicious", _as_tags(raw.get("tags")), {}
        if int(raw.get("KnownBenign", 0) or 0) >= 1:
            return "clean", [], {}
        return "none", [], {}

    if source == "virustotal":
        data = raw.get("data", {}) if isinstance(raw.get("data"), dict) else {}
        attrs = data.get("attributes", {}) if isinstance(data.get("attributes"), dict) else {}
        stats = attrs.get("last_analysis_stats", {}) or {}
        mal = int(stats.get("malicious", 0) or 0)
        susp = int(stats.get("suspicious", 0) or 0)
        harmless = int(stats.get("harmless", 0) or 0)
        reputation = int(attrs.get("reputation", 0) or 0)
        tags = _as_tags(attrs.get("tags"))
        if mal >= 3:
            return "malicious", tags, {}
        if mal >= 1 or susp >= 3 or reputation < 0:
            return "suspicious", tags, {}
        return ("clean" if harmless > 0 else "none"), tags, {}

    if source == "urlscan":
        verdicts = raw.get("verdicts", {}) if isinstance(raw.get("verdicts"), dict) else {}
        overall = verdicts.get("overall", {}) if isinstance(verdicts.get("overall"), dict) else {}
        if overall.get("malicious"):
            return "malicious", ["urlscan-malicious"], {}
        if raw.get("results"):
            return "clean", [], {}
        return "none", [], {}

    return "none", [], {}


def _as_tags(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(t) for t in value if t]
    return []
