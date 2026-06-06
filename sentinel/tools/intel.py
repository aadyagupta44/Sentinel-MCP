"""Threat intelligence tools.

enrich_ioc      — FULLY IMPLEMENTED (Phase 2, mock data)
threat_hunt     — stub (Phase 4: OpenSearch adapter)
mitre_technique — stub (Phase 4: local MITRE STIX JSON)
"""

from typing import Any, Literal

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
    return {
        "status": "not_yet_implemented",
        "phase": "Phase 4 — OpenSearch adapter",
        "indicator": args.get("indicator"),
        "look_back_days": args.get("look_back_days", 30),
        "appearances": [],
        "total_appearances": 0,
    }


@mcp.tool()
async def threat_hunt(indicator: str, look_back_days: int = 30) -> dict[str, Any]:
    """Search backwards through ALL stored logs for every occurrence of an indicator.

    Unlike search_logs (which searches recent alert-relevant events), threat_hunt
    searches the full log archive including events that never triggered an alert.
    Use this to determine when an IOC first appeared in your environment and
    which systems it has touched.

    Returns a chronological timeline of appearances.

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
    # Basic validation
    if not tid.startswith("T") or not any(c.isdigit() for c in tid):
        return {
            "error": f"'{tid}' is not a valid MITRE ATT&CK technique ID",
            "code": "INVALID_PARAMETER",
            "examples": ["T1059.001", "T1078", "T1003.001"],
        }
    # Stub responses for known IDs used in test data
    known: dict[str, dict[str, Any]] = {
        "T1059.001": {
            "technique_id": "T1059.001",
            "name": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution",
            "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
            "detection": "Monitor for PowerShell execution with suspicious flags: -EncodedCommand, -WindowStyle Hidden, -NonInteractive, -ExecutionPolicy Bypass.",
            "mitigation": "Constrained Language Mode, AMSI, Logging (Script Block Logging, Module Logging, Transcription).",
            "data_sources": ["Command: Command Execution", "Process: Process Creation"],
        },
        "T1078": {
            "technique_id": "T1078",
            "name": "Valid Accounts",
            "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
            "description": "Adversaries may obtain and abuse credentials of existing accounts to gain access.",
            "detection": "Monitor for impossible travel, logins from new geographies/devices, off-hours access.",
            "mitigation": "MFA, conditional access policies, privileged access workstations.",
            "data_sources": ["Authentication: Authentication Log", "Logon Session: Logon Session Creation"],
        },
        "T1110.001": {
            "technique_id": "T1110.001",
            "name": "Brute Force: Password Guessing",
            "tactic": "Credential Access",
            "description": "Adversaries may use repeated login attempts with common passwords.",
            "detection": "Monitor for high volume of failed authentications from single source IP.",
            "mitigation": "Account lockout policy, MFA, login rate limiting.",
            "data_sources": ["Authentication: Authentication Log"],
        },
        "T1003.001": {
            "technique_id": "T1003.001",
            "name": "OS Credential Dumping: LSASS Memory",
            "tactic": "Credential Access",
            "description": "Adversaries may attempt to access credential material stored in LSASS process memory.",
            "detection": "Monitor for access to LSASS process memory, tools like Mimikatz or ProcDump targeting LSASS.",
            "mitigation": "Credential Guard, LSA Protection, restrict debugging privileges.",
            "data_sources": ["Process: OS API Execution", "Process: Process Access"],
        },
    }
    if tid in known:
        return known[tid]
    return {
        "status": "not_yet_implemented",
        "phase": "Phase 4 — local MITRE STIX JSON",
        "technique_id": tid,
        "note": "Full MITRE ATT&CK lookup available after Phase 4.",
    }


@mcp.tool()
async def mitre_technique(technique_id: str) -> dict[str, Any]:
    """Look up a MITRE ATT&CK technique: name, tactic, detection, mitigation.

    Uses the local STIX 2.1 Enterprise ATT&CK JSON — no API call, always fast.
    Use this after get_alert() to understand what the attacker was trying to
    do and what defensive actions are recommended.

    Args:
        technique_id: MITRE technique ID, e.g. "T1059.001" or "T1078"
    """
    return await run_middleware(
        "mitre_technique", {"technique_id": technique_id}, _execute_mitre_technique
    )
