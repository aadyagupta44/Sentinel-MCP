"""Centralized mock data factory for Phase 2 placeholder tools.

Every function is deterministic: same input always produces the same output.
The structure of each response exactly matches what the real Phase 3+4
implementation will return, so replacing mock logic with real adapter
calls requires no schema changes.
"""

from datetime import datetime, timedelta, timezone
from typing import Any

# ── Known test employees (used across all tools for consistency) ──────────────

_EMPLOYEES: dict[str, dict[str, Any]] = {
    "alice.hr@acmecorp.com": {
        "name": "Alice Chen",
        "department": "Human Resources",
        "manager": "carol.hr@acmecorp.com",
        "groups": ["HR-All", "SharePoint-HR", "Workday-Users"],
        "mfa_enabled": True,
        "mfa_method": "TOTP",
        "devices": ["MacBook-Alice", "iPhone-Alice"],
        "usual_ip": "103.21.48.10",
        "usual_country": "IN",
        "risk_level": "low",
    },
    "bob.finance@acmecorp.com": {
        "name": "Bob Sharma",
        "department": "Finance",
        "manager": "dave.finance@acmecorp.com",
        "groups": ["Finance-All", "SAP-Users", "Sensitive-Finance"],
        "mfa_enabled": True,
        "mfa_method": "Push",
        "devices": ["LAPTOP-FINANCE-03", "iPhone-Bob"],
        "usual_ip": "103.21.48.11",
        "usual_country": "IN",
        "risk_level": "medium",
    },
    "charlie.devops@acmecorp.com": {
        "name": "Charlie Patel",
        "department": "DevOps",
        "manager": "eve.devops@acmecorp.com",
        "groups": ["DevOps-All", "AWS-Admins", "GitHub-Org"],
        "mfa_enabled": True,
        "mfa_method": "YubiKey",
        "devices": ["MacBook-Charlie", "LAPTOP-DEVOPS-01"],
        "usual_ip": "103.21.48.12",
        "usual_country": "IN",
        "risk_level": "low",
    },
}

# ── Known test alerts ─────────────────────────────────────────────────────────

_ALERTS: dict[str, dict[str, Any]] = {
    "ALT-2026-001": {
        "alert_id": "ALT-2026-001",
        "severity": "high",
        "rule_name": "Suspicious PowerShell Execution with Encoded Command",
        "affected_host": "LAPTOP-HR-03",
        "affected_user": "alice.hr@acmecorp.com",
        "timestamp": "2026-06-02T08:14:33Z",
        "status": "open",
        "mitre_techniques": ["T1059.001"],
        "source_ip": None,
        "raw_log_references": ["log-es-2026-1001", "log-es-2026-1002"],
        "description": (
            "PowerShell was launched with a Base64-encoded command string on "
            "LAPTOP-HR-03. Encoded execution is a common technique for "
            "evading script-based detection rules."
        ),
        "raw_command": "powershell.exe -EncodedCommand JABjAD0ATgBlAHcALQBPAGIA...",
        "risk_score": 78,
    },
    "ALT-2026-002": {
        "alert_id": "ALT-2026-002",
        "severity": "critical",
        "rule_name": "Impossible Travel Detected",
        "affected_host": None,
        "affected_user": "bob.finance@acmecorp.com",
        "timestamp": "2026-06-02T09:02:11Z",
        "status": "open",
        "mitre_techniques": ["T1078"],
        "source_ip": "185.220.101.34",
        "raw_log_references": ["log-es-2026-2001"],
        "description": (
            "bob.finance@acmecorp.com authenticated from Mumbai (IN) at 09:00 "
            "and then from Frankfurt (DE) at 09:08 — physically impossible travel. "
            "The Frankfurt IP (185.220.101.34) is a known Tor exit node."
        ),
        "raw_command": None,
        "risk_score": 96,
    },
    "ALT-2026-003": {
        "alert_id": "ALT-2026-003",
        "severity": "medium",
        "rule_name": "Multiple Failed Logins Followed by Success",
        "affected_host": None,
        "affected_user": "charlie.devops@acmecorp.com",
        "timestamp": "2026-06-02T11:45:00Z",
        "status": "investigating",
        "mitre_techniques": ["T1110.001"],
        "source_ip": "91.108.4.51",
        "raw_log_references": ["log-es-2026-3001", "log-es-2026-3002"],
        "description": (
            "32 failed login attempts for charlie.devops@acmecorp.com from "
            "91.108.4.51 over 4 minutes, followed by one successful authentication."
        ),
        "raw_command": None,
        "risk_score": 65,
    },
}

# ── Known IOCs ────────────────────────────────────────────────────────────────

_IOCS: dict[str, dict[str, Any]] = {
    "185.220.101.34": {
        "verdict": "malicious",
        "confidence": 0.97,
        "tags": ["tor-exit-node", "c2", "emotet"],
        "country": "DE",
        "asn": "AS58220",
        "org": "netzbetrieb GmbH",
        "sources_hit": ["abuse_ch_feodotracker", "dnsbl_spamhaus"],
        "details": {
            "abuse_ch_feodotracker": {"listed": True, "malware_family": "Emotet", "first_seen": "2026-01-15"},
            "internetdb": {"ports": [443, 9001, 9030], "cves": [], "tags": ["tor"]},
            "ipapi": {"country": "DE", "asn": "AS58220", "org": "netzbetrieb GmbH", "is_datacenter": True, "is_tor": True},
            "dnsbl_spamhaus": {"zen": True, "xbl": True, "sbl": False},
        },
    },
    "91.108.4.51": {
        "verdict": "suspicious",
        "confidence": 0.62,
        "tags": ["vpn", "proxy"],
        "country": "NL",
        "asn": "AS60781",
        "org": "LeaseWeb Netherlands",
        "sources_hit": ["dnsbl_spamhaus"],
        "details": {
            "internetdb": {"ports": [80, 443, 1194], "cves": [], "tags": ["vpn"]},
            "ipapi": {"country": "NL", "asn": "AS60781", "org": "LeaseWeb Netherlands B.V.", "is_datacenter": True, "is_tor": False},
            "dnsbl_spamhaus": {"zen": False, "xbl": True, "sbl": False},
        },
    },
    "44d88612fea8a8f36de82e1278abb02f": {
        "verdict": "malicious",
        "confidence": 0.99,
        "tags": ["malware", "emotet", "dropper"],
        "country": None,
        "asn": None,
        "org": None,
        "sources_hit": ["abuse_ch_malwarebazaar", "circl_hashlookup"],
        "details": {
            "abuse_ch_malwarebazaar": {"listed": True, "malware_family": "Emotet", "file_type": "exe", "first_seen": "2026-01-20"},
            "circl_hashlookup": {"known_malicious": True, "source": "MalwareBazaar"},
        },
    },
    "8.8.8.8": {
        "verdict": "clean",
        "confidence": 1.0,
        "tags": ["dns", "google"],
        "country": "US",
        "asn": "AS15169",
        "org": "Google LLC",
        "sources_hit": [],
        "details": {
            "internetdb": {"ports": [53], "cves": [], "tags": ["google-dns"]},
            "ipapi": {"country": "US", "asn": "AS15169", "org": "Google LLC", "is_datacenter": True, "is_tor": False},
            "dnsbl_spamhaus": {"zen": False, "xbl": False, "sbl": False},
        },
    },
}


# ── Public factory functions ──────────────────────────────────────────────────

def get_alert(alert_id: str) -> dict[str, Any] | None:
    return _ALERTS.get(alert_id)


def list_active_alerts() -> list[dict[str, Any]]:
    return [a for a in _ALERTS.values() if a["status"] == "open"]


def get_user(email: str) -> dict[str, Any] | None:
    emp = _EMPLOYEES.get(email.lower())
    if not emp:
        return None
    now = datetime.now(timezone.utc)
    return {
        "email": email,
        "name": emp["name"],
        "department": emp["department"],
        "manager": emp["manager"],
        "groups": emp["groups"],
        "mfa_enabled": emp["mfa_enabled"],
        "mfa_method": emp["mfa_method"],
        "registered_devices": emp["devices"],
        "account_status": "active",
        "last_password_change": (now - timedelta(days=80)).strftime("%Y-%m-%d"),
        "created_at": "2022-03-01",
        "last_login": (now - timedelta(hours=2)).isoformat(),
    }


def get_logins(email: str, days: int) -> list[dict[str, Any]]:
    emp = _EMPLOYEES.get(email.lower())
    if not emp:
        return []
    now = datetime.now(timezone.utc)
    logins = []
    for i in range(min(days * 2, 20)):
        offset_hours = i * 12
        logins.append({
            "timestamp": (now - timedelta(hours=offset_hours)).isoformat(),
            "ip_address": emp["usual_ip"],
            "country": emp["usual_country"],
            "device": emp["devices"][0],
            "success": True,
            "mfa_method": emp["mfa_method"],
        })
    # Inject suspicious login for bob
    if email.lower() == "bob.finance@acmecorp.com" and days >= 1:
        logins.insert(0, {
            "timestamp": (now - timedelta(hours=3)).isoformat(),
            "ip_address": "185.220.101.34",
            "country": "DE",
            "device": "Unknown",
            "success": True,
            "mfa_method": None,
        })
    return logins


def enrich_ioc(indicator: str, indicator_type: str) -> dict[str, Any]:
    data = _IOCS.get(indicator)
    if data:
        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            **data,
            "sources_checked": list(data["details"].keys()),
            "enriched_at": datetime.now(timezone.utc).isoformat(),
        }
    # Unknown indicator — return clean/unknown
    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "verdict": "unknown",
        "confidence": 0.0,
        "tags": [],
        "country": None,
        "asn": None,
        "org": None,
        "sources_checked": ["abuse_ch_feodotracker", "internetdb", "ipapi", "dnsbl_spamhaus"],
        "sources_hit": [],
        "details": {},
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }


def risk_score(email: str) -> dict[str, Any]:
    emp = _EMPLOYEES.get(email.lower())
    if not emp:
        return {"email": email, "score": 0, "level": "unknown", "factors": []}
    scores = {
        "alice.hr@acmecorp.com": (35, "low"),
        "bob.finance@acmecorp.com": (72, "high"),
        "charlie.devops@acmecorp.com": (28, "low"),
    }
    score_val, level = scores.get(email.lower(), (10, "low"))
    factors = []
    if score_val > 60:
        factors = [
            {"factor": "recent_impossible_travel", "weight": 40, "detail": "Login from DE 8 min after IN"},
            {"factor": "login_from_known_bad_ip", "weight": 32, "detail": "185.220.101.34 is a Tor exit node on FeodoTracker"},
        ]
    return {
        "email": email,
        "score": score_val,
        "level": level,
        "factors": factors,
        "assessed_at": datetime.now(timezone.utc).isoformat(),
    }


def device_processes(hostname: str, time_window_minutes: int) -> list[dict[str, Any]]:
    return [
        {
            "pid": 4821,
            "parent_pid": 1234,
            "name": "powershell.exe",
            "command_line": "powershell.exe -EncodedCommand JABjAD0A...",
            "user": "ACMECORP\\alice",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "suspicious": True,
            "suspicion_reason": "Encoded command argument",
        },
        {
            "pid": 5012,
            "parent_pid": 4821,
            "name": "cmd.exe",
            "command_line": "cmd.exe /c whoami",
            "user": "ACMECORP\\alice",
            "started_at": datetime.now(timezone.utc).isoformat(),
            "suspicious": True,
            "suspicion_reason": "Spawned by PowerShell",
        },
    ]


def network_connections(hostname: str, time_window_minutes: int) -> list[dict[str, Any]]:
    return [
        {
            "pid": 4821,
            "process_name": "powershell.exe",
            "src_ip": "10.0.1.42",
            "src_port": 49821,
            "dst_ip": "185.220.101.34",
            "dst_port": 443,
            "protocol": "TCP",
            "state": "ESTABLISHED",
            "threat_intel_flagged": True,
            "threat_intel_reason": "Known Emotet C2 (FeodoTracker)",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    ]
