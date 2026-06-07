"""Event factories — build log documents and alerts from a profile.

Every document carries `"simulated": True` so simulator data is distinguishable
from real telemetry. Randomness is driven by an injected `random.Random` so
generation is reproducible in tests.
"""

from datetime import datetime
from random import Random
from typing import Any

from simulator.profiles import Profile

_BENIGN_PROCESSES = (
    ("chrome.exe", "chrome.exe --profile-directory=Default"),
    ("Code.exe", "Code.exe --crashpad-handler"),
    ("slack.exe", "slack.exe"),
    ("Teams.exe", "Teams.exe"),
    ("git.exe", "git pull origin main"),
)

_BENIGN_FILES = (
    "\\\\fileserver\\shared\\Q2-report.xlsx",
    "https://acmecorp.sharepoint.com/HR/policy.docx",
    "/repos/acme-api/src/main.py",
    "salesforce://opportunities/2026-Q2",
    "sap://finance/ledger/2026-06",
)


def login_event(
    profile: Profile,
    rng: Random,
    now: datetime,
    *,
    success: bool = True,
    ip: str | None = None,
    country: str | None = None,
    mfa: bool = True,
) -> dict[str, Any]:
    src_ip = ip or profile.usual_ip
    ctry = country or profile.usual_country
    outcome = "succeeded" if success else "failed"
    return {
        "simulated": True,
        "timestamp": now.isoformat(),
        "source": "keycloak",
        "event_type": "auth",
        "host": None,
        "user": profile.email,
        "ip": src_ip,
        "country": ctry,
        "success": success,
        "mfa_method": ("TOTP" if mfa else None),
        "message": f"login {outcome} for {profile.email} from {src_ip} ({ctry})",
    }


def file_access_event(profile: Profile, rng: Random, now: datetime) -> dict[str, Any]:
    path = rng.choice(_BENIGN_FILES)
    return {
        "simulated": True,
        "timestamp": now.isoformat(),
        "source": "dlp",
        "event_type": "file_access",
        "host": profile.hostname,
        "user": profile.email,
        "path": path,
        "action": rng.choice(("read", "write")),
        "message": f"{profile.email} accessed {path}",
    }


def process_event(
    profile: Profile,
    rng: Random,
    now: datetime,
    *,
    name: str | None = None,
    command: str | None = None,
    suspicious: bool = False,
) -> dict[str, Any]:
    if name is None:
        name, command = rng.choice(_BENIGN_PROCESSES)
    return {
        "simulated": True,
        "timestamp": now.isoformat(),
        "source": "wazuh",
        "event_type": "process",
        "host": profile.hostname,
        "user": profile.email,
        "process": name,
        "command_line": command,
        "suspicious": suspicious,
        "message": f"process {name} on {profile.hostname}: {command}",
    }


def network_event(
    profile: Profile,
    rng: Random,
    now: datetime,
    *,
    dst_ip: str,
    dst_port: int = 443,
    bytes_out: int = 0,
    flagged: bool = False,
) -> dict[str, Any]:
    return {
        "simulated": True,
        "timestamp": now.isoformat(),
        "source": "wazuh",
        "event_type": "network",
        "host": profile.hostname,
        "user": profile.email,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "bytes_out": bytes_out,
        "threat_intel_flagged": flagged,
        "message": f"{profile.hostname} → {dst_ip}:{dst_port} ({bytes_out} bytes out)",
    }


def make_alert(
    rng: Random,
    now: datetime,
    *,
    profile: Profile,
    rule_name: str,
    severity: str,
    mitre_techniques: list[str],
    description: str,
    source_ip: str | None = None,
    affected_host: str | None = None,
) -> dict[str, Any]:
    return {
        "simulated": True,
        "alert_id": f"SIM-{rng.randrange(10**6, 10**7)}",
        "severity": severity,
        "rule_name": rule_name,
        "affected_user": profile.email,
        "affected_host": affected_host,
        "source_ip": source_ip,
        "timestamp": now.isoformat(),
        "status": "open",
        "mitre_techniques": mitre_techniques,
        "description": description,
    }
