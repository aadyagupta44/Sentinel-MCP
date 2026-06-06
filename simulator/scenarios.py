"""Five adversarial attack scenarios.

Each scenario(profile, iocs, rng, now) -> (log_events, alert). The log events
and the alert share the same user / host / source_ip so the Sentinel
correlate_alerts tool can group them into one incident. Adversarial scenarios
use real abuse.ch C2 IPs and malware hashes via the IocProvider.
"""

from datetime import datetime, timedelta
from random import Random
from typing import Any

from simulator.events import login_event, make_alert, network_event, process_event
from simulator.iocs import IocProvider
from simulator.profiles import Profile

Scenario = tuple[list[dict[str, Any]], dict[str, Any]]

_FOREIGN = (("Frankfurt", "DE"), ("Amsterdam", "NL"), ("Moscow", "RU"))


def impossible_travel(profile: Profile, iocs: IocProvider, rng: Random, now: datetime) -> Scenario:
    c2 = iocs.random_c2_ip(rng)
    _, country = rng.choice(_FOREIGN)
    logs = [
        login_event(profile, rng, now - timedelta(minutes=8)),
        login_event(profile, rng, now, ip=c2, country=country, mfa=False),
    ]
    alert = make_alert(
        rng,
        now,
        profile=profile,
        rule_name="Impossible Travel Detected",
        severity="critical",
        mitre_techniques=["T1078"],
        source_ip=c2,
        description=(
            f"{profile.email} authenticated from {profile.usual_country} then from "
            f"{country} ({c2}) minutes later — physically impossible travel."
        ),
    )
    return logs, alert


def brute_force(profile: Profile, iocs: IocProvider, rng: Random, now: datetime) -> Scenario:
    c2 = iocs.random_c2_ip(rng)
    logs = [
        login_event(profile, rng, now - timedelta(seconds=20 - i), success=False, ip=c2, mfa=False)
        for i in range(12)
    ]
    logs.append(login_event(profile, rng, now, ip=c2, mfa=False))
    alert = make_alert(
        rng,
        now,
        profile=profile,
        rule_name="Multiple Failed Logins Followed by Success",
        severity="high",
        mitre_techniques=["T1110.001"],
        source_ip=c2,
        description=f"12 failed logins then a success for {profile.email} from {c2} (brute force).",
    )
    return logs, alert


def suspicious_process(profile: Profile, iocs: IocProvider, rng: Random, now: datetime) -> Scenario:
    malware_hash = iocs.random_malware_hash(rng)
    logs = [
        process_event(
            profile,
            rng,
            now,
            name="powershell.exe",
            command="powershell.exe -EncodedCommand JABjAD0ATgBlAHcA",
            suspicious=True,
        ),
        process_event(
            profile,
            rng,
            now,
            name="mimikatz.exe",
            command="mimikatz.exe sekurlsa::logonpasswords",
            suspicious=True,
        ),
    ]
    alert = make_alert(
        rng,
        now,
        profile=profile,
        rule_name="Suspicious PowerShell + LSASS Access",
        severity="high",
        mitre_techniques=["T1059.001", "T1003.001"],
        affected_host=profile.hostname,
        description=(
            f"Encoded PowerShell and LSASS credential access on {profile.hostname} "
            f"(malware hash {malware_hash})."
        ),
    )
    return logs, alert


def data_exfiltration(profile: Profile, iocs: IocProvider, rng: Random, now: datetime) -> Scenario:
    c2 = iocs.random_c2_ip(rng)
    bytes_out = rng.randrange(500_000_000, 2_000_000_000)
    logs = [
        network_event(
            profile, rng, now, dst_ip=c2, dst_port=443, bytes_out=bytes_out, flagged=True
        ),
    ]
    alert = make_alert(
        rng,
        now,
        profile=profile,
        rule_name="Large Outbound Transfer to Known C2",
        severity="critical",
        mitre_techniques=["T1048"],
        source_ip=c2,
        affected_host=profile.hostname,
        description=f"{round(bytes_out / 1e9, 2)} GB exfiltrated from {profile.hostname} to {c2}.",
    )
    return logs, alert


def known_bad_ip(profile: Profile, iocs: IocProvider, rng: Random, now: datetime) -> Scenario:
    c2 = iocs.random_c2_ip(rng)
    logs = [
        network_event(
            profile,
            rng,
            now,
            dst_ip=c2,
            dst_port=rng.choice((443, 8080, 9001)),
            bytes_out=rng.randrange(1000, 50000),
            flagged=True,
        ),
    ]
    alert = make_alert(
        rng,
        now,
        profile=profile,
        rule_name="Beacon to Known Malicious IP",
        severity="high",
        mitre_techniques=["T1071"],
        source_ip=c2,
        affected_host=profile.hostname,
        description=f"{profile.hostname} is beaconing to known C2 {c2} (abuse.ch FeodoTracker).",
    )
    return logs, alert


SCENARIOS = {
    "impossible_travel": impossible_travel,
    "brute_force": brute_force,
    "suspicious_process": suspicious_process,
    "data_exfiltration": data_exfiltration,
    "known_bad_ip": known_bad_ip,
}
SCENARIO_NAMES = tuple(SCENARIOS.keys())
