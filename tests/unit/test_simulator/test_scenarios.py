"""Adversarial scenario tests."""

from datetime import UTC, datetime
from random import Random

import pytest

from simulator.iocs import IocProvider
from simulator.profiles import PROFILES
from simulator.scenarios import SCENARIO_NAMES, SCENARIOS

NOW = datetime(2026, 6, 6, 12, 0, tzinfo=UTC)
IOCS = IocProvider(c2_ips=("9.9.9.9",), malware_hashes=("deadbeefdeadbeef",))
P = PROFILES[0]


def test_five_scenarios_registered():
    assert set(SCENARIO_NAMES) == {
        "impossible_travel",
        "brute_force",
        "suspicious_process",
        "data_exfiltration",
        "known_bad_ip",
    }


@pytest.mark.parametrize("name", SCENARIO_NAMES)
def test_scenario_returns_logs_and_alert(name):
    logs, alert = SCENARIOS[name](P, IOCS, Random(0), NOW)
    assert logs, f"{name} produced no log events"
    assert alert["alert_id"].startswith("SIM-")
    assert alert["mitre_techniques"]
    # Alert and its logs share the user → correlate_alerts can group them.
    assert alert["affected_user"] == P.email
    assert all(log["user"] == P.email for log in logs)


@pytest.mark.parametrize("name", ["impossible_travel", "data_exfiltration", "known_bad_ip"])
def test_network_scenarios_use_real_c2_ip(name):
    _, alert = SCENARIOS[name](P, IOCS, Random(0), NOW)
    assert alert["source_ip"] == "9.9.9.9"


def test_data_exfiltration_flags_large_transfer():
    logs, alert = SCENARIOS["data_exfiltration"](P, IOCS, Random(0), NOW)
    net = [log for log in logs if log["event_type"] == "network"]
    assert net
    assert net[0]["threat_intel_flagged"] is True
    assert net[0]["bytes_out"] >= 500_000_000


def test_brute_force_has_failed_then_success():
    logs, _ = SCENARIOS["brute_force"](P, IOCS, Random(0), NOW)
    failures = [log for log in logs if log["event_type"] == "auth" and not log["success"]]
    successes = [log for log in logs if log["event_type"] == "auth" and log["success"]]
    assert len(failures) >= 10
    assert len(successes) >= 1


def test_suspicious_process_marks_processes():
    logs, alert = SCENARIOS["suspicious_process"](P, IOCS, Random(0), NOW)
    assert all(log["suspicious"] for log in logs if log["event_type"] == "process")
    assert alert["affected_host"] == P.hostname
