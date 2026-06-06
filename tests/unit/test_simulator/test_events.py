"""Event factory tests."""

from datetime import UTC, datetime
from random import Random

from simulator.events import (
    file_access_event,
    login_event,
    make_alert,
    network_event,
    process_event,
)
from simulator.profiles import PROFILES

NOW = datetime(2026, 6, 6, 12, 0, tzinfo=UTC)
P = PROFILES[0]


def test_login_event_defaults():
    e = login_event(P, Random(0), NOW)
    assert e["event_type"] == "auth"
    assert e["user"] == P.email
    assert e["ip"] == P.usual_ip
    assert e["success"] is True
    assert e["simulated"] is True


def test_login_event_foreign_failed():
    e = login_event(P, Random(0), NOW, success=False, ip="9.9.9.9", country="DE", mfa=False)
    assert e["success"] is False
    assert e["ip"] == "9.9.9.9"
    assert e["mfa_method"] is None


def test_file_access_event():
    e = file_access_event(P, Random(0), NOW)
    assert e["event_type"] == "file_access"
    assert e["host"] == P.hostname
    assert e["path"]


def test_process_event_benign_and_suspicious():
    benign = process_event(P, Random(0), NOW)
    assert benign["event_type"] == "process"
    assert benign["suspicious"] is False
    bad = process_event(P, Random(0), NOW, name="mimikatz.exe", command="mimikatz", suspicious=True)
    assert bad["suspicious"] is True
    assert bad["process"] == "mimikatz.exe"


def test_network_event():
    e = network_event(P, Random(0), NOW, dst_ip="9.9.9.9", bytes_out=1234, flagged=True)
    assert e["dst_ip"] == "9.9.9.9"
    assert e["threat_intel_flagged"] is True
    assert e["bytes_out"] == 1234


def test_make_alert_schema():
    a = make_alert(
        Random(0),
        NOW,
        profile=P,
        rule_name="Test Rule",
        severity="high",
        mitre_techniques=["T1078"],
        description="d",
        source_ip="9.9.9.9",
        affected_host=P.hostname,
    )
    assert a["alert_id"].startswith("SIM-")
    assert a["affected_user"] == P.email
    assert a["source_ip"] == "9.9.9.9"
    assert a["status"] == "open"
    assert a["mitre_techniques"] == ["T1078"]
