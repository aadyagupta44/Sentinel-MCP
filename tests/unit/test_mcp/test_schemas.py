"""Schema model instantiation tests — ensures every model is importable
and correctly validates its required fields."""

import pytest
from pydantic import ValidationError

from sentinel.mcp.schemas import (
    AlertSummary,
    CircuitOpen,
    ConfirmedAction,
    EnrichmentVerdict,
    LoginEvent,
    PolicyDenied,
    ProposedAction,
    RateLimitExceeded,
    ToolError,
)


class TestErrorModels:
    def test_tool_error_minimal(self):
        e = ToolError(error="something broke", code="INTERNAL_ERROR")
        assert e.error == "something broke"
        assert e.code == "INTERNAL_ERROR"
        assert e.details == {}

    def test_tool_error_with_details(self):
        e = ToolError(error="bad input", code="VALIDATION_ERROR", details={"field": "alert_id"})
        assert e.details["field"] == "alert_id"

    def test_policy_denied_defaults(self):
        p = PolicyDenied(tool="isolate_device", reason="write_tools_require_senior_analyst")
        assert p.error == "Access denied by policy"
        assert p.code == "POLICY_DENIED"
        assert p.tool == "isolate_device"

    def test_rate_limit_exceeded_defaults(self):
        r = RateLimitExceeded(tool="enrich_ioc")
        assert r.code == "RATE_LIMIT_EXCEEDED"
        assert r.retry_after_seconds == 60

    def test_circuit_open(self):
        c = CircuitOpen(service="virustotal")
        assert c.code == "CIRCUIT_OPEN"
        assert c.service == "virustotal"


class TestProposedAction:
    def test_proposed_action_full(self):
        p = ProposedAction(
            action_type="isolate_device",
            description="Isolate LAPTOP-001 from the network",
            target="LAPTOP-001",
            parameters={"hostname": "LAPTOP-001", "reason": "malware detected"},
            warning="This will cut all network access immediately.",
            confirmation_token="tok-abc123",
            expires_at="2026-06-02T10:10:00Z",
        )
        assert p.action_type == "isolate_device"
        assert p.confirmation_token == "tok-abc123"
        assert "Call this tool again" in p.instructions

    def test_proposed_action_missing_required_field(self):
        with pytest.raises(ValidationError):
            ProposedAction(
                action_type="isolate_device",
                # missing description, target, parameters, warning, token, expires_at
            )


class TestConfirmedAction:
    def test_confirmed_action(self):
        c = ConfirmedAction(
            action_type="block_ip",
            target="185.220.101.34",
            executed_at="2026-06-02T10:01:00Z",
            analyst_id="alice@acmecorp.com",
            trace_id="trace-xyz",
            result={"status": "blocked"},
        )
        assert c.action_type == "block_ip"
        assert c.result["status"] == "blocked"


class TestEnrichmentVerdict:
    def test_malicious_verdict(self):
        v = EnrichmentVerdict(
            verdict="malicious",
            confidence=0.97,
            sources_checked=["virustotal", "abuseipdb", "feodotracker"],
            sources_hit=["virustotal", "feodotracker"],
        )
        assert v.verdict == "malicious"
        assert v.confidence == 0.97

    def test_confidence_out_of_range(self):
        with pytest.raises(ValidationError):
            EnrichmentVerdict(
                verdict="clean",
                confidence=1.5,  # > 1.0
                sources_checked=[],
                sources_hit=[],
            )

    def test_invalid_verdict(self):
        with pytest.raises(ValidationError):
            EnrichmentVerdict(
                verdict="definitely_evil",  # not in Literal
                confidence=0.5,
                sources_checked=[],
                sources_hit=[],
            )


class TestAlertSummary:
    def test_alert_summary_with_nulls(self):
        a = AlertSummary(
            alert_id="ALT-001",
            severity="high",
            rule_name="Suspicious PowerShell",
            affected_host=None,
            affected_user=None,
            timestamp="2026-06-02T08:00:00Z",
            status="open",
        )
        assert a.affected_host is None
        assert a.raw_log_references == []

    def test_alert_summary_full(self):
        a = AlertSummary(
            alert_id="ALT-002",
            severity="critical",
            rule_name="Impossible Travel",
            affected_host="LAPTOP-001",
            affected_user="alice@corp.com",
            timestamp="2026-06-02T09:00:00Z",
            status="investigating",
            raw_log_references=["log-001", "log-002"],
        )
        assert len(a.raw_log_references) == 2


class TestLoginEvent:
    def test_login_event_with_mfa(self):
        e = LoginEvent(
            timestamp="2026-06-02T07:00:00Z",
            ip_address="103.21.48.10",
            country="IN",
            device="MacBook-Alice",
            success=True,
            mfa_method="TOTP",
        )
        assert e.success is True
        assert e.mfa_method == "TOTP"

    def test_login_event_no_mfa(self):
        e = LoginEvent(
            timestamp="2026-06-02T07:00:00Z",
            ip_address="10.0.0.1",
            country="US",
            device="Chrome",
            success=False,
            mfa_method=None,
        )
        assert e.mfa_method is None
