"""Unit tests for report tools."""

import pytest


class TestGenerateIncidentReport:
    async def test_returns_stub_with_alert_id(self):
        from sentinel.tools.reports import _execute_generate_incident_report

        result = await _execute_generate_incident_report({"alert_id": "ALT-2026-001"})
        assert result["status"] == "not_yet_implemented"
        assert result["alert_id"] == "ALT-2026-001"


class TestWeeklySummary:
    async def test_returns_stub(self):
        from sentinel.tools.reports import _execute_weekly_summary

        result = await _execute_weekly_summary({})
        assert result["status"] == "not_yet_implemented"
        assert "phase" in result
