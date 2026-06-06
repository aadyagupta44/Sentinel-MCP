"""Unit tests for report tools (Phase 4 — orchestration + aggregation)."""


class TestGenerateIncidentReport:
    async def test_orchestrates_full_report(self):
        from sentinel.tools.reports import _execute_generate_incident_report

        result = await _execute_generate_incident_report({"alert_id": "ALT-2026-002"})
        assert result["report_id"] == "IR-ALT-2026-002"
        assert result["alert_id"] == "ALT-2026-002"
        assert result["severity"] == "critical"
        # Orchestrated sub-sections are all present
        assert "executive_summary" in result
        assert "affected_assets" in result
        assert "identity" in result
        assert "endpoint" in result
        assert "threat_intelligence" in result
        assert "mitre_attack" in result
        assert "similar_incidents" in result
        assert isinstance(result["recommended_actions"], list)
        assert result["recommended_actions"]
        # ALT-2026-002 has source_ip 185.220.101.34 (malicious) → enriched
        assert result["executive_summary"]["ioc_count"] >= 1
        assert result["executive_summary"]["malicious_ioc_count"] >= 1
        # MITRE technique T1078 mapped
        assert len(result["mitre_attack"]) >= 1
        # Narrative disabled by default in test env
        assert result["narrative_enabled"] is False

    async def test_unknown_alert_returns_not_found(self):
        from sentinel.tools.reports import _execute_generate_incident_report

        result = await _execute_generate_incident_report({"alert_id": "DOESNOTEXIST"})
        assert result["code"] == "NOT_FOUND"

    async def test_missing_alert_id_returns_error(self):
        from sentinel.tools.reports import _execute_generate_incident_report

        result = await _execute_generate_incident_report({"alert_id": ""})
        assert result["code"] == "MISSING_PARAMETER"

    async def test_report_for_host_based_alert_includes_endpoint(self):
        from sentinel.tools.reports import _execute_generate_incident_report

        # ALT-2026-001 has affected_host LAPTOP-HR-03
        result = await _execute_generate_incident_report({"alert_id": "ALT-2026-001"})
        assert result["endpoint"]["processes"]
        assert result["endpoint"]["suspicious_process_count"] >= 1


class TestWeeklySummary:
    async def test_returns_structured_summary(self):
        from sentinel.tools.reports import _execute_weekly_summary

        result = await _execute_weekly_summary({})
        assert result["period_days"] == 7
        assert "generated_at" in result
        assert "total_alerts" in result
        assert "by_severity" in result
        assert isinstance(result["top_risky_users"], list)
        assert isinstance(result["top_source_ips"], list)

    async def test_top_lists_are_ranked(self):
        from sentinel.tools.reports import _execute_weekly_summary

        result = await _execute_weekly_summary({})
        counts = [u["alert_count"] for u in result["top_risky_users"]]
        assert counts == sorted(counts, reverse=True)
