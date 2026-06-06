"""Unit tests for alert tools."""

from unittest.mock import AsyncMock, patch

import pytest


class TestGetAlert:
    async def test_known_alert_returns_full_object(self):
        from sentinel.tools.alerts import _execute_get_alert

        result = await _execute_get_alert({"alert_id": "ALT-2026-001"})
        assert result["alert_id"] == "ALT-2026-001"
        assert result["severity"] == "high"
        assert "mitre_techniques" in result
        assert "affected_user" in result
        assert "affected_host" in result

    async def test_unknown_alert_returns_not_found(self):
        from sentinel.tools.alerts import _execute_get_alert

        result = await _execute_get_alert({"alert_id": "DOESNOTEXIST"})
        assert result["code"] == "NOT_FOUND"
        assert "error" in result

    async def test_empty_alert_id_returns_error(self):
        from sentinel.tools.alerts import _execute_get_alert

        result = await _execute_get_alert({"alert_id": ""})
        assert result["code"] == "MISSING_PARAMETER"

    async def test_alert_goes_through_middleware(self):
        from sentinel.tools.alerts import get_alert

        with (
            patch("sentinel.mcp.middleware.write_audit_log", new_callable=AsyncMock),
            patch("sentinel.mcp.middleware._get_rate_count", new=AsyncMock(return_value=0)),
            patch("sentinel.mcp.middleware.get_opa_engine") as mock_opa,
        ):
            mock_opa.return_value.is_allowed = AsyncMock(return_value=(True, "policy_allow"))
            mock_opa.return_value.check_rate_limit = AsyncMock(return_value=(True, "ok"))
            result = await get_alert("ALT-2026-001")

        assert result["alert_id"] == "ALT-2026-001"

    async def test_all_three_alerts_accessible(self):
        from sentinel.tools.alerts import _execute_get_alert

        for alert_id in ["ALT-2026-001", "ALT-2026-002", "ALT-2026-003"]:
            result = await _execute_get_alert({"alert_id": alert_id})
            assert "alert_id" in result
            assert result.get("code") != "NOT_FOUND"


class TestSearchLogs:
    async def test_returns_stub(self):
        from sentinel.tools.alerts import _execute_search_logs

        result = await _execute_search_logs({"query": "mimikatz", "time_window_hours": 24})
        assert result["status"] == "not_yet_implemented"
        assert result["query"] == "mimikatz"
