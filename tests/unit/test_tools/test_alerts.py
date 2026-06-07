"""Unit tests for alert tools."""

from unittest.mock import AsyncMock, patch


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
    async def test_returns_matching_results(self):
        from sentinel.tools.alerts import _execute_search_logs

        result = await _execute_search_logs({"query": "mimikatz", "time_window_hours": 168})
        assert result["query"] == "mimikatz"
        assert result["total_hits"] == len(result["results"])
        assert result["total_hits"] >= 1
        assert all("mimikatz" in str(r).lower() for r in result["results"])

    async def test_empty_query_returns_error(self):
        from sentinel.tools.alerts import _execute_search_logs

        result = await _execute_search_logs({"query": "  "})
        assert result["code"] == "MISSING_PARAMETER"

    async def test_window_and_max_are_capped(self):
        from sentinel.tools.alerts import _execute_search_logs

        result = await _execute_search_logs(
            {"query": "login", "time_window_hours": 9999, "max_results": 9999}
        )
        assert result["time_window_hours"] <= 168

    async def test_no_match_returns_empty(self):
        from sentinel.tools.alerts import _execute_search_logs

        result = await _execute_search_logs(
            {"query": "zzz-no-such-token", "time_window_hours": 168}
        )
        assert result["total_hits"] == 0
        assert result["results"] == []

    async def test_short_common_substring_does_not_match_everything(self):
        # Token-aware matching: a 1-char query is not a whole token → no spurious hits.
        from sentinel.tools.alerts import _execute_search_logs

        result = await _execute_search_logs({"query": "a", "time_window_hours": 168})
        assert result["total_hits"] == 0


class TestCorrelateAlerts:
    async def test_returns_clusters_covering_all_alerts(self):
        from sentinel.tools.alerts import _execute_correlate_alerts

        result = await _execute_correlate_alerts({"time_window_hours": 24})
        assert "clusters" in result
        assert result["cluster_count"] == len(result["clusters"])
        clustered = sum(c["alert_count"] for c in result["clusters"])
        assert clustered == result["total_alerts"]
        for c in result["clusters"]:
            assert c["cluster_id"].startswith("CL-")
            assert "summary" in c

    async def test_window_is_capped(self):
        from sentinel.tools.alerts import _execute_correlate_alerts

        result = await _execute_correlate_alerts({"time_window_hours": 99999})
        assert result["time_window_hours"] <= 720

    async def test_overlapping_alerts_merge_into_one_cluster(self, monkeypatch):
        from sentinel.adapters.opensearch import get_opensearch_adapter
        from sentinel.tools import alerts

        pool = [
            {
                "alert_id": "A1",
                "affected_user": "u@x.com",
                "affected_host": "H1",
                "source_ip": "1.1.1.1",
                "mitre_techniques": ["T1059.001"],
            },
            {
                "alert_id": "A2",
                "affected_user": "u@x.com",
                "affected_host": None,
                "source_ip": None,
                "mitre_techniques": ["T1078"],
            },  # shares user with A1
            {
                "alert_id": "A3",
                "affected_user": "other@x.com",
                "affected_host": None,
                "source_ip": "9.9.9.9",
                "mitre_techniques": ["T1059.001"],
            },  # shares technique with A1
            {
                "alert_id": "A4",
                "affected_user": "loner@x.com",
                "affected_host": "H9",
                "source_ip": "2.2.2.2",
                "mitre_techniques": ["T9999"],
            },  # no overlap
        ]
        monkeypatch.setattr(get_opensearch_adapter(), "get_alerts", AsyncMock(return_value=pool))

        result = await alerts._execute_correlate_alerts({})
        assert result["total_alerts"] == 4
        # A1+A2+A3 collapse into one cluster; A4 stands alone
        big = max(result["clusters"], key=lambda c: c["alert_count"])
        assert big["alert_count"] == 3
        assert set(big["alert_ids"]) == {"A1", "A2", "A3"}
        assert {"user", "mitre_technique"} <= set(big["shared_factors"])
        assert result["correlated_cluster_count"] == 1


class TestSimilarIncidents:
    async def test_ranks_candidates(self):
        from sentinel.tools.alerts import _execute_similar_incidents

        result = await _execute_similar_incidents({"alert_id": "ALT-2026-001", "limit": 5})
        assert result["alert_id"] == "ALT-2026-001"
        assert isinstance(result["similar"], list)
        # target itself is excluded
        assert all(s["alert_id"] != "ALT-2026-001" for s in result["similar"])
        # results are sorted by similarity descending
        scores = [s["similarity_score"] for s in result["similar"]]
        assert scores == sorted(scores, reverse=True)

    async def test_unknown_alert_returns_not_found(self):
        from sentinel.tools.alerts import _execute_similar_incidents

        result = await _execute_similar_incidents({"alert_id": "NOPE", "limit": 5})
        assert result["code"] == "NOT_FOUND"

    async def test_empty_alert_id_returns_error(self):
        from sentinel.tools.alerts import _execute_similar_incidents

        result = await _execute_similar_incidents({"alert_id": ""})
        assert result["code"] == "MISSING_PARAMETER"

    async def test_similarity_scoring_covers_all_factors(self, monkeypatch):
        from sentinel.adapters.opensearch import get_opensearch_adapter
        from sentinel.tools import alerts

        target = {
            "alert_id": "T",
            "rule_name": "Rule X",
            "severity": "high",
            "affected_user": "u@x.com",
            "mitre_techniques": ["T1059.001"],
        }
        pool = [
            target,
            {
                "alert_id": "FULL",
                "rule_name": "Rule X",
                "severity": "high",
                "affected_user": "u@x.com",
                "mitre_techniques": ["T1059.001"],
            },  # every factor
            {
                "alert_id": "TECH",
                "rule_name": "Other",
                "severity": "low",
                "affected_user": "z@x.com",
                "mitre_techniques": ["T1059.001"],
            },  # technique only
            {
                "alert_id": "NONE",
                "rule_name": "Other",
                "severity": "low",
                "affected_user": "z@x.com",
                "mitre_techniques": ["T9999"],
            },  # nothing → excluded
        ]
        adapter = get_opensearch_adapter()
        monkeypatch.setattr(adapter, "get_alert", AsyncMock(return_value=target))
        monkeypatch.setattr(adapter, "get_alerts", AsyncMock(return_value=pool))

        result = await alerts._execute_similar_incidents({"alert_id": "T", "limit": 5})
        ids = [s["alert_id"] for s in result["similar"]]
        assert ids[0] == "FULL"  # highest score ranks first
        assert "NONE" not in ids  # zero-similarity excluded
        full = result["similar"][0]
        assert {"same_rule", "same_severity", "same_user"} <= set(full["shared_factors"])
