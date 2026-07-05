"""OpenSearch adapter tests — respx-mocked, no real network.

Contract covered for the live HTTP path:
  1. success path returns the correct structure
  2. transport error triggers retry (3 attempts) then degrades gracefully
  3. circuit breaker opens after 5 failures
Plus the mock-mode branches and 404 handling for full coverage.

Uses the ``respx_mock`` fixture (assert_all_called=False) so unused routes
never fail a test.
"""

import pytest
from httpx import ConnectError, Response

from sentinel.adapters.base import CircuitOpenError
from sentinel.adapters.opensearch import OpenSearchAdapter, get_opensearch_adapter

ALERTS_URL = "http://localhost:9200/sentinel-alerts"
LOGS_SEARCH = "http://localhost:9200/sentinel-logs-*/_search"
ALERTS_SEARCH = "http://localhost:9200/sentinel-alerts/_search"


# ── Mock mode (suite default) ─────────────────────────────────────────────────


class TestOpenSearchMockMode:
    async def test_get_alert_returns_mock(self):
        adapter = OpenSearchAdapter()
        result = await adapter.get_alert("ALT-2026-001")
        assert result is not None
        assert result["alert_id"] == "ALT-2026-001"
        await adapter.close()

    async def test_search_logs_returns_mock_corpus(self):
        adapter = OpenSearchAdapter()
        # A matching query returns events from the deterministic mock corpus...
        hits = await adapter.search_logs("powershell", time_window_hours=168)
        assert isinstance(hits, list)
        assert hits
        assert all("powershell" in str(h).lower() for h in hits)
        # ...and a non-matching query returns nothing.
        assert await adapter.search_logs("zzz-no-such-token", time_window_hours=168) == []
        await adapter.close()

    async def test_get_alerts_returns_mock_list_capped(self):
        adapter = OpenSearchAdapter()
        result = await adapter.get_alerts(limit=1)
        assert isinstance(result, list)
        assert len(result) <= 1
        await adapter.close()

    async def test_aggregate_alerts_returns_mock_stats(self):
        adapter = OpenSearchAdapter()
        result = await adapter.aggregate_alerts()
        assert result["total"] == 3
        assert "by_severity" in result
        await adapter.close()

    async def test_index_document_returns_true_in_mock(self):
        adapter = OpenSearchAdapter()
        assert await adapter.index_document("idx", "1", {"a": 1}) is True
        await adapter.close()


# ── Live HTTP path: success ───────────────────────────────────────────────────


class TestOpenSearchSuccess:
    async def test_get_alert_success(self, respx_mock, live_mode):
        respx_mock.get(f"{ALERTS_URL}/_doc/ALT-1").mock(
            return_value=Response(200, json={"_source": {"alert_id": "ALT-1", "severity": "high"}})
        )
        adapter = OpenSearchAdapter()
        result = await adapter.get_alert("ALT-1")
        assert result == {"alert_id": "ALT-1", "severity": "high"}
        await adapter.close()

    async def test_get_alert_404_returns_none(self, respx_mock, live_mode):
        respx_mock.get(f"{ALERTS_URL}/_doc/missing").mock(return_value=Response(404, json={}))
        adapter = OpenSearchAdapter()
        assert await adapter.get_alert("missing") is None
        await adapter.close()

    async def test_search_logs_success(self, respx_mock, live_mode):
        respx_mock.post(LOGS_SEARCH).mock(
            return_value=Response(200, json={"hits": {"hits": [{"_source": {"msg": "x"}}]}})
        )
        adapter = OpenSearchAdapter()
        result = await adapter.search_logs("x", time_window_hours=1, max_results=5)
        assert result == [{"msg": "x"}]
        await adapter.close()

    async def test_get_alerts_success_with_status_filter(self, respx_mock, live_mode):
        respx_mock.post(ALERTS_SEARCH).mock(
            return_value=Response(200, json={"hits": {"hits": [{"_source": {"alert_id": "A1"}}]}})
        )
        adapter = OpenSearchAdapter()
        result = await adapter.get_alerts(status="open", limit=10)
        assert result == [{"alert_id": "A1"}]
        await adapter.close()

    async def test_get_alerts_time_window_adds_range_filter(self, respx_mock, live_mode):
        # weekly_summary bounds its per-alert breakdown to the same 7-day window
        # as the aggregate — assert the range filter actually lands in the query.
        route = respx_mock.post(ALERTS_SEARCH).mock(
            return_value=Response(200, json={"hits": {"hits": []}})
        )
        adapter = OpenSearchAdapter()
        await adapter.get_alerts(limit=500, time_window_hours=168)
        import json as _json

        body = _json.loads(route.calls.last.request.content)
        filters = body["query"]["bool"]["filter"]
        assert any("range" in f and "timestamp" in f["range"] for f in filters)
        await adapter.close()

    async def test_get_alerts_no_window_has_no_query(self, respx_mock, live_mode):
        # An unconstrained call must match all alerts (no bool query at all).
        route = respx_mock.post(ALERTS_SEARCH).mock(
            return_value=Response(200, json={"hits": {"hits": []}})
        )
        adapter = OpenSearchAdapter()
        await adapter.get_alerts(limit=10)
        import json as _json

        body = _json.loads(route.calls.last.request.content)
        assert "query" not in body
        await adapter.close()

    async def test_aggregate_alerts_success_returns_weekly_contract(self, respx_mock, live_mode):
        # The live branch must return the SAME {total, by_severity, open, closed}
        # contract weekly_summary consumes (not raw agg buckets).
        respx_mock.post(ALERTS_SEARCH).mock(
            return_value=Response(
                200,
                json={
                    "hits": {"total": {"value": 7}},
                    "aggregations": {
                        "by_severity": {
                            "buckets": [
                                {"key": "high", "doc_count": 4},
                                {"key": "low", "doc_count": 3},
                            ]
                        },
                        "by_status": {
                            "buckets": [
                                {"key": "open", "doc_count": 5},
                                {"key": "closed", "doc_count": 2},
                            ]
                        },
                    },
                },
            )
        )
        adapter = OpenSearchAdapter()
        result = await adapter.aggregate_alerts(time_window_hours=24)
        assert result["total"] == 7
        assert result["by_severity"] == {"high": 4, "low": 3}
        assert result["open"] == 5
        assert result["closed"] == 2
        await adapter.close()

    async def test_index_document_success(self, respx_mock, live_mode):
        respx_mock.put("http://localhost:9200/myidx/_doc/1").mock(
            return_value=Response(201, json={})
        )
        adapter = OpenSearchAdapter()
        assert await adapter.index_document("myidx", "1", {"k": "v"}) is True
        await adapter.close()


# ── Live HTTP path: transport error → retry → graceful degradation ────────────


class TestOpenSearchGracefulDegradation:
    async def test_get_alert_retries_then_returns_none(self, respx_mock, live_mode):
        route = respx_mock.get(f"{ALERTS_URL}/_doc/ALT-1").mock(side_effect=ConnectError("boom"))
        adapter = OpenSearchAdapter()
        result = await adapter.get_alert("ALT-1")
        assert result is None
        assert route.call_count == 3  # tenacity retried 3 times before giving up
        await adapter.close()

    async def test_search_logs_error_returns_empty(self, respx_mock, live_mode):
        respx_mock.post(LOGS_SEARCH).mock(side_effect=ConnectError("boom"))
        adapter = OpenSearchAdapter()
        assert await adapter.search_logs("x") == []
        await adapter.close()

    async def test_get_alerts_error_returns_empty(self, respx_mock, live_mode):
        respx_mock.post(ALERTS_SEARCH).mock(side_effect=ConnectError("boom"))
        adapter = OpenSearchAdapter()
        assert await adapter.get_alerts() == []
        await adapter.close()

    async def test_aggregate_alerts_error_returns_empty(self, respx_mock, live_mode):
        respx_mock.post(ALERTS_SEARCH).mock(side_effect=ConnectError("boom"))
        adapter = OpenSearchAdapter()
        assert await adapter.aggregate_alerts() == {}
        await adapter.close()

    async def test_index_document_error_returns_false(self, respx_mock, live_mode):
        respx_mock.put("http://localhost:9200/myidx/_doc/1").mock(side_effect=ConnectError("boom"))
        adapter = OpenSearchAdapter()
        assert await adapter.index_document("myidx", "1", {"k": "v"}) is False
        await adapter.close()

    async def test_500_status_returns_graceful(self, respx_mock, live_mode):
        respx_mock.get(f"{ALERTS_URL}/_doc/ALT-1").mock(return_value=Response(500, json={}))
        adapter = OpenSearchAdapter()
        assert await adapter.get_alert("ALT-1") is None
        await adapter.close()


# ── Live HTTP path: circuit breaker ───────────────────────────────────────────


class TestOpenSearchCircuitBreaker:
    async def test_circuit_opens_after_five_failures(self, respx_mock, live_mode):
        respx_mock.get(f"{ALERTS_URL}/_doc/ALT-1").mock(side_effect=ConnectError("down"))
        adapter = OpenSearchAdapter()

        for _ in range(5):
            assert await adapter.get_alert("ALT-1") is None

        assert adapter._breaker.is_open()
        with pytest.raises(CircuitOpenError):
            await adapter.get_alert("ALT-1")
        await adapter.close()

    async def test_search_logs_raises_when_circuit_open(self, live_mode):
        adapter = OpenSearchAdapter()
        for _ in range(5):
            await adapter._breaker.record_failure()
        with pytest.raises(CircuitOpenError):
            await adapter.search_logs("x")
        await adapter.close()

    async def test_get_alerts_raises_when_circuit_open(self, live_mode):
        adapter = OpenSearchAdapter()
        for _ in range(5):
            await adapter._breaker.record_failure()
        with pytest.raises(CircuitOpenError):
            await adapter.get_alerts()
        await adapter.close()

    async def test_aggregate_alerts_raises_when_circuit_open(self, live_mode):
        adapter = OpenSearchAdapter()
        for _ in range(5):
            await adapter._breaker.record_failure()
        with pytest.raises(CircuitOpenError):
            await adapter.aggregate_alerts()
        await adapter.close()


# ── Singleton accessor ────────────────────────────────────────────────────────


def test_get_opensearch_adapter_is_singleton():
    a = get_opensearch_adapter()
    b = get_opensearch_adapter()
    assert a is b
