"""OpenSearch adapter — SIEM log storage and search.

Wraps: get alert by ID, search logs, aggregate alerts.
Uses httpx directly against the OpenSearch REST API for consistent
mocking in tests (same pattern as all other adapters).

Security: queries are parameterised — user input never appears
in raw Lucene query strings. Only structured query DSL is used.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from opentelemetry import trace

from sentinel.adapters.base import BaseAdapter, CircuitOpenError
from sentinel.config import get_settings
from sentinel.tools import mock_data as mock

tracer = trace.get_tracer("sentinel.adapters.opensearch")


class OpenSearchAdapter(BaseAdapter):
    adapter_name = "opensearch"

    def __init__(self) -> None:
        super().__init__()
        settings = get_settings()
        self._base_url = settings.opensearch_url.rstrip("/")
        self._index_alerts = settings.opensearch_index_alerts
        self._index_logs = settings.opensearch_index_logs
        # Basic auth header if credentials configured
        self._headers: dict[str, str] = {"Content-Type": "application/json"}

    # ── Alert operations ──────────────────────────────────────────────────────

    async def get_alert(self, alert_id: str) -> dict[str, Any] | None:
        if self.is_mock:
            return mock.get_alert(alert_id)

        if self._breaker.is_open():
            raise CircuitOpenError(self.adapter_name)

        url = f"{self._base_url}/{self._index_alerts}/_doc/{alert_id}"
        with tracer.start_as_current_span("opensearch.get_alert") as span:
            span.set_attribute("alert.id", alert_id)
            try:
                resp = await self._retry_request("GET", url, headers=self._headers)
                if resp.status_code == 404:
                    await self._breaker.record_success()
                    return None
                resp.raise_for_status()
                await self._breaker.record_success()
                data = resp.json()
                return data.get("_source")
            except Exception as exc:
                await self._breaker.record_failure()
                self._log.warning("opensearch_get_alert_failed", error=str(exc), alert_id=alert_id)
                return None

    async def search_logs(
        self,
        query: str,
        time_window_hours: int = 24,
        max_results: int = 50,
    ) -> list[dict[str, Any]]:
        if self.is_mock:
            return mock.search_logs(query, time_window_hours, max_results)

        if self._breaker.is_open():
            raise CircuitOpenError(self.adapter_name)

        since = datetime.now(UTC) - timedelta(hours=time_window_hours)
        # Parameterised query — user input in `match` clause, never in raw Lucene
        body = {
            "size": min(max_results, 500),
            "query": {
                "bool": {
                    "must": [{"multi_match": {"query": query, "fields": ["*"]}}],
                    "filter": [{"range": {"@timestamp": {"gte": since.isoformat()}}}],
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
        }

        url = f"{self._base_url}/{self._index_logs}/_search"
        with tracer.start_as_current_span("opensearch.search_logs"):
            try:
                resp = await self._retry_request("POST", url, json=body, headers=self._headers)
                resp.raise_for_status()
                await self._breaker.record_success()
                hits = resp.json().get("hits", {}).get("hits", [])
                return [h["_source"] for h in hits]
            except Exception as exc:
                await self._breaker.record_failure()
                self._log.warning("opensearch_search_failed", error=str(exc))
                return []

    async def get_alerts(
        self,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        if self.is_mock:
            alerts = mock.list_active_alerts()
            return alerts[:limit]

        if self._breaker.is_open():
            raise CircuitOpenError(self.adapter_name)

        body: dict[str, Any] = {
            "size": min(limit, 1000),
            "sort": [{"timestamp": {"order": "desc"}}],
        }
        if status:
            body["query"] = {"term": {"status": status}}

        url = f"{self._base_url}/{self._index_alerts}/_search"
        with tracer.start_as_current_span("opensearch.get_alerts"):
            try:
                resp = await self._retry_request("POST", url, json=body, headers=self._headers)
                resp.raise_for_status()
                await self._breaker.record_success()
                hits = resp.json().get("hits", {}).get("hits", [])
                return [h["_source"] for h in hits]
            except Exception as exc:
                await self._breaker.record_failure()
                self._log.warning("opensearch_get_alerts_failed", error=str(exc))
                return []

    async def aggregate_alerts(
        self,
        time_window_hours: int = 168,
    ) -> dict[str, Any]:
        """Return aggregated alert stats for weekly_summary."""
        if self.is_mock:
            return {
                "total": 3,
                "by_severity": {"critical": 1, "high": 1, "medium": 1, "low": 0},
                "open": 2,
                "closed": 1,
            }

        since = datetime.now(UTC) - timedelta(hours=time_window_hours)
        body = {
            "size": 0,
            "track_total_hits": True,
            "query": {"range": {"timestamp": {"gte": since.isoformat()}}},
            "aggs": {
                "by_severity": {"terms": {"field": "severity.keyword"}},
                "by_status": {"terms": {"field": "status.keyword"}},
            },
        }
        url = f"{self._base_url}/{self._index_alerts}/_search"
        with tracer.start_as_current_span("opensearch.aggregate_alerts"):
            try:
                resp = await self._retry_request("POST", url, json=body, headers=self._headers)
                resp.raise_for_status()
                await self._breaker.record_success()
                return self._parse_aggregations(resp.json())
            except Exception as exc:
                await self._breaker.record_failure()
                self._log.warning("opensearch_aggregate_failed", error=str(exc))
                return {}

    @staticmethod
    def _parse_aggregations(body: dict[str, Any]) -> dict[str, Any]:
        """Normalise raw OpenSearch aggregation buckets into the weekly_summary
        contract — the SAME `{total, by_severity, open, closed}` shape the mock
        branch returns, so the tool behaves identically against a live backend."""
        aggs = body.get("aggregations", {})
        total = body.get("hits", {}).get("total", {})
        total_count = total.get("value", 0) if isinstance(total, dict) else int(total or 0)

        by_severity = {
            b["key"]: b["doc_count"] for b in aggs.get("by_severity", {}).get("buckets", [])
        }
        by_status = {b["key"]: b["doc_count"] for b in aggs.get("by_status", {}).get("buckets", [])}
        return {
            "total": total_count,
            "by_severity": by_severity,
            "open": by_status.get("open", 0),
            "closed": by_status.get("closed", 0),
            "raw_aggregations": aggs,
        }

    async def index_document(self, index: str, doc_id: str, document: dict[str, Any]) -> bool:
        """Write a document — used by the simulator."""
        if self.is_mock:
            return True

        url = f"{self._base_url}/{index}/_doc/{doc_id}"
        with tracer.start_as_current_span("opensearch.index_document"):
            try:
                resp = await self._retry_request("PUT", url, json=document, headers=self._headers)
                resp.raise_for_status()
                await self._breaker.record_success()
                return True
            except Exception as exc:
                await self._breaker.record_failure()
                self._log.warning("opensearch_index_failed", error=str(exc))
                return False


_adapter: OpenSearchAdapter | None = None


def get_opensearch_adapter() -> OpenSearchAdapter:
    global _adapter
    if _adapter is None:
        _adapter = OpenSearchAdapter()
    return _adapter
