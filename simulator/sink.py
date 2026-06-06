"""Event sinks — where generated events go.

OpenSearchSink writes through the existing OpenSearch adapter (logs → the logs
index, alerts → the alerts index) so the Sentinel tools can query them.
InMemorySink collects events for tests and dry runs.
"""

from typing import Any, Protocol

import structlog

logger = structlog.get_logger("simulator.sink")


class EventSink(Protocol):
    async def write_log(self, doc: dict[str, Any]) -> None: ...
    async def write_alert(self, alert: dict[str, Any]) -> None: ...


class InMemorySink:
    """Collects events in memory — used for tests and `--dry-run`."""

    def __init__(self) -> None:
        self.logs: list[dict[str, Any]] = []
        self.alerts: list[dict[str, Any]] = []

    async def write_log(self, doc: dict[str, Any]) -> None:
        self.logs.append(doc)

    async def write_alert(self, alert: dict[str, Any]) -> None:
        self.alerts.append(alert)


class OpenSearchSink:
    """Writes events to OpenSearch via the Sentinel adapter."""

    def __init__(self) -> None:
        from sentinel.adapters.opensearch import get_opensearch_adapter
        from sentinel.config import get_settings

        s = get_settings()
        self._adapter = get_opensearch_adapter()
        # opensearch_index_logs is a read PATTERN ("sentinel-logs-*"). Write to a concrete
        # index that still MATCHES that wildcard so search_logs() can read what we write
        # ("sentinel-logs-*" → "sentinel-logs-sim").
        pattern = s.opensearch_index_logs
        self._logs_index = pattern.replace("*", "sim") if "*" in pattern else pattern
        self._alerts_index = s.opensearch_index_alerts
        self._seq = 0

    async def write_log(self, doc: dict[str, Any]) -> None:
        self._seq += 1
        await self._adapter.index_document(self._logs_index, f"sim-log-{self._seq}", doc)

    async def write_alert(self, alert: dict[str, Any]) -> None:
        await self._adapter.index_document(self._alerts_index, alert["alert_id"], alert)
