"""Sink tests."""

from simulator.sink import InMemorySink, OpenSearchSink


class TestInMemorySink:
    async def test_collects_logs_and_alerts(self):
        sink = InMemorySink()
        await sink.write_log({"event_type": "auth"})
        await sink.write_alert({"alert_id": "SIM-1"})
        assert sink.logs == [{"event_type": "auth"}]
        assert sink.alerts == [{"alert_id": "SIM-1"}]


class TestOpenSearchSink:
    async def test_writes_via_adapter_in_mock_mode(self):
        # In mock mode index_document returns True without a real OpenSearch.
        sink = OpenSearchSink()
        await sink.write_log({"event_type": "auth", "message": "x"})
        await sink.write_alert({"alert_id": "SIM-42", "rule_name": "r"})
        # logs go to a concrete index that still matches the search read pattern
        # ("sentinel-logs-*"), so search_logs() can read what the simulator writes.
        from fnmatch import fnmatch

        from sentinel.config import get_settings

        assert "*" not in sink._logs_index
        assert fnmatch(sink._logs_index, get_settings().opensearch_index_logs)
