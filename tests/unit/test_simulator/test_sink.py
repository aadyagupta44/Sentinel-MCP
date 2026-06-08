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
        # Logs go to an isolated simulator index to prevent test data from polluting
        # production queries. The test suite uses this; production should use a
        # separate OpenSearch instance for testing.
        assert sink._logs_index == "sentinel-simulator-logs"
        assert sink._alerts_index == "sentinel-simulator-alerts"
