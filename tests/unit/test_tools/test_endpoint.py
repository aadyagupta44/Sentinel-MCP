"""Unit tests for endpoint forensics tools."""



class TestDeviceProcesses:
    async def test_returns_process_list(self):
        from sentinel.tools.endpoint import _execute_device_processes

        result = await _execute_device_processes(
            {"hostname": "LAPTOP-HR-03", "time_window_minutes": 60}
        )
        assert result["hostname"] == "LAPTOP-HR-03"
        assert isinstance(result["processes"], list)
        assert result["total_processes"] == len(result["processes"])

    async def test_suspicious_count_matches(self):
        from sentinel.tools.endpoint import _execute_device_processes

        result = await _execute_device_processes(
            {"hostname": "LAPTOP-HR-03", "time_window_minutes": 30}
        )
        suspicious = sum(1 for p in result["processes"] if p.get("suspicious"))
        assert result["suspicious_count"] == suspicious

    async def test_empty_hostname_returns_error(self):
        from sentinel.tools.endpoint import _execute_device_processes

        result = await _execute_device_processes({"hostname": "", "time_window_minutes": 60})
        assert result["code"] == "MISSING_PARAMETER"

    async def test_window_is_capped(self):
        from sentinel.tools.endpoint import _execute_device_processes

        result = await _execute_device_processes(
            {"hostname": "HOST-001", "time_window_minutes": 99999}
        )
        assert result["time_window_minutes"] <= 1440


class TestNetworkConnections:
    async def test_returns_connection_list(self):
        from sentinel.tools.endpoint import _execute_network_connections

        result = await _execute_network_connections(
            {"hostname": "LAPTOP-HR-03", "time_window_minutes": 60}
        )
        assert result["hostname"] == "LAPTOP-HR-03"
        assert isinstance(result["connections"], list)

    async def test_threat_intel_flagged_count(self):
        from sentinel.tools.endpoint import _execute_network_connections

        result = await _execute_network_connections(
            {"hostname": "LAPTOP-HR-03", "time_window_minutes": 60}
        )
        flagged = sum(1 for c in result["connections"] if c.get("threat_intel_flagged"))
        assert result["threat_intel_flagged"] == flagged

    async def test_empty_hostname_returns_error(self):
        from sentinel.tools.endpoint import _execute_network_connections

        result = await _execute_network_connections({"hostname": "", "time_window_minutes": 60})
        assert result["code"] == "MISSING_PARAMETER"
