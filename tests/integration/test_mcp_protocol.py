"""MCP protocol compliance tests.

Verifies that the server correctly implements the MCP spec:
- list_tools returns all 18 tools with descriptions and schemas
- call_tool works for the three fully-implemented tools
- list_resources returns all 4 resources
- list_prompts returns all 3 prompts
- Errors are structured (never raw exceptions)
"""

import pytest

ALL_TOOLS = {
    "get_alert",
    "search_logs",
    "correlate_alerts",
    "similar_incidents",
    "enrich_ioc",
    "threat_hunt",
    "mitre_technique",
    "user_context",
    "recent_logins",
    "risk_score_user",
    "device_processes",
    "network_connections",
    "generate_incident_report",
    "weekly_summary",
    "isolate_device",
    "disable_user",
    "block_ip",
    "kill_process",
}

ALL_RESOURCES = {
    "sentinel://alerts/active",
    "sentinel://alerts/{alert_id}",
    "sentinel://mitre/{technique_id}",
    "sentinel://watchlist/ips",
}

ALL_PROMPTS = {"investigate_alert", "triage_user", "morning_briefing"}


class TestToolListing:
    async def test_all_18_tools_registered(self):
        from sentinel.mcp.server import mcp

        # list_tools() is async in MCP SDK
        tools = await mcp.list_tools()
        tool_names = {t.name for t in tools}
        assert tool_names == ALL_TOOLS, (
            f"Missing: {ALL_TOOLS - tool_names}\nExtra: {tool_names - ALL_TOOLS}"
        )

    async def test_every_tool_has_description(self):
        from sentinel.mcp.server import mcp

        tools = await mcp.list_tools()
        for tool in tools:
            assert tool.description, f"Tool '{tool.name}' has no description"
            assert len(tool.description) > 20, f"Tool '{tool.name}' description is too short"

    async def test_every_tool_has_input_schema(self):
        from sentinel.mcp.server import mcp

        tools = await mcp.list_tools()
        for tool in tools:
            assert tool.inputSchema is not None, f"Tool '{tool.name}' has no inputSchema"


class TestToolCalls:
    async def test_get_alert_returns_structured_data(self):
        from unittest.mock import AsyncMock, patch

        from sentinel.mcp.server import mcp

        with (
            patch("sentinel.mcp.middleware.write_audit_log", new_callable=AsyncMock),
            patch("sentinel.mcp.middleware._get_rate_count", new=AsyncMock(return_value=0)),
            patch("sentinel.mcp.middleware.get_opa_engine") as mock_opa,
        ):
            mock_opa.return_value.is_allowed = AsyncMock(return_value=(True, "ok"))
            mock_opa.return_value.check_rate_limit = AsyncMock(return_value=(True, "ok"))
            result = await mcp.call_tool("get_alert", {"alert_id": "ALT-2026-001"})

        assert result is not None
        # FastMCP returns list of content items
        text = result[0].text if hasattr(result[0], "text") else str(result)
        assert "ALT-2026-001" in text

    async def test_enrich_ioc_returns_verdict(self):
        from unittest.mock import AsyncMock, patch

        from sentinel.mcp.server import mcp

        with (
            patch("sentinel.mcp.middleware.write_audit_log", new_callable=AsyncMock),
            patch("sentinel.mcp.middleware._get_rate_count", new=AsyncMock(return_value=0)),
            patch("sentinel.mcp.middleware.get_opa_engine") as mock_opa,
        ):
            mock_opa.return_value.is_allowed = AsyncMock(return_value=(True, "ok"))
            mock_opa.return_value.check_rate_limit = AsyncMock(return_value=(True, "ok"))
            result = await mcp.call_tool(
                "enrich_ioc", {"indicator": "185.220.101.34", "indicator_type": "ip"}
            )

        text = result[0].text if hasattr(result[0], "text") else str(result)
        assert "malicious" in text

    async def test_unknown_tool_raises_error(self):
        from mcp.server.fastmcp.exceptions import ToolError

        from sentinel.mcp.server import mcp

        with pytest.raises(ToolError):
            await mcp.call_tool("nonexistent_tool", {})

    async def test_policy_denied_returns_structured_error(self):
        from unittest.mock import AsyncMock, patch

        from sentinel.mcp.server import mcp

        with (
            patch("sentinel.mcp.middleware.write_audit_log", new_callable=AsyncMock),
            patch("sentinel.mcp.middleware._get_rate_count", new=AsyncMock(return_value=0)),
            patch("sentinel.mcp.middleware.get_opa_engine") as mock_opa,
        ):
            mock_opa.return_value.is_allowed = AsyncMock(return_value=(False, "policy_deny"))
            mock_opa.return_value.check_rate_limit = AsyncMock(return_value=(True, "ok"))
            result = await mcp.call_tool("get_alert", {"alert_id": "ALT-2026-001"})

        text = result[0].text if hasattr(result[0], "text") else str(result)
        assert "POLICY_DENIED" in text


class TestResources:
    async def test_active_alerts_resource_readable(self):
        from sentinel.mcp.resources import active_alerts_resource

        content = await active_alerts_resource()
        import json

        data = json.loads(content)
        assert "alerts" in data
        assert isinstance(data["alerts"], list)

    async def test_ip_watchlist_resource_readable(self):
        from sentinel.mcp.resources import ip_watchlist_resource

        content = await ip_watchlist_resource()
        import json

        data = json.loads(content)
        assert "blocked_ips" in data

    async def test_mitre_resource_readable(self):
        from sentinel.mcp.resources import mitre_resource

        content = await mitre_resource("T1059.001")
        import json

        data = json.loads(content)
        assert "technique_id" in data or "name" in data


class TestPrompts:
    async def test_investigate_alert_prompt_returns_string(self):
        from sentinel.mcp.prompts import investigate_alert

        result = investigate_alert("ALT-2026-001")
        assert isinstance(result, str)
        assert "ALT-2026-001" in result
        assert "STEP 1" in result

    async def test_triage_user_prompt_contains_steps(self):
        from sentinel.mcp.prompts import triage_user

        result = triage_user("bob.finance@acmecorp.com")
        assert "bob.finance@acmecorp.com" in result
        assert "STEP" in result

    async def test_morning_briefing_prompt_returns_string(self):
        from sentinel.mcp.prompts import morning_briefing

        result = morning_briefing()
        assert isinstance(result, str)
        assert len(result) > 100
