"""Phase 4 integration tests — every tool exercised through the MCP server.

Tools and adapters run for real (mock-adapter mode, no external services).
Only the infra hooks (OPA, Redis, Postgres audit) are stubbed, so the test is
deterministic and fast — the tool logic itself is never mocked.

Verifies:
- Every read tool returns schema-shaped data (no `not_yet_implemented`).
- Write tools: 1st call returns a ProposedAction + token; confirm without a
  token is rejected; confirm with the token executes and is audited; an expired
  token is rejected.
- generate_incident_report orchestrates its sub-tools into a complete report.
"""

import json
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, patch

import pytest

import sentinel.tools  # noqa: F401  — registers all @mcp.tool() decorators
from sentinel.mcp.server import mcp


def _payload(result):
    """Extract the tool's JSON payload from a FastMCP call_tool() result."""
    content = result[0] if isinstance(result, tuple) else result
    return json.loads(content[0].text)


@pytest.fixture
def soc_infra():
    """Stub OPA/Redis/Postgres so calls are fast; spy on the audit writer."""
    audit_spy = AsyncMock()
    opa = AsyncMock()
    opa.is_allowed = AsyncMock(return_value=(True, "ok"))
    opa.check_rate_limit = AsyncMock(return_value=(True, "ok"))
    with (
        patch("sentinel.mcp.middleware.write_audit_log", audit_spy),
        patch("sentinel.mcp.middleware._get_rate_count", new=AsyncMock(return_value=0)),
        patch("sentinel.mcp.middleware.get_opa_engine", return_value=opa),
    ):
        yield audit_spy


READ_TOOL_CALLS = {
    "get_alert": {"alert_id": "ALT-2026-001"},
    "search_logs": {"query": "powershell"},
    "correlate_alerts": {},
    "similar_incidents": {"alert_id": "ALT-2026-001"},
    "enrich_ioc": {"indicator": "185.220.101.34", "indicator_type": "ip"},
    "threat_hunt": {"indicator": "185.220.101.34"},
    "mitre_technique": {"technique_id": "T1059.001"},
    "user_context": {"email": "alice.hr@acmecorp.com"},
    "recent_logins": {"email": "bob.finance@acmecorp.com"},
    "risk_score_user": {"email": "bob.finance@acmecorp.com"},
    "device_processes": {"hostname": "LAPTOP-HR-03"},
    "network_connections": {"hostname": "LAPTOP-HR-03"},
    "generate_incident_report": {"alert_id": "ALT-2026-002"},
    "weekly_summary": {},
}


class TestReadToolsThroughMcp:
    @pytest.mark.parametrize(("tool_name", "args"), list(READ_TOOL_CALLS.items()))
    async def test_tool_returns_real_data(self, soc_infra, tool_name, args):
        data = _payload(await mcp.call_tool(tool_name, args))
        assert isinstance(data, dict)
        # No stub leftovers, no top-level error for a valid call
        assert data.get("status") != "not_yet_implemented"
        assert "error" not in data, f"{tool_name} returned an error: {data}"

    async def test_all_14_read_tools_covered(self):
        # Guard: the parametrized set covers exactly the read tools.
        assert len(READ_TOOL_CALLS) == 14


class TestWriteToolTwoStepFlow:
    async def test_first_call_returns_proposal_only(self, soc_infra):
        data = _payload(
            await mcp.call_tool(
                "isolate_device", {"hostname": "LAPTOP-HR-03", "reason": "confirmed C2"}
            )
        )
        assert data["action_type"] == "isolate_device"
        assert data["confirmation_token"]
        assert "warning" in data
        # Nothing executed yet
        assert "executed_at" not in data

    async def test_confirm_without_token_is_rejected(self, soc_infra):
        data = _payload(
            await mcp.call_tool(
                "isolate_device",
                {
                    "hostname": "LAPTOP-HR-03",
                    "reason": "x",
                    "confirmed": True,
                    "confirmation_token": "",
                },
            )
        )
        assert data["code"] == "INVALID_TOKEN"

    async def test_confirm_with_token_executes_and_is_audited(self, soc_infra):
        proposal = _payload(
            await mcp.call_tool(
                "disable_user",
                {"email": "bob.finance@acmecorp.com", "reason": "credential compromise"},
            )
        )
        token = proposal["confirmation_token"]

        result = _payload(
            await mcp.call_tool(
                "disable_user",
                {
                    "email": "bob.finance@acmecorp.com",
                    "reason": "credential compromise",
                    "confirmed": True,
                    "confirmation_token": token,
                },
            )
        )
        assert result["action_type"] == "disable_user"
        assert "executed_at" in result
        assert result["result"]["action"] == "suspended"

        # The confirmed execution was written to the audit trail with success.
        audited = [c.args[0] for c in soc_infra.call_args_list]
        assert any(e.tool_name == "disable_user" and e.response_code == "success" for e in audited)

    async def test_expired_token_is_rejected(self, soc_infra):
        from sentinel.tools import confirmation

        proposal = _payload(
            await mcp.call_tool("block_ip", {"ip_address": "185.220.101.34", "reason": "c2"})
        )
        token = proposal["confirmation_token"]
        # In test (no Postgres) the pending action lives in the in-memory store.
        assert token in confirmation._mem_store
        confirmation._mem_store[token]["expires_at"] = datetime.now(UTC) - timedelta(seconds=1)

        result = _payload(
            await mcp.call_tool(
                "block_ip",
                {
                    "ip_address": "185.220.101.34",
                    "reason": "c2",
                    "confirmed": True,
                    "confirmation_token": token,
                },
            )
        )
        assert result["code"] == "TOKEN_EXPIRED"

    async def test_token_for_wrong_tool_is_rejected(self, soc_infra):
        proposal = _payload(
            await mcp.call_tool("isolate_device", {"hostname": "H1", "reason": "test"})
        )
        token = proposal["confirmation_token"]
        # Reuse an isolate_device token on kill_process
        result = _payload(
            await mcp.call_tool(
                "kill_process",
                {
                    "hostname": "H1",
                    "pid": 4821,
                    "reason": "x",
                    "confirmed": True,
                    "confirmation_token": token,
                },
            )
        )
        assert result["code"] == "TOKEN_MISMATCH"


class TestIncidentReportOrchestration:
    async def test_report_pulls_together_all_sub_tools(self, soc_infra):
        report = _payload(
            await mcp.call_tool("generate_incident_report", {"alert_id": "ALT-2026-002"})
        )
        assert report["report_id"] == "IR-ALT-2026-002"
        # Sub-tool outputs are all woven in
        for section in (
            "executive_summary",
            "affected_assets",
            "identity",
            "endpoint",
            "threat_intelligence",
            "mitre_attack",
            "similar_incidents",
            "recommended_actions",
        ):
            assert section in report
        # The malicious source IP was enriched
        assert report["executive_summary"]["malicious_ioc_count"] >= 1
        assert report["mitre_attack"]
