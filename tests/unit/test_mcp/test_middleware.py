"""Middleware pipeline unit tests.

Mocks out OPA, Redis, and audit log so no external services are needed.
Tests the full pipeline: policy check → rate limit → execute → audit.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from sentinel.mcp.middleware import _sanitize_inputs, run_middleware

# ── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def allow_policy():
    """OPA engine that always allows."""
    engine = MagicMock()
    engine.is_allowed = AsyncMock(return_value=(True, "policy_allow"))
    engine.check_rate_limit = AsyncMock(return_value=(True, "within_limit"))
    return engine


@pytest.fixture
def deny_policy():
    """OPA engine that always denies."""
    engine = MagicMock()
    engine.is_allowed = AsyncMock(return_value=(False, "write_tools_require_senior_analyst"))
    engine.check_rate_limit = AsyncMock(return_value=(True, "within_limit"))
    return engine


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestMiddlewarePipeline:
    async def test_allowed_tool_returns_result(self, allow_policy):
        async def tool_fn(args):
            return {"alert_id": args["alert_id"], "severity": "high"}

        with (
            patch("sentinel.mcp.middleware.get_opa_engine", return_value=allow_policy),
            patch("sentinel.mcp.middleware.write_audit_log", new_callable=AsyncMock),
            patch(
                "sentinel.mcp.middleware._get_rate_count", new_callable=AsyncMock, return_value=0
            ),
        ):
            result = await run_middleware("get_alert", {"alert_id": "ALT-001"}, tool_fn)

        assert result["alert_id"] == "ALT-001"
        assert result["severity"] == "high"

    async def test_policy_denied_returns_error_dict(self, deny_policy):
        async def tool_fn(args):
            return {}  # should never be called

        with (
            patch("sentinel.mcp.middleware.get_opa_engine", return_value=deny_policy),
            patch("sentinel.mcp.middleware.write_audit_log", new_callable=AsyncMock),
        ):
            result = await run_middleware("isolate_device", {"hostname": "LAPTOP-001"}, tool_fn)

        assert result["code"] == "POLICY_DENIED"
        assert "error" in result

    async def test_tool_exception_returns_error_dict(self, allow_policy):
        async def failing_tool(args):
            raise ValueError("Elastic connection refused")

        with (
            patch("sentinel.mcp.middleware.get_opa_engine", return_value=allow_policy),
            patch("sentinel.mcp.middleware.write_audit_log", new_callable=AsyncMock),
            patch(
                "sentinel.mcp.middleware._get_rate_count", new_callable=AsyncMock, return_value=0
            ),
        ):
            result = await run_middleware("search_logs", {"query": "fail"}, failing_tool)

        assert result["code"] == "INTERNAL_ERROR"
        assert "Elastic connection refused" in result["error"]

    async def test_audit_log_written_on_allow(self, allow_policy):
        async def tool_fn(args):
            return {"ok": True}

        mock_audit = AsyncMock()
        with (
            patch("sentinel.mcp.middleware.get_opa_engine", return_value=allow_policy),
            patch("sentinel.mcp.middleware.write_audit_log", mock_audit),
            patch(
                "sentinel.mcp.middleware._get_rate_count", new_callable=AsyncMock, return_value=0
            ),
        ):
            await run_middleware("get_alert", {"alert_id": "ALT-001"}, tool_fn)

        mock_audit.assert_called_once()
        entry = mock_audit.call_args[0][0]
        assert entry.tool_name == "get_alert"
        assert entry.response_code == "success"

    async def test_audit_log_written_on_deny(self, deny_policy):
        async def tool_fn(args):
            return {}

        mock_audit = AsyncMock()
        with (
            patch("sentinel.mcp.middleware.get_opa_engine", return_value=deny_policy),
            patch("sentinel.mcp.middleware.write_audit_log", mock_audit),
        ):
            await run_middleware("isolate_device", {}, tool_fn)

        mock_audit.assert_called_once()
        entry = mock_audit.call_args[0][0]
        assert entry.response_code == "denied"

    async def test_rate_limit_exceeded_returns_error(self, allow_policy):
        allow_policy.check_rate_limit = AsyncMock(return_value=(False, "rate_limit_exceeded"))

        async def tool_fn(args):
            return {}

        mock_audit = AsyncMock()
        with (
            patch("sentinel.mcp.middleware.get_opa_engine", return_value=allow_policy),
            patch("sentinel.mcp.middleware.write_audit_log", mock_audit),
            patch(
                "sentinel.mcp.middleware._get_rate_count", new_callable=AsyncMock, return_value=999
            ),
        ):
            result = await run_middleware("enrich_ioc", {"indicator": "1.2.3.4"}, tool_fn)

        assert result["code"] == "RATE_LIMIT_EXCEEDED"

    async def test_sensitive_inputs_redacted_in_audit(self, allow_policy):
        async def tool_fn(args):
            return {}

        mock_audit = AsyncMock()
        with (
            patch("sentinel.mcp.middleware.get_opa_engine", return_value=allow_policy),
            patch("sentinel.mcp.middleware.write_audit_log", mock_audit),
            patch(
                "sentinel.mcp.middleware._get_rate_count", new_callable=AsyncMock, return_value=0
            ),
        ):
            await run_middleware(
                "user_context",
                {"email": "alice@corp.com", "api_key": "secret-value"},
                tool_fn,
            )

        entry = mock_audit.call_args[0][0]
        assert entry.input_summary["api_key"] == "[REDACTED]"
        assert entry.input_summary["email"] == "[EMAIL_REDACTED]"  # PII redaction


class TestRateLimitRedisDown:
    async def test_write_tool_fails_closed_when_redis_down(self, allow_policy):
        async def tool_fn(args):
            return {"action_type": "isolate_device"}

        with (
            patch("sentinel.mcp.middleware.get_opa_engine", return_value=allow_policy),
            patch("sentinel.mcp.middleware.write_audit_log", new_callable=AsyncMock),
            patch(
                "sentinel.mcp.middleware._get_rate_count", new_callable=AsyncMock, return_value=-1
            ),
        ):
            result = await run_middleware("isolate_device", {"hostname": "H"}, tool_fn)
        assert result["code"] == "RATE_LIMIT_UNAVAILABLE"

    async def test_read_tool_degrades_open_when_redis_down(self, allow_policy):
        async def tool_fn(args):
            return {"alert_id": "ALT-1"}

        with (
            patch("sentinel.mcp.middleware.get_opa_engine", return_value=allow_policy),
            patch("sentinel.mcp.middleware.write_audit_log", new_callable=AsyncMock),
            patch(
                "sentinel.mcp.middleware._get_rate_count", new_callable=AsyncMock, return_value=-1
            ),
        ):
            result = await run_middleware("get_alert", {"alert_id": "ALT-1"}, tool_fn)
        assert result["alert_id"] == "ALT-1"  # read tool still runs (degraded)


class TestPrincipalAuthorization:
    async def test_analyst_principal_denied_write_tool(self, allow_policy):
        from sentinel.auth.context import (
            Principal,
            reset_current_principal,
            set_current_principal,
        )

        async def tool_fn(args):
            return {}  # must not run

        principal = Principal("user-1", "analyst", ("soc:read", "soc:write"))
        tok = set_current_principal(principal)
        try:
            with (
                patch("sentinel.mcp.middleware.get_opa_engine", return_value=allow_policy),
                patch("sentinel.mcp.middleware.write_audit_log", new_callable=AsyncMock),
                patch(
                    "sentinel.mcp.middleware._get_rate_count",
                    new_callable=AsyncMock,
                    return_value=0,
                ),
            ):
                result = await run_middleware("isolate_device", {"hostname": "H"}, tool_fn)
        finally:
            reset_current_principal(tok)
        assert result["code"] == "FORBIDDEN"
        assert result["reason"] == "write_requires_senior_analyst"

    async def test_analyst_principal_allowed_read_tool(self, allow_policy):
        from sentinel.auth.context import (
            Principal,
            reset_current_principal,
            set_current_principal,
        )

        async def tool_fn(args):
            return {"alert_id": "ALT-1"}

        principal = Principal("user-1", "analyst", ("soc:read",))
        tok = set_current_principal(principal)
        try:
            with (
                patch("sentinel.mcp.middleware.get_opa_engine", return_value=allow_policy),
                patch("sentinel.mcp.middleware.write_audit_log", new_callable=AsyncMock),
                patch(
                    "sentinel.mcp.middleware._get_rate_count",
                    new_callable=AsyncMock,
                    return_value=0,
                ),
            ):
                result = await run_middleware("get_alert", {"alert_id": "ALT-1"}, tool_fn)
        finally:
            reset_current_principal(tok)
        assert result["alert_id"] == "ALT-1"


class TestSanitizeInputs:
    def test_redacts_api_key(self):
        result = _sanitize_inputs({"api_key": "abc", "query": "hello"})
        assert result["api_key"] == "[REDACTED]"
        assert result["query"] == "hello"

    def test_redacts_password(self):
        result = _sanitize_inputs({"password": "hunter2"})
        assert result["password"] == "[REDACTED]"

    def test_redacts_token(self):
        result = _sanitize_inputs({"token": "bearer-xyz"})
        assert result["token"] == "[REDACTED]"

    def test_passes_through_safe_fields(self):
        inputs = {"hostname": "LAPTOP-001", "limit": 10, "days": 7}
        assert _sanitize_inputs(inputs) == inputs

    def test_empty_dict(self):
        assert _sanitize_inputs({}) == {}
