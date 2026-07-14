"""OPA policy engine unit tests.

These tests mock the OPA HTTP endpoint using respx so no real OPA
instance is needed. They verify the engine's behaviour when:
- OPA returns allow=true
- OPA returns allow=false
- OPA is unreachable (default deny)
- Policy enforcement is disabled
"""


import pytest
import respx
from httpx import Response

from sentinel.config import get_settings
from sentinel.policy.engine import OPAEngine


@pytest.fixture(autouse=True)
def enforce_policy(monkeypatch):
    """OPA unit tests need enforcement ON so the engine actually calls OPA."""
    monkeypatch.setenv("POLICY_ENFORCEMENT", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def engine():
    return OPAEngine("http://opa-test:8181")


class TestIsAllowed:
    @respx.mock
    async def test_allows_when_opa_returns_true(self, engine):
        respx.post("http://opa-test:8181/v1/data/sentinel/authz").mock(
            return_value=Response(
                200, json={"result": {"allow": True, "reason": "analyst_read_allowed"}}
            )
        )
        allowed, reason = await engine.is_allowed("get_alert", "alice@corp.com", "analyst")
        assert allowed is True
        assert reason == "policy_allow"

    @respx.mock
    async def test_denies_when_opa_returns_false(self, engine):
        respx.post("http://opa-test:8181/v1/data/sentinel/authz").mock(
            return_value=Response(
                200,
                json={"result": {"allow": False, "reason": "write_tools_require_senior_analyst"}},
            )
        )
        allowed, reason = await engine.is_allowed("isolate_device", "alice@corp.com", "analyst")
        assert allowed is False
        assert "write" in reason or reason == "policy_deny"

    @respx.mock
    async def test_default_deny_when_opa_unreachable(self, engine):
        respx.post("http://opa-test:8181/v1/data/sentinel/authz").mock(
            side_effect=Exception("Connection refused")
        )
        allowed, reason = await engine.is_allowed("get_alert", "alice@corp.com", "analyst")
        assert allowed is False

    @respx.mock
    async def test_default_deny_when_opa_returns_500(self, engine):
        respx.post("http://opa-test:8181/v1/data/sentinel/authz").mock(
            return_value=Response(500, text="Internal Server Error")
        )
        allowed, _ = await engine.is_allowed("get_alert", "alice@corp.com", "analyst")
        assert allowed is False

    @respx.mock
    async def test_empty_result_is_deny(self, engine):
        respx.post("http://opa-test:8181/v1/data/sentinel/authz").mock(
            return_value=Response(200, json={"result": {}})
        )
        allowed, _ = await engine.is_allowed("get_alert", "alice@corp.com", "analyst")
        assert allowed is False


class TestRateLimit:
    @respx.mock
    async def test_within_limit_returns_true(self, engine):
        respx.post("http://opa-test:8181/v1/data/sentinel/rate_limit").mock(
            return_value=Response(200, json={"result": {"allow": True}})
        )
        within, _ = await engine.check_rate_limit("get_alert", "alice@corp.com", 5)
        assert within is True

    @respx.mock
    async def test_exceeded_limit_returns_false(self, engine):
        respx.post("http://opa-test:8181/v1/data/sentinel/rate_limit").mock(
            return_value=Response(
                200, json={"result": {"allow": False, "reason": "rate_limit_exceeded"}}
            )
        )
        within, reason = await engine.check_rate_limit("get_alert", "alice@corp.com", 200)
        assert within is False

    @respx.mock
    async def test_opa_unreachable_defaults_to_allow_for_rate_limit(self, engine):
        respx.post("http://opa-test:8181/v1/data/sentinel/rate_limit").mock(
            side_effect=Exception("timeout")
        )
        within, _ = await engine.check_rate_limit("get_alert", "alice@corp.com", 5)
        # Rate limit fails open (allow) — policy fails closed (deny)
        assert within is True
