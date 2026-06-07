"""Scope + role authorization tests (mirrors policies/authz.rego)."""

from sentinel.auth.authz import authorize, required_scope
from sentinel.auth.context import Principal


def _p(role="analyst", scopes=("soc:read",)):
    return Principal(analyst_id="u-1", role=role, scopes=tuple(scopes))


def test_required_scope_mapping():
    assert required_scope("get_alert") == "soc:read"
    assert required_scope("isolate_device") == "soc:write"


def test_read_tool_allowed_for_analyst_with_read_scope():
    allowed, reason = authorize(_p(), "get_alert")
    assert allowed is True
    assert reason == "authorized"


def test_read_tool_denied_without_read_scope():
    allowed, reason = authorize(_p(role="senior_analyst", scopes=("openid",)), "get_alert")
    assert allowed is False
    assert reason == "missing_scope:soc:read"


def test_write_tool_denied_for_analyst_role():
    allowed, reason = authorize(
        _p(role="analyst", scopes=("soc:read", "soc:write")), "isolate_device"
    )
    assert allowed is False
    assert reason == "write_requires_senior_analyst"


def test_write_tool_denied_without_write_scope():
    allowed, reason = authorize(_p(role="senior_analyst", scopes=("soc:read",)), "isolate_device")
    assert allowed is False
    assert reason == "missing_scope:soc:write"


def test_write_tool_allowed_for_senior_analyst():
    allowed, _ = authorize(
        _p(role="senior_analyst", scopes=("soc:read", "soc:write")), "isolate_device"
    )
    assert allowed is True


def test_write_tool_allowed_for_admin():
    allowed, _ = authorize(_p(role="admin", scopes=("soc:read", "soc:write")), "kill_process")
    assert allowed is True


def test_unknown_tool_denied():
    allowed, reason = authorize(_p(scopes=("soc:read", "soc:write")), "definitely_not_a_tool")
    assert allowed is False
    assert reason == "unknown_tool"
