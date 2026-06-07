"""Keycloak identity adapter tests — respx-mocked, no real network.

Keycloak resolves a user id + admin token (via _retry_request, which does not
touch the breaker) before each operation, then performs the operation via _call
(which does). Tests mock the token + user-lookup endpoints, then exercise the
operation endpoints.
"""

from unittest.mock import AsyncMock

import pytest
from httpx import ConnectError, Response

from sentinel.adapters.base import CircuitOpenError
from sentinel.adapters.keycloak import KeycloakAdapter, get_keycloak_adapter

TOKEN_URL = "http://localhost:8080/realms/master/protocol/openid-connect/token"
USERS_URL = "http://localhost:8080/admin/realms/sentinel/users"
USER_URL = "http://localhost:8080/admin/realms/sentinel/users/uid-1"
EVENTS_URL = "http://localhost:8080/admin/realms/sentinel/events"

EMAIL = "alice@acme.com"


def _mock_token(respx_mock):
    respx_mock.post(TOKEN_URL).mock(
        return_value=Response(200, json={"access_token": "tok", "expires_in": 300})
    )


def _mock_user_lookup(respx_mock, users=None):
    respx_mock.get(USERS_URL).mock(
        return_value=Response(200, json=users if users is not None else [{"id": "uid-1"}])
    )


def _resolve(adapter):
    """Bypass token + user-id resolution with stubs (id present, token present)."""
    adapter._find_user_id = AsyncMock(return_value="uid-1")
    adapter._get_token = AsyncMock(return_value="tok")


# ── Mock mode ─────────────────────────────────────────────────────────────────


class TestKeycloakMockMode:
    async def test_get_user_mock(self):
        adapter = KeycloakAdapter()
        result = await adapter.get_user("alice.hr@acmecorp.com")
        assert result is not None
        await adapter.close()

    async def test_get_login_events_mock(self):
        adapter = KeycloakAdapter()
        result = await adapter.get_login_events("alice.hr@acmecorp.com")
        assert isinstance(result, list)
        await adapter.close()

    async def test_suspend_user_mock(self):
        adapter = KeycloakAdapter()
        result = await adapter.suspend_user("alice.hr@acmecorp.com")
        assert result["action"] == "suspended"
        assert result["mock"] is True
        await adapter.close()


# ── get_user ──────────────────────────────────────────────────────────────────


class TestKeycloakGetUser:
    async def test_success_enabled_user(self, respx_mock, live_mode):
        _mock_token(respx_mock)
        _mock_user_lookup(respx_mock)
        respx_mock.get(USER_URL).mock(
            return_value=Response(
                200,
                json={
                    "email": EMAIL,
                    "firstName": "Alice",
                    "lastName": "HR",
                    "enabled": True,
                    "createdTimestamp": 1700000000000,
                    "requiredActions": ["CONFIGURE_TOTP"],
                },
            )
        )
        adapter = KeycloakAdapter()
        result = await adapter.get_user(EMAIL)
        assert result["email"] == EMAIL
        assert result["name"] == "Alice HR"
        assert result["account_status"] == "active"
        assert result["mfa_enabled"] is True
        await adapter.close()

    async def test_success_disabled_user_no_mfa(self, respx_mock, live_mode):
        _mock_token(respx_mock)
        _mock_user_lookup(respx_mock)
        respx_mock.get(USER_URL).mock(
            return_value=Response(
                200,
                json={
                    "email": EMAIL,
                    "firstName": "Bob",
                    "lastName": "",
                    "enabled": False,
                    "requiredActions": [],
                },
            )
        )
        adapter = KeycloakAdapter()
        result = await adapter.get_user(EMAIL)
        assert result["account_status"] == "disabled"
        assert result["mfa_enabled"] is False
        await adapter.close()

    async def test_user_not_found_returns_none(self, respx_mock, live_mode):
        _mock_token(respx_mock)
        _mock_user_lookup(respx_mock, users=[])
        adapter = KeycloakAdapter()
        assert await adapter.get_user(EMAIL) is None
        await adapter.close()

    async def test_token_failure_returns_none(self, live_mode):
        adapter = KeycloakAdapter()
        adapter._find_user_id = AsyncMock(return_value="uid-1")
        adapter._get_token = AsyncMock(return_value=None)
        assert await adapter.get_user(EMAIL) is None
        await adapter.close()

    async def test_circuit_opens_after_five_failures(self, respx_mock, live_mode):
        _mock_token(respx_mock)
        _mock_user_lookup(respx_mock)
        respx_mock.get(USER_URL).mock(side_effect=ConnectError("down"))
        adapter = KeycloakAdapter()
        for _ in range(5):
            assert await adapter.get_user(EMAIL) is None
        assert adapter._breaker.is_open()
        with pytest.raises(CircuitOpenError):
            await adapter.get_user(EMAIL)
        await adapter.close()

    async def test_circuit_open_error_from_call_propagates(self, live_mode):
        adapter = KeycloakAdapter()
        _resolve(adapter)
        adapter._call = AsyncMock(side_effect=CircuitOpenError("x"))
        with pytest.raises(CircuitOpenError):
            await adapter.get_user(EMAIL)
        await adapter.close()


# ── get_login_events ──────────────────────────────────────────────────────────


class TestKeycloakLoginEvents:
    async def test_success(self, respx_mock, live_mode):
        _mock_token(respx_mock)
        _mock_user_lookup(respx_mock)
        respx_mock.get(EVENTS_URL).mock(
            return_value=Response(
                200,
                json=[
                    {
                        "time": 1700000000000,
                        "ipAddress": "1.2.3.4",
                        "type": "LOGIN",
                        "details": {"auth_method": "otp", "auth_type": "totp"},
                    },
                ],
            )
        )
        adapter = KeycloakAdapter()
        result = await adapter.get_login_events(EMAIL, days=3)
        assert len(result) == 1
        assert result[0]["ip_address"] == "1.2.3.4"
        assert result[0]["success"] is True
        assert result[0]["mfa_method"] == "totp"
        await adapter.close()

    async def test_user_not_found_returns_empty(self, respx_mock, live_mode):
        _mock_token(respx_mock)
        _mock_user_lookup(respx_mock, users=[])
        adapter = KeycloakAdapter()
        assert await adapter.get_login_events(EMAIL) == []
        await adapter.close()

    async def test_token_failure_returns_empty(self, live_mode):
        adapter = KeycloakAdapter()
        adapter._find_user_id = AsyncMock(return_value="uid-1")
        adapter._get_token = AsyncMock(return_value=None)
        assert await adapter.get_login_events(EMAIL) == []
        await adapter.close()

    async def test_transport_error_returns_empty(self, respx_mock, live_mode):
        _mock_token(respx_mock)
        _mock_user_lookup(respx_mock)
        respx_mock.get(EVENTS_URL).mock(side_effect=ConnectError("boom"))
        adapter = KeycloakAdapter()
        assert await adapter.get_login_events(EMAIL) == []
        await adapter.close()

    async def test_circuit_open_guard_raises(self, live_mode):
        adapter = KeycloakAdapter()
        _resolve(adapter)
        for _ in range(5):
            await adapter._breaker.record_failure()
        with pytest.raises(CircuitOpenError):
            await adapter.get_login_events(EMAIL)
        await adapter.close()

    async def test_circuit_open_error_from_call_propagates(self, live_mode):
        adapter = KeycloakAdapter()
        _resolve(adapter)
        adapter._call = AsyncMock(side_effect=CircuitOpenError("x"))
        with pytest.raises(CircuitOpenError):
            await adapter.get_login_events(EMAIL)
        await adapter.close()


# ── suspend_user ──────────────────────────────────────────────────────────────


class TestKeycloakSuspendUser:
    async def test_success(self, respx_mock, live_mode):
        _mock_token(respx_mock)
        _mock_user_lookup(respx_mock)
        respx_mock.put(USER_URL).mock(return_value=Response(204))
        adapter = KeycloakAdapter()
        result = await adapter.suspend_user(EMAIL)
        assert result["action"] == "suspended"
        assert result["user_id"] == "uid-1"
        await adapter.close()

    async def test_not_found(self, respx_mock, live_mode):
        _mock_token(respx_mock)
        _mock_user_lookup(respx_mock, users=[])
        adapter = KeycloakAdapter()
        result = await adapter.suspend_user(EMAIL)
        assert result["code"] == "NOT_FOUND"
        await adapter.close()

    async def test_token_failure(self, live_mode):
        adapter = KeycloakAdapter()
        adapter._find_user_id = AsyncMock(return_value="uid-1")
        adapter._get_token = AsyncMock(return_value=None)
        result = await adapter.suspend_user(EMAIL)
        assert result["code"] == "AUTH_FAILED"
        await adapter.close()

    async def test_transport_error(self, respx_mock, live_mode):
        _mock_token(respx_mock)
        _mock_user_lookup(respx_mock)
        respx_mock.put(USER_URL).mock(side_effect=ConnectError("boom"))
        adapter = KeycloakAdapter()
        result = await adapter.suspend_user(EMAIL)
        assert result["code"] == "KEYCLOAK_ERROR"
        await adapter.close()

    async def test_circuit_open_guard_raises(self, live_mode):
        adapter = KeycloakAdapter()
        _resolve(adapter)
        for _ in range(5):
            await adapter._breaker.record_failure()
        with pytest.raises(CircuitOpenError):
            await adapter.suspend_user(EMAIL)
        await adapter.close()

    async def test_circuit_open_error_from_call_propagates(self, live_mode):
        adapter = KeycloakAdapter()
        _resolve(adapter)
        adapter._call = AsyncMock(side_effect=CircuitOpenError("x"))
        with pytest.raises(CircuitOpenError):
            await adapter.suspend_user(EMAIL)
        await adapter.close()


# ── Internal helpers: _get_token, _find_user_id ───────────────────────────────


class TestKeycloakHelpers:
    async def test_get_token_success_then_cached(self, respx_mock, live_mode):
        route = respx_mock.post(TOKEN_URL).mock(
            return_value=Response(200, json={"access_token": "tok", "expires_in": 300})
        )
        adapter = KeycloakAdapter()
        assert await adapter._get_token() == "tok"
        assert await adapter._get_token() == "tok"  # cached — no second request
        assert route.call_count == 1
        await adapter.close()

    async def test_get_token_failure_returns_none(self, respx_mock, live_mode):
        respx_mock.post(TOKEN_URL).mock(side_effect=ConnectError("boom"))
        adapter = KeycloakAdapter()
        assert await adapter._get_token() is None
        await adapter.close()

    async def test_find_user_id_no_token_returns_none(self, live_mode):
        adapter = KeycloakAdapter()
        adapter._get_token = AsyncMock(return_value=None)
        assert await adapter._find_user_id(EMAIL) is None
        await adapter.close()

    async def test_find_user_id_success(self, respx_mock, live_mode):
        _mock_token(respx_mock)
        _mock_user_lookup(respx_mock, users=[{"id": "uid-1"}])
        adapter = KeycloakAdapter()
        assert await adapter._find_user_id(EMAIL) == "uid-1"
        await adapter.close()

    async def test_find_user_id_empty_returns_none(self, respx_mock, live_mode):
        _mock_token(respx_mock)
        _mock_user_lookup(respx_mock, users=[])
        adapter = KeycloakAdapter()
        assert await adapter._find_user_id(EMAIL) is None
        await adapter.close()

    async def test_find_user_id_error_returns_none(self, respx_mock, live_mode):
        _mock_token(respx_mock)
        respx_mock.get(USERS_URL).mock(side_effect=ConnectError("boom"))
        adapter = KeycloakAdapter()
        assert await adapter._find_user_id(EMAIL) is None
        await adapter.close()


def test_get_keycloak_adapter_is_singleton():
    assert get_keycloak_adapter() is get_keycloak_adapter()
