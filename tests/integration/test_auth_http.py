"""Phase 5 integration tests — OAuth 2.1 + PKCE and JWT-protected HTTP transport.

Exercised through the FastAPI app via an in-process ASGI client. Keycloak's
JWKS and token endpoints are respx-mocked; tokens are signed with a test key.
Infra hooks (OPA/Redis/Postgres audit) are stubbed so the test is deterministic.
"""

from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
import respx
from httpx import Response

from sentinel.config import get_settings


@pytest.fixture
def http_auth_env(jwks_response, reset_jwt_validator):
    """respx-mock Keycloak JWKS + stub OPA/Redis/Postgres; expose the audit spy."""
    s = get_settings()
    audit_spy = AsyncMock()
    opa = AsyncMock()
    opa.is_allowed = AsyncMock(return_value=(True, "ok"))
    opa.check_rate_limit = AsyncMock(return_value=(True, "ok"))
    with (
        respx.mock(assert_all_mocked=False, assert_all_called=False) as router,
        patch("sentinel.mcp.middleware.write_audit_log", audit_spy),
        patch("sentinel.mcp.middleware._get_rate_count", new=AsyncMock(return_value=0)),
        patch("sentinel.mcp.middleware.get_opa_engine", return_value=opa),
    ):
        router.get(s.oidc_jwks_uri).mock(return_value=Response(200, json=jwks_response))
        yield {"audit_spy": audit_spy, "router": router}


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


class TestOAuthFlow:
    async def test_login_returns_pkce_authorization_url(self, http_client):
        resp = await http_client.get("/auth/login")
        assert resp.status_code == 200
        data = resp.json()
        assert data["code_verifier"]
        assert data["state"]
        q = parse_qs(urlparse(data["authorization_url"]).query)
        assert q["code_challenge_method"] == ["S256"]
        assert q["code_challenge"]
        assert q["response_type"] == ["code"]

    async def test_token_exchange_returns_access_token(self, http_client, http_auth_env, make_jwt):
        access = make_jwt(sub="user-xyz", roles=("analyst",), scope="soc:read")
        http_auth_env["router"].post(get_settings().oidc_token_endpoint).mock(
            return_value=Response(
                200, json={"access_token": access, "token_type": "Bearer", "expires_in": 300}
            )
        )
        resp = await http_client.post(
            "/auth/token", json={"code": "auth-code", "code_verifier": "verifier"}
        )
        assert resp.status_code == 200
        assert resp.json()["access_token"] == access

    async def test_token_exchange_missing_fields_400(self, http_client):
        resp = await http_client.post("/auth/token", json={"code": "x"})
        assert resp.status_code == 400


class TestProtectedToolCalls:
    async def test_no_token_returns_401(self, http_client, http_auth_env):
        resp = await http_client.post("/tools/get_alert", json={"alert_id": "ALT-2026-001"})
        assert resp.status_code == 401

    async def test_valid_token_calls_tool_and_audits_sub(
        self, http_client, http_auth_env, make_jwt
    ):
        token = make_jwt(sub="analyst-001", roles=("analyst",), scope="soc:read")
        resp = await http_client.post(
            "/tools/get_alert", json={"alert_id": "ALT-2026-001"}, headers=_bearer(token)
        )
        assert resp.status_code == 200
        assert resp.json()["alert_id"] == "ALT-2026-001"
        # analyst_id in the audit entry equals the JWT sub
        audited = [c.args[0] for c in http_auth_env["audit_spy"].call_args_list]
        assert any(e.tool_name == "get_alert" and e.analyst_id == "analyst-001" for e in audited)

    async def test_missing_scope_returns_403(self, http_client, http_auth_env, make_jwt):
        # senior_analyst but no soc:read scope → denied
        token = make_jwt(sub="s-1", roles=("senior_analyst",), scope="openid profile")
        resp = await http_client.post(
            "/tools/get_alert", json={"alert_id": "ALT-2026-001"}, headers=_bearer(token)
        )
        assert resp.status_code == 403
        assert resp.json()["detail"]["reason"] == "missing_scope:soc:read"

    async def test_analyst_cannot_call_write_tool_403(self, http_client, http_auth_env, make_jwt):
        token = make_jwt(sub="a-1", roles=("analyst",), scope="soc:read soc:write")
        resp = await http_client.post(
            "/tools/isolate_device",
            json={"hostname": "LAPTOP-HR-03", "reason": "c2"},
            headers=_bearer(token),
        )
        assert resp.status_code == 403
        assert resp.json()["detail"]["reason"] == "write_requires_senior_analyst"

    async def test_senior_analyst_can_propose_write_action(
        self, http_client, http_auth_env, make_jwt
    ):
        token = make_jwt(sub="snr-1", roles=("senior_analyst",), scope="soc:read soc:write")
        resp = await http_client.post(
            "/tools/isolate_device",
            json={"hostname": "LAPTOP-HR-03", "reason": "c2 confirmed"},
            headers=_bearer(token),
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["action_type"] == "isolate_device"
        assert body["confirmation_token"]

    async def test_invalid_token_returns_401(self, http_client, http_auth_env):
        resp = await http_client.post(
            "/tools/get_alert",
            json={"alert_id": "ALT-2026-001"},
            headers=_bearer("garbage.token.here"),
        )
        assert resp.status_code == 401

    async def test_unknown_tool_returns_404(self, http_client, http_auth_env, make_jwt):
        token = make_jwt(sub="a-1", roles=("admin",), scope="soc:read soc:write")
        resp = await http_client.post("/tools/not_a_real_tool", json={}, headers=_bearer(token))
        assert resp.status_code == 404


class TestMcpTransportGuard:
    async def test_mcp_requires_bearer(self, http_client):
        resp = await http_client.post("/mcp", json={})
        assert resp.status_code == 401
        assert resp.json()["code"] == "UNAUTHENTICATED"

    async def test_mcp_401_points_at_resource_metadata(self, http_client):
        # RFC 9728: the challenge must tell the client where to discover the
        # authorization server, or Claude Desktop can't complete the connector.
        resp = await http_client.post("/mcp", json={})
        challenge = resp.headers.get("www-authenticate", "")
        assert challenge.startswith("Bearer ")
        assert "resource_metadata=" in challenge
        assert "/.well-known/oauth-protected-resource/mcp" in challenge


class TestProtectedResourceMetadata:
    async def test_resource_metadata_advertises_keycloak_as(self, http_client):
        for path in (
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
        ):
            meta = (await http_client.get(path)).json()
            assert meta["resource"].endswith("/mcp")
            assert meta["authorization_servers"], "must name an authorization server"
            assert any("/realms/" in s for s in meta["authorization_servers"])

    async def test_oauth_metadata_exposes_registration_endpoint(self, http_client):
        # Clients without a pre-provisioned client_id (Claude) need DCR.
        meta = (await http_client.get("/.well-known/oauth-authorization-server")).json()
        assert meta["registration_endpoint"].endswith(
            "/clients-registrations/openid-connect"
        )


class TestManifestAdvertisesOAuth:
    async def test_manifest_and_oauth_metadata(self, http_client):
        manifest = (await http_client.get("/.well-known/mcp")).json()
        assert manifest["transport"]["http"]["auth"] == "oauth2_pkce"
        meta = (await http_client.get("/.well-known/oauth-authorization-server")).json()
        assert meta["code_challenge_methods_supported"] == ["S256"]
        assert "soc:read" in meta["scopes_supported"]
