"""OAuth client tests — authorization URL build + token exchange (respx)."""

from urllib.parse import parse_qs, urlparse

from httpx import Response

from sentinel.auth.oauth import OAuthClient
from sentinel.config import get_settings


class TestAuthorizationUrl:
    def test_contains_pkce_and_required_params(self):
        url = OAuthClient().authorization_url(code_challenge="CHALLENGE", state="STATE")
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        assert parsed.path.endswith("/protocol/openid-connect/auth")
        assert q["response_type"] == ["code"]
        assert q["code_challenge"] == ["CHALLENGE"]
        assert q["code_challenge_method"] == ["S256"]
        assert q["state"] == ["STATE"]
        assert q["client_id"] == [get_settings().oauth_client_id]
        assert "soc:read" in q["scope"][0]


class TestExchangeCode:
    async def test_success_returns_tokens(self, respx_mock):
        route = respx_mock.post(get_settings().oidc_token_endpoint).mock(
            return_value=Response(
                200, json={"access_token": "abc", "token_type": "Bearer", "expires_in": 300}
            )
        )
        tokens = await OAuthClient().exchange_code(code="authcode", code_verifier="verifier")
        assert tokens["access_token"] == "abc"
        assert route.called
        # PKCE verifier + grant type were sent
        sent = route.calls.last.request.content.decode()
        assert "grant_type=authorization_code" in sent
        assert "code_verifier=verifier" in sent

    async def test_failure_returns_error(self, respx_mock):
        respx_mock.post(get_settings().oidc_token_endpoint).mock(
            return_value=Response(400, json={"error": "invalid_grant"})
        )
        tokens = await OAuthClient().exchange_code(code="bad", code_verifier="v")
        assert tokens["error"] == "token_exchange_failed"
        assert tokens["status"] == 400
