"""JWT validation tests — JWKS fetched via respx, no real Keycloak."""

import pytest
from httpx import Response

from sentinel.auth.jwt import InvalidTokenError, JWTValidator, principal_from_claims
from sentinel.config import get_settings


def _certs_url():
    return get_settings().oidc_jwks_uri


class TestJWTValidate:
    async def test_valid_token_returns_claims(self, respx_mock, jwks_response, make_jwt):
        respx_mock.get(_certs_url()).mock(return_value=Response(200, json=jwks_response))
        token = make_jwt(sub="analyst-7", roles=("analyst",), scope="soc:read")
        claims = await JWTValidator().validate(token)
        assert claims["sub"] == "analyst-7"

    async def test_principal_extraction(self, respx_mock, jwks_response, make_jwt):
        respx_mock.get(_certs_url()).mock(return_value=Response(200, json=jwks_response))
        token = make_jwt(sub="u-9", roles=("analyst",), scope="soc:read soc:write")
        principal = await JWTValidator().principal(token)
        assert principal.analyst_id == "u-9"
        assert principal.role == "analyst"
        assert principal.has_scope("soc:read")
        assert principal.has_scope("soc:write")

    async def test_role_precedence_picks_most_privileged(self, respx_mock, jwks_response, make_jwt):
        respx_mock.get(_certs_url()).mock(return_value=Response(200, json=jwks_response))
        token = make_jwt(roles=("analyst", "admin", "senior_analyst"))
        principal = await JWTValidator().principal(token)
        assert principal.role == "admin"

    async def test_expired_token_rejected(self, respx_mock, jwks_response, make_jwt):
        respx_mock.get(_certs_url()).mock(return_value=Response(200, json=jwks_response))
        token = make_jwt(exp=1)  # 1970
        with pytest.raises(InvalidTokenError):
            await JWTValidator().validate(token)

    async def test_wrong_issuer_rejected(self, respx_mock, jwks_response, make_jwt):
        respx_mock.get(_certs_url()).mock(return_value=Response(200, json=jwks_response))
        token = make_jwt(iss="https://evil.example.com/realms/x")
        with pytest.raises(InvalidTokenError):
            await JWTValidator().validate(token)

    async def test_tampered_signature_rejected(self, respx_mock, jwks_response, make_jwt):
        respx_mock.get(_certs_url()).mock(return_value=Response(200, json=jwks_response))
        token = make_jwt() + "tamper"
        with pytest.raises(InvalidTokenError):
            await JWTValidator().validate(token)

    async def test_unknown_kid_rejected(self, respx_mock, jwks_response, make_jwt, rsa_key):
        import jwt as pyjwt

        respx_mock.get(_certs_url()).mock(return_value=Response(200, json=jwks_response))
        token = pyjwt.encode(
            {"sub": "x", "iss": get_settings().oidc_issuer, "exp": 9999999999},
            rsa_key["private_pem"],
            algorithm="RS256",
            headers={"kid": "some-other-kid"},
        )
        with pytest.raises(InvalidTokenError):
            await JWTValidator().validate(token)

    async def test_malformed_token_rejected(self, respx_mock, jwks_response):
        respx_mock.get(_certs_url()).mock(return_value=Response(200, json=jwks_response))
        with pytest.raises(InvalidTokenError):
            await JWTValidator().validate("not-a-jwt")


class TestJWKSCacheTTL:
    async def test_cache_is_reused_within_ttl_then_refetched_after(
        self, respx_mock, jwks_response, make_jwt, rsa_key
    ):
        from sentinel.auth.jwt import _JWKS_TTL_SECONDS

        # After rotation the JWKS no longer contains the original kid.
        rotated = {"keys": [{**rsa_key["jwk"], "kid": "rotated-out"}]}
        route = respx_mock.get(_certs_url()).mock(
            side_effect=[
                Response(200, json=jwks_response),  # initial fetch
                Response(200, json=rotated),  # refetch after TTL
                Response(200, json=rotated),  # force-refresh retry
            ]
        )
        validator = JWTValidator()
        clock = {"t": 0.0}
        validator._now = lambda: clock["t"]
        token = make_jwt(sub="u-ttl")

        # 1) first validate fetches the JWKS
        assert (await validator.validate(token))["sub"] == "u-ttl"
        assert route.call_count == 1
        # 2) within TTL → cache reused, no refetch
        await validator.validate(token)
        assert route.call_count == 1
        # 3) past TTL → refetch; the original key is gone → rejected
        clock["t"] = _JWKS_TTL_SECONDS + 1
        with pytest.raises(InvalidTokenError):
            await validator.validate(token)
        assert route.call_count >= 2


class TestPrincipalFromClaims:
    def test_missing_sub_raises(self):
        with pytest.raises(InvalidTokenError):
            principal_from_claims({"scope": "soc:read"})

    def test_defaults_to_analyst_when_no_roles(self):
        p = principal_from_claims({"sub": "u-1", "scope": "soc:read"})
        assert p.role == "analyst"
        assert p.analyst_id == "u-1"
