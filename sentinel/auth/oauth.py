"""OAuth 2.1 authorization-code + PKCE client for Keycloak.

Builds the authorization URL the client redirects to, and exchanges the
returned authorization code (plus PKCE verifier) for tokens at Keycloak's
token endpoint. Public clients send no secret; confidential clients may set
OAUTH_CLIENT_SECRET.
"""

from typing import Any
from urllib.parse import urlencode

import httpx
import structlog

from sentinel.config import get_settings

logger = structlog.get_logger(__name__)


class OAuthClient:
    def __init__(self) -> None:
        self._settings = get_settings()

    def authorization_url(
        self,
        *,
        code_challenge: str,
        state: str,
        redirect_uri: str | None = None,
        scopes: str | None = None,
    ) -> str:
        """Build the OAuth 2.1 authorization-code + PKCE authorization URL."""
        s = self._settings
        params = {
            "response_type": "code",
            "client_id": s.oauth_client_id,
            "redirect_uri": redirect_uri or s.oauth_redirect_uri,
            "scope": scopes or s.oauth_default_scopes,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        return f"{s.oidc_authorize_endpoint}?{urlencode(params)}"

    async def exchange_code(
        self,
        *,
        code: str,
        code_verifier: str,
        redirect_uri: str | None = None,
    ) -> dict[str, Any]:
        """Exchange an authorization code + PKCE verifier for tokens."""
        s = self._settings
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri or s.oauth_redirect_uri,
            "client_id": s.oauth_client_id,
            "code_verifier": code_verifier,
        }
        if s.oauth_client_secret:
            data["client_secret"] = s.oauth_client_secret

        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
            resp = await client.post(
                s.oidc_token_endpoint,
                data=data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        if resp.status_code != 200:
            logger.warning("oauth_token_exchange_failed", status=resp.status_code)
            return {
                "error": "token_exchange_failed",
                "status": resp.status_code,
                "detail": resp.text[:300],
            }
        tokens: dict[str, Any] = resp.json()
        return tokens


_client: OAuthClient | None = None


def get_oauth_client() -> OAuthClient:
    global _client
    if _client is None:
        _client = OAuthClient()
    return _client
