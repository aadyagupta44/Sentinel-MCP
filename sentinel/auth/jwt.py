"""JWT validation for the HTTP transport.

Validates Keycloak-issued RS256 access tokens against the realm JWKS:
signature, issuer, expiry, and (optionally) audience. Derives the SOC
Principal — analyst_id from `sub`, role from realm roles, scopes from the
`scope` claim.
"""

import asyncio
import json
import time
from typing import Any

import httpx
import jwt
from jwt.algorithms import RSAAlgorithm

from sentinel.auth.context import Principal
from sentinel.config import get_settings

# Highest privilege first — the principal's role is the most privileged realm role it holds.
_ROLE_PRECEDENCE = ("admin", "senior_analyst", "analyst")

# How long a fetched JWKS is trusted before a refresh. Bounds the window a
# rotated-out (revoked) key stays accepted.
_JWKS_TTL_SECONDS = 600.0


class InvalidTokenError(Exception):
    """Raised when a Bearer token fails validation."""


class JWTValidator:
    def __init__(self) -> None:
        self._settings = get_settings()
        self._jwks: dict[str, Any] | None = None
        self._fetched_at: float = 0.0
        self._lock = asyncio.Lock()
        self._now = time.monotonic  # injectable for tests

    def _is_fresh(self) -> bool:
        return self._jwks is not None and (self._now() - self._fetched_at) < _JWKS_TTL_SECONDS

    async def _get_jwks(self, *, force: bool = False) -> dict[str, Any]:
        if not force and self._is_fresh():
            return self._jwks  # type: ignore[return-value]
        # Single-flight: only one coroutine refetches; others reuse the result.
        async with self._lock:
            if not force and self._is_fresh():
                return self._jwks  # type: ignore[return-value]
            async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
                resp = await client.get(self._settings.oidc_jwks_uri)
                resp.raise_for_status()
                self._jwks = resp.json()
                self._fetched_at = self._now()
        return self._jwks

    async def _signing_key(self, token: str) -> Any:
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except jwt.PyJWTError as exc:
            raise InvalidTokenError(f"malformed token header: {exc}") from exc

        jwks = await self._get_jwks()
        for key in jwks.get("keys", []):
            if key.get("kid") == kid:
                return RSAAlgorithm.from_jwk(json.dumps(key))
        # kid not found in the (possibly stale) cache — force one refresh and retry.
        for key in (await self._get_jwks(force=True)).get("keys", []):
            if key.get("kid") == kid:
                return RSAAlgorithm.from_jwk(json.dumps(key))
        raise InvalidTokenError(f"no signing key for kid={kid}")

    async def validate(self, token: str) -> dict[str, Any]:
        """Validate the token and return its claims, or raise InvalidTokenError."""
        s = self._settings
        try:
            key = await self._signing_key(token)
            claims: dict[str, Any] = jwt.decode(
                token,
                key=key,
                algorithms=["RS256"],
                issuer=s.oidc_issuer,
                audience=s.oauth_audience or None,
                options={"verify_aud": bool(s.oauth_audience)},
            )
            return claims
        except InvalidTokenError:
            raise
        except jwt.PyJWTError as exc:
            raise InvalidTokenError(str(exc)) from exc

    async def principal(self, token: str) -> Principal:
        claims = await self.validate(token)
        return principal_from_claims(claims)


def principal_from_claims(claims: dict[str, Any]) -> Principal:
    sub = claims.get("sub") or ""
    if not sub:
        raise InvalidTokenError("token has no `sub` claim")
    realm_roles = set(claims.get("realm_access", {}).get("roles", []) or [])
    role = next((r for r in _ROLE_PRECEDENCE if r in realm_roles), "analyst")
    scopes = tuple((claims.get("scope") or "").split())
    # analyst_id is the JWT subject — the audit trail is keyed on `sub`.
    return Principal(analyst_id=sub, role=role, scopes=scopes, claims=claims)


_validator: JWTValidator | None = None


def get_jwt_validator() -> JWTValidator:
    global _validator
    if _validator is None:
        _validator = JWTValidator()
    return _validator
