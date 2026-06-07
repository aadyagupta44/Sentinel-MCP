"""Authentication & authorization for the HTTP transport.

OAuth 2.1 authorization-code + PKCE against Keycloak, RS256 JWT validation,
and scope/role authorization. On stdio (trusted local process) auth is not
applied and the static settings identity is used.
"""

from sentinel.auth.authz import authorize, required_scope
from sentinel.auth.context import (
    Principal,
    get_current_principal,
    reset_current_principal,
    set_current_principal,
)
from sentinel.auth.dependencies import require_principal
from sentinel.auth.jwt import InvalidTokenError, get_jwt_validator, principal_from_claims
from sentinel.auth.oauth import get_oauth_client
from sentinel.auth.pkce import code_challenge_s256, generate_code_verifier, generate_state

__all__ = [
    "Principal",
    "authorize",
    "required_scope",
    "get_current_principal",
    "set_current_principal",
    "reset_current_principal",
    "require_principal",
    "get_jwt_validator",
    "principal_from_claims",
    "InvalidTokenError",
    "get_oauth_client",
    "generate_code_verifier",
    "code_challenge_s256",
    "generate_state",
]
