"""PKCE (RFC 7636) helpers for the OAuth 2.1 authorization-code flow.

The client generates a high-entropy `code_verifier`, derives the S256
`code_challenge`, and sends the challenge with the authorization request. On
token exchange it sends the verifier; the authorization server recomputes the
challenge and rejects the exchange if they don't match — binding the issued
token to the client that started the flow.
"""

import base64
import hashlib
import secrets


def _b64url_no_pad(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate_code_verifier(n_bytes: int = 32) -> str:
    """Return a URL-safe code verifier (43–128 chars per RFC 7636)."""
    return _b64url_no_pad(secrets.token_bytes(n_bytes))


def code_challenge_s256(verifier: str) -> str:
    """Derive the S256 code challenge from a verifier."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return _b64url_no_pad(digest)


def generate_state(n_bytes: int = 16) -> str:
    """Return an opaque CSRF state value for the authorization request."""
    return _b64url_no_pad(secrets.token_bytes(n_bytes))
