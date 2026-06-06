"""FastAPI auth dependencies for the HTTP transport.

`require_principal` validates the Bearer JWT and returns the Principal (401 on a
missing/invalid token). `extract_bearer` is the shared header parser, reused by
the /mcp ASGI guard.
"""

from fastapi import Header, HTTPException, status

from sentinel.auth.context import Principal
from sentinel.auth.jwt import InvalidTokenError, get_jwt_validator

_UNAUTH_HEADERS = {"WWW-Authenticate": "Bearer"}


def extract_bearer(authorization: str | None) -> str | None:
    if not authorization:
        return None
    parts = authorization.split(" ", 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        return None
    return parts[1].strip()


async def require_principal(authorization: str | None = Header(default=None)) -> Principal:
    token = extract_bearer(authorization)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "Missing or malformed Bearer token", "code": "UNAUTHENTICATED"},
            headers=_UNAUTH_HEADERS,
        )
    try:
        return await get_jwt_validator().principal(token)
    except InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": f"Invalid token: {exc}", "code": "INVALID_TOKEN"},
            headers=_UNAUTH_HEADERS,
        ) from exc
