"""Sentinel MCP entry point.

stdio mode  → mcp.run() handles the MCP protocol directly (trusted local process,
              no auth — the static settings identity is used).
HTTP mode   → FastAPI app. OAuth 2.1 + PKCE via Keycloak, RS256 JWT validation on
              every tool call, the MCP streamable-HTTP transport mounted at /mcp,
              and an authenticated REST tool surface at /tools/{name}.
"""

import json
import time
from contextlib import asynccontextmanager
from typing import Any

import structlog
import uvicorn
from fastapi import Body, Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Import tool, resource, and prompt modules to trigger @mcp.tool() /
# @mcp.resource() / @mcp.prompt() registration with the FastMCP instance.
import sentinel.mcp.prompts  # noqa: E402, F401
import sentinel.mcp.resources  # noqa: E402, F401
import sentinel.tools  # noqa: E402, F401
from sentinel.auth import (
    InvalidTokenError,
    Principal,
    authorize,
    code_challenge_s256,
    generate_code_verifier,
    generate_state,
    get_jwt_validator,
    get_oauth_client,
    require_principal,
    reset_current_principal,
    set_current_principal,
)
from sentinel.auth.dependencies import extract_bearer
from sentinel.config import get_settings
from sentinel.db.session import close_db, init_db
from sentinel.mcp.server import mcp

logger = structlog.get_logger(__name__)
settings = get_settings()
_start_time = time.time()


# ── Lifespan ──────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[type-arg]
    # Fail fast on an unsafe production configuration (auth off, mock adapters
    # on, placeholder secrets) rather than discovering it at first request.
    problems = settings.validate_runtime()
    if problems:
        raise RuntimeError("Unsafe configuration for environment: " + "; ".join(problems))
    logger.info(
        "sentinel_starting",
        version=settings.version,
        transport=settings.mcp_transport,
        environment=settings.environment,
        mock_adapters=settings.mock_adapters,
    )
    await init_db()
    yield
    await close_db()
    logger.info("sentinel_stopped")


# ── MCP HTTP-transport auth guard (pure ASGI — preserves contextvars) ─────────


class McpAuthMiddleware:
    """Require a valid Bearer JWT on the /mcp transport and bind the principal."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        if (
            scope["type"] != "http"
            or scope.get("method") == "OPTIONS"
            or not scope.get("path", "").startswith("/mcp")
        ):
            await self.app(scope, receive, send)
            return

        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        token = extract_bearer(headers.get("authorization"))
        principal: Principal | None = None
        if token:
            try:
                principal = await get_jwt_validator().principal(token)
            except InvalidTokenError:
                principal = None

        if principal is None:
            response = JSONResponse(
                {
                    "error": "Authentication required for the MCP HTTP transport",
                    "code": "UNAUTHENTICATED",
                },
                status_code=status.HTTP_401_UNAUTHORIZED,
                headers={"WWW-Authenticate": "Bearer"},
            )
            await response(scope, receive, send)
            return

        ctx = set_current_principal(principal)
        try:
            await self.app(scope, receive, send)
        finally:
            reset_current_principal(ctx)


# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="Sentinel MCP Server",
    description="Production-grade SOC MCP Server",
    version=settings.version,
    lifespan=lifespan,
    docs_url="/docs" if settings.is_development else None,
    redoc_url=None,
)

# Even in dev, scope CORS to explicit localhost origins rather than "*" so a
# reachable dev instance can't be driven cross-origin. Production defaults to
# no cross-origin allowance (same-origin only).
_DEV_CORS_ORIGINS = [
    "http://localhost",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:3000",
]

app.add_middleware(McpAuthMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_DEV_CORS_ORIGINS if settings.is_development else [],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Mcp-Session-Id"],
)


# ── Health endpoint (marketplace required) ────────────────────────────────────


@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status": "healthy",
        "version": settings.version,
        "uptime_seconds": int(time.time() - _start_time),
        "environment": settings.environment,
        "transport": settings.mcp_transport,
        "mock_adapters": settings.mock_adapters,
    }


# ── MCP manifest (marketplace required) ──────────────────────────────────────


@app.get("/.well-known/mcp")
async def mcp_manifest() -> dict[str, Any]:
    return {
        "name": "sentinel-mcp",
        "version": settings.version,
        "description": (
            "Production-grade SOC MCP Server. Gives Claude Desktop "
            "secure, policy-enforced access to your security toolstack: "
            "SIEM alerts, threat intelligence, identity data, and EDR telemetry."
        ),
        "transport": {
            "http": {
                "url": f"http://localhost:{settings.http_port}/mcp",
                "auth": "oauth2_pkce",
                "authorization_endpoint": settings.oidc_authorize_endpoint,
                "token_endpoint": settings.oidc_token_endpoint,
                "scopes": settings.oauth_default_scopes.split(),
            },
            "stdio": {"supported": True},
        },
        "capabilities": {"tools": True, "resources": True, "prompts": True},
    }


@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata() -> dict[str, Any]:
    return {
        "issuer": settings.oidc_issuer,
        "authorization_endpoint": settings.oidc_authorize_endpoint,
        "token_endpoint": settings.oidc_token_endpoint,
        "jwks_uri": settings.oidc_jwks_uri,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": settings.oauth_default_scopes.split(),
    }


# ── OAuth 2.1 + PKCE flow helpers ─────────────────────────────────────────────


@app.get("/auth/login")
async def auth_login() -> dict[str, Any]:
    """Begin the OAuth 2.1 + PKCE flow.

    Returns the authorization URL plus the PKCE code_verifier and state. The
    caller redirects the user to authorization_url, keeps code_verifier, and
    later posts the returned `code` (with the verifier) to /auth/token.
    """
    verifier = generate_code_verifier()
    challenge = code_challenge_s256(verifier)
    state = generate_state()
    url = get_oauth_client().authorization_url(code_challenge=challenge, state=state)
    return {"authorization_url": url, "code_verifier": verifier, "state": state}


@app.post("/auth/token")
async def auth_token(payload: dict[str, Any] = Body(...)) -> dict[str, Any]:
    """Exchange an authorization code + PKCE verifier for tokens."""
    code = str(payload.get("code", "")).strip()
    code_verifier = str(payload.get("code_verifier", "")).strip()
    if not code or not code_verifier:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "code and code_verifier are required", "code": "INVALID_REQUEST"},
        )
    tokens = await get_oauth_client().exchange_code(
        code=code,
        code_verifier=code_verifier,
        redirect_uri=payload.get("redirect_uri"),
    )
    if "error" in tokens:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=tokens)
    return tokens


# ── Authenticated REST tool surface ───────────────────────────────────────────


@app.post("/tools/{tool_name}")
async def call_tool_http(
    tool_name: str,
    arguments: dict[str, Any] = Body(default_factory=dict),
    principal: Principal = Depends(require_principal),
) -> Any:
    """Invoke a SOC tool over HTTP. Requires a Bearer JWT with the right scope/role."""
    allowed, reason = authorize(principal, tool_name)
    if not allowed:
        code = status.HTTP_404_NOT_FOUND if reason == "unknown_tool" else status.HTTP_403_FORBIDDEN
        raise HTTPException(
            status_code=code,
            detail={"error": "Authorization denied", "code": "FORBIDDEN", "reason": reason},
        )

    ctx = set_current_principal(principal)
    try:
        result = await mcp.call_tool(tool_name, arguments)
    except Exception as exc:  # unknown tool / dispatch error
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": str(exc), "code": "TOOL_ERROR"},
        ) from exc
    finally:
        reset_current_principal(ctx)

    content = result[0] if isinstance(result, tuple) else result
    return json.loads(content[0].text)


# ── Mount MCP (HTTP transport only) ──────────────────────────────────────────

if settings.mcp_transport == "http":
    app.mount("/mcp", mcp.streamable_http_app())


# ── Entry point ───────────────────────────────────────────────────────────────


def main() -> None:
    if settings.mcp_transport == "stdio":
        mcp.run(transport="stdio")
    else:
        uvicorn.run(
            "sentinel.main:app",
            host=settings.http_host,
            port=settings.http_port,
            log_level=settings.log_level.lower(),
            access_log=settings.is_development,
        )


if __name__ == "__main__":
    main()
