"""Sentinel MCP entry point.

stdio mode  → mcp.run() handles the MCP protocol directly.
HTTP mode   → FastAPI app serves /health, /.well-known/mcp, and mounts
              the MCP streamable-HTTP transport at /mcp.
"""

import time
from contextlib import asynccontextmanager
from typing import Any

import structlog
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from sentinel.config import get_settings
from sentinel.db.session import close_db, init_db
from sentinel.mcp.server import mcp

# Import tool, resource, and prompt modules to trigger @mcp.tool() /
# @mcp.resource() / @mcp.prompt() registration with the FastMCP instance.
# Order matters: server must be imported first (above), then registrations.
import sentinel.tools          # noqa: E402, F401
import sentinel.mcp.resources  # noqa: E402, F401
import sentinel.mcp.prompts    # noqa: E402, F401

logger = structlog.get_logger(__name__)
settings = get_settings()
_start_time = time.time()


# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[type-arg]
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


# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="Sentinel MCP Server",
    description="Production-grade SOC MCP Server",
    version=settings.version,
    lifespan=lifespan,
    docs_url="/docs" if settings.is_development else None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.is_development else [],
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
                "auth_url": (
                    f"{settings.keycloak_url}/realms/{settings.keycloak_realm}"
                    "/protocol/openid-connect/auth"
                ),
            },
            "stdio": {"supported": True},
        },
        "capabilities": {
            "tools": True,
            "resources": True,
            "prompts": True,
        },
    }


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
