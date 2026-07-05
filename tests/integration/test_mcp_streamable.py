"""End-to-end tests for the /mcp streamable-HTTP transport.

Closes the long-standing Phase 5 gap: the streamable session was previously
only asserted at the auth boundary (401 without a bearer), never driven through
a real MCP handshake. Here we boot the actual `mcp.streamable_http_app()` ASGI
app in-process (starting its StreamableHTTPSessionManager task group via the
ASGI lifespan protocol) and speak the real protocol over httpx + SSE:

    initialize → notifications/initialized → tools/list → tools/call

so the transport, session lifecycle, SSE framing, session-id enforcement, and
the auth guard are all exercised against the same code that runs in production.

Notes
-----
* The streamable app's DNS-rebinding protection only allows Host = localhost/
  127.0.0.1 *with a port*, so the client base_url must be http://127.0.0.1:8000.
* FastMCP caches a single streamable app whose session manager can be run only
  once per process, so every test shares one module-scoped boot.
"""

import asyncio
import json
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import sentinel.mcp.resources  # noqa: F401  — register @mcp.resource
import sentinel.tools  # noqa: F401  — register @mcp.tool
from sentinel.main import McpAuthMiddleware
from sentinel.mcp.server import mcp

# Host must carry a port to satisfy the transport's allowed-hosts (127.0.0.1:*).
_BASE_URL = "http://127.0.0.1:8000"
_MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


# ── ASGI lifespan runner ──────────────────────────────────────────────────────


@asynccontextmanager
async def _boot(app):
    """Drive the ASGI lifespan protocol so the session-manager task group starts."""
    started = asyncio.Event()
    shutdown = asyncio.Event()
    state = {"startup_sent": False}

    async def receive():
        if not state["startup_sent"]:
            state["startup_sent"] = True
            return {"type": "lifespan.startup"}
        await shutdown.wait()
        return {"type": "lifespan.shutdown"}

    async def send(message):
        if message["type"] == "lifespan.startup.complete":
            started.set()

    task = asyncio.ensure_future(app({"type": "lifespan"}, receive, send))
    await started.wait()
    try:
        yield
    finally:
        shutdown.set()
        await task


def _parse_sse(text: str, want_id=None) -> dict:
    """Return the JSON-RPC payload from an SSE body (matching want_id if given)."""
    payloads = [
        json.loads(line[5:].strip())
        for line in text.splitlines()
        if line.startswith("data:")
    ]
    if want_id is not None:
        for p in payloads:
            if p.get("id") == want_id:
                return p
    return payloads[0] if payloads else {}


async def _initialize(client: AsyncClient):
    """Run the initialize handshake; return (response, session_id)."""
    req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "1.0"},
        },
    }
    resp = await client.post("/mcp", headers=_MCP_HEADERS, json=req)
    return resp, resp.headers.get("mcp-session-id")


async def _session(client: AsyncClient) -> str:
    """Initialize and complete the handshake; return a ready-to-use session id."""
    _, sid = await _initialize(client)
    await client.post(
        "/mcp",
        headers={**_MCP_HEADERS, "mcp-session-id": sid},
        json={"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
    )
    return sid


async def _rpc(client: AsyncClient, sid: str, req_id: int, method: str, params: dict):
    resp = await client.post(
        "/mcp",
        headers={**_MCP_HEADERS, "mcp-session-id": sid},
        json={"jsonrpc": "2.0", "id": req_id, "method": method, "params": params},
    )
    return resp, _parse_sse(resp.text, want_id=req_id)


# ── One shared boot for the whole module ──────────────────────────────────────


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def streamable_client():
    """A booted streamable-HTTP client with infra (audit/rate/OPA) stubbed."""
    app = mcp.streamable_http_app()
    opa = AsyncMock()
    opa.is_allowed = AsyncMock(return_value=(True, "ok"))
    opa.check_rate_limit = AsyncMock(return_value=(True, "ok"))
    with (
        patch("sentinel.mcp.middleware.write_audit_log", new=AsyncMock()),
        patch("sentinel.mcp.middleware._get_rate_count", new=AsyncMock(return_value=0)),
        patch("sentinel.mcp.middleware.get_opa_engine", return_value=opa),
    ):
        async with _boot(app):
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url=_BASE_URL
            ) as client:
                yield client


# ── Tests ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio(loop_scope="module")
class TestStreamableSession:
    async def test_initialize_returns_capabilities_and_session(self, streamable_client):
        resp, sid = await _initialize(streamable_client)
        assert resp.status_code == 200
        assert "text/event-stream" in resp.headers.get("content-type", "")
        assert sid  # server minted a session id
        result = _parse_sse(resp.text, want_id=1)["result"]
        assert result["protocolVersion"]
        assert result["serverInfo"]["name"] == "sentinel-mcp"

    async def test_tools_list_advertises_all_soc_tools(self, streamable_client):
        sid = await _session(streamable_client)
        _, payload = await _rpc(streamable_client, sid, 2, "tools/list", {})
        names = {t["name"] for t in payload["result"]["tools"]}
        # The full advertised toolset must survive the transport round-trip.
        assert len(names) == 18
        assert {"get_alert", "enrich_ioc", "isolate_device", "weekly_summary"} <= names

    async def test_tools_call_executes_through_the_pipeline(self, streamable_client):
        sid = await _session(streamable_client)
        resp, payload = await _rpc(
            streamable_client,
            sid,
            3,
            "tools/call",
            {"name": "get_alert", "arguments": {"alert_id": "ALT-2026-001"}},
        )
        assert resp.status_code == 200
        result = payload["result"]
        assert result.get("isError") is not True
        text = result["content"][0]["text"]
        assert "ALT-2026-001" in text

    async def test_request_without_session_id_is_rejected(self, streamable_client):
        # A tools/list without the mcp-session-id from initialize must not run.
        resp = await streamable_client.post(
            "/mcp",
            headers=_MCP_HEADERS,
            json={"jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": {}},
        )
        assert resp.status_code == 400
        assert "session" in resp.text.lower()


@pytest.mark.asyncio(loop_scope="module")
class TestStreamableAuthGuard:
    async def test_unauthenticated_request_is_rejected_end_to_end(self, streamable_client):
        # Wrap the SAME booted transport in the production auth middleware and
        # confirm an initialize with no bearer is refused before it ever reaches
        # the session manager.
        guarded = McpAuthMiddleware(streamable_client._transport.app)
        async with AsyncClient(
            transport=ASGITransport(app=guarded), base_url=_BASE_URL
        ) as client:
            resp, _ = await _initialize(client)
        assert resp.status_code == 401
        assert resp.json()["code"] == "UNAUTHENTICATED"
