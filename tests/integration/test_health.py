"""Health endpoint and MCP manifest integration tests.

These tests use the FastAPI test client and do not require any external
services (mock_adapters=true, policy_enforcement=false).
"""

import pytest
from httpx import ASGITransport, AsyncClient

from sentinel.main import app


@pytest.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as c:
        yield c


class TestHealthEndpoint:
    async def test_health_returns_200(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200

    async def test_health_response_schema(self, client):
        resp = await client.get("/health")
        body = resp.json()
        assert body["status"] == "healthy"
        assert "version" in body
        assert "uptime_seconds" in body
        assert "environment" in body
        assert "transport" in body
        assert isinstance(body["uptime_seconds"], int)
        assert body["uptime_seconds"] >= 0

    async def test_health_version_matches_package(self, client):
        from sentinel import __version__
        resp = await client.get("/health")
        assert resp.json()["version"] == __version__


class TestMCPManifest:
    async def test_manifest_returns_200(self, client):
        resp = await client.get("/.well-known/mcp")
        assert resp.status_code == 200

    async def test_manifest_schema(self, client):
        resp = await client.get("/.well-known/mcp")
        body = resp.json()
        assert body["name"] == "sentinel-mcp"
        assert "version" in body
        assert "description" in body
        assert "transport" in body
        assert "capabilities" in body

    async def test_manifest_capabilities(self, client):
        resp = await client.get("/.well-known/mcp")
        caps = resp.json()["capabilities"]
        assert caps["tools"] is True
        assert caps["resources"] is True
        assert caps["prompts"] is True

    async def test_unknown_path_returns_404(self, client):
        resp = await client.get("/nonexistent")
        assert resp.status_code == 404
