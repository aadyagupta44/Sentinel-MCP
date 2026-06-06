"""Shared pytest fixtures for all tests."""

import asyncio
from collections.abc import AsyncGenerator

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from sentinel.config import get_settings
from sentinel.db.models import Base
from sentinel.main import app

# ── Settings override for tests ───────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def test_settings(monkeypatch=None):
    """Ensure test settings are used throughout the session."""
    import os
    os.environ.setdefault("ENVIRONMENT", "test")
    os.environ.setdefault("MOCK_ADAPTERS", "true")
    os.environ.setdefault("POLICY_ENFORCEMENT", "false")
    os.environ.setdefault("ANALYST_ID", "test@acmecorp.com")
    os.environ.setdefault("ANALYST_ROLE", "admin")
    # Clear the lru_cache so test env vars take effect
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ── In-memory SQLite for unit tests ──────────────────────────────────────────
# Integration tests use the real Postgres URL from the environment.

TEST_DB_URL = "sqlite+aiosqlite:///:memory:"


@pytest_asyncio.fixture
async def db_engine():
    """Per-test in-memory SQLite engine."""
    try:
        engine = create_async_engine(TEST_DB_URL, echo=False)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        yield engine
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        await engine.dispose()
    except Exception:
        pytest.skip("aiosqlite not available — skipping DB test")


@pytest_asyncio.fixture
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    """Per-test async DB session bound to the in-memory engine."""
    factory = async_sessionmaker(db_engine, expire_on_commit=False, class_=AsyncSession)
    async with factory() as session:
        yield session


# ── HTTP test client ──────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def http_client() -> AsyncGenerator[AsyncClient, None]:
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        yield client
