"""Shared pytest fixtures for all tests."""

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
def test_settings():
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
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client


# ── Auth / JWT test helpers (Phase 5) ─────────────────────────────────────────

_TEST_KID = "sentinel-test-key-1"


@pytest.fixture(scope="session")
def rsa_key():
    """A session RSA keypair + matching JWK for signing/validating test JWTs."""
    import json

    import jwt as pyjwt
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    jwk = json.loads(pyjwt.algorithms.RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": _TEST_KID, "alg": "RS256", "use": "sig"})
    return {"private_pem": private_pem, "jwk": jwk, "kid": _TEST_KID}


@pytest.fixture
def jwks_response(rsa_key):
    return {"keys": [rsa_key["jwk"]]}


@pytest.fixture
def make_jwt(rsa_key):
    """Factory: build a signed Keycloak-style access token for tests."""
    import time

    import jwt as pyjwt

    from sentinel.config import get_settings

    def _make(*, sub="u-123", roles=("analyst",), scope="soc:read", **overrides):
        s = get_settings()
        now = int(time.time())
        claims = {
            "sub": sub,
            "iss": s.oidc_issuer,
            "iat": now,
            "exp": now + 300,
            "realm_access": {"roles": list(roles)},
            "scope": scope,
            "preferred_username": sub,
        }
        claims.update(overrides)
        return pyjwt.encode(
            claims, rsa_key["private_pem"], algorithm="RS256", headers={"kid": rsa_key["kid"]}
        )

    return _make


@pytest.fixture
def reset_jwt_validator(monkeypatch):
    """Reset the cached JWTValidator singleton so JWKS is re-fetched (via respx)."""
    monkeypatch.setattr("sentinel.auth.jwt._validator", None)
    yield
    monkeypatch.setattr("sentinel.auth.jwt._validator", None)
