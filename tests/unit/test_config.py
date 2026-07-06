"""Settings.validate_runtime() — production safety guard."""

from sentinel.config import Settings


def _settings(**over):
    base = {
        "environment": "production",
        "policy_enforcement": True,
        "mock_adapters": False,
        "database_url": "postgresql+asyncpg://u:p@db.internal:5432/sentinel",
        "keycloak_url": "https://sso.acme.com",
        "mcp_transport": "stdio",
    }
    base.update(over)
    return Settings(**base)


def test_safe_production_config_has_no_problems():
    assert _settings().validate_runtime() == []


def test_dev_environment_is_never_blocked():
    s = _settings(
        environment="development",
        policy_enforcement=False,
        mock_adapters=True,
        database_url="postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel",
    )
    assert s.validate_runtime() == []


def test_production_rejects_policy_disabled():
    problems = _settings(policy_enforcement=False).validate_runtime()
    assert any("POLICY_ENFORCEMENT" in p for p in problems)


def test_production_rejects_mock_adapters():
    problems = _settings(mock_adapters=True).validate_runtime()
    assert any("MOCK_ADAPTERS" in p for p in problems)


def test_demo_mode_permits_mock_adapters_in_production():
    # The public demo runs production-hardened (auth/policy/audit real) but with
    # simulated data; DEMO_MODE=true is the explicit opt-in that allows it.
    problems = _settings(mock_adapters=True, demo_mode=True).validate_runtime()
    assert not any("MOCK_ADAPTERS" in p for p in problems)
    assert problems == []


def test_demo_mode_relaxes_localhost_for_colocated_stack():
    # The single-container demo co-locates Postgres/Keycloak on localhost, so
    # demo mode relaxes those two checks (but nothing else).
    problems = _settings(
        mock_adapters=True,
        demo_mode=True,
        mcp_transport="http",
        database_url="postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel",
        keycloak_url="http://localhost:8080",
    ).validate_runtime()
    assert problems == []


def test_demo_mode_still_enforces_policy_enforcement():
    # Demo mode does NOT weaken authorization — policy enforcement is still required.
    problems = _settings(
        mock_adapters=True, demo_mode=True, policy_enforcement=False
    ).validate_runtime()
    assert any("POLICY_ENFORCEMENT" in p for p in problems)


def test_production_rejects_localhost_database():
    problems = _settings(
        database_url="postgresql+asyncpg://sentinel:sentinel@localhost:5432/sentinel"
    ).validate_runtime()
    assert any("DATABASE_URL" in p for p in problems)


def test_production_http_rejects_localhost_keycloak():
    problems = _settings(
        mcp_transport="http", keycloak_url="http://localhost:8080"
    ).validate_runtime()
    assert any("KEYCLOAK_URL" in p for p in problems)
