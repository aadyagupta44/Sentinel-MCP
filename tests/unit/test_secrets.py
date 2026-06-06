"""SecretsProvider tests."""

import pytest

from sentinel.secrets import EnvSecretsProvider, get_secrets_provider


class TestEnvSecretsProvider:
    async def test_get_known_key(self):
        provider = EnvSecretsProvider()
        val = await provider.get("analyst_id")
        assert isinstance(val, str)

    async def test_get_unknown_key_returns_empty_string(self):
        provider = EnvSecretsProvider()
        val = await provider.get("nonexistent_key_xyz")
        assert val == ""

    async def test_get_all_returns_dict(self):
        provider = EnvSecretsProvider()
        all_vals = await provider.get_all()
        assert isinstance(all_vals, dict)
        assert "analyst_id" in all_vals

    def test_get_secrets_provider_returns_env_provider(self):
        from sentinel.secrets import _provider
        import sentinel.secrets as secrets_module
        secrets_module._provider = None  # reset singleton
        provider = get_secrets_provider()
        assert isinstance(provider, EnvSecretsProvider)
        secrets_module._provider = None  # clean up
