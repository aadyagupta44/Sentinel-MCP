"""SecretsProvider abstraction.

Local dev: reads from env vars via Settings.
Production: swap EnvSecretsProvider for an AwsSecretsProvider without
changing any call sites.
"""

from abc import ABC, abstractmethod
from typing import Any

from sentinel.config import Settings, get_settings


class SecretsProvider(ABC):
    @abstractmethod
    async def get(self, key: str) -> str: ...

    @abstractmethod
    async def get_all(self) -> dict[str, Any]: ...


class EnvSecretsProvider(SecretsProvider):
    """Reads secrets from environment variables via Settings."""

    def __init__(self) -> None:
        self._settings: Settings = get_settings()

    async def get(self, key: str) -> str:
        return str(getattr(self._settings, key.lower(), ""))

    async def get_all(self) -> dict[str, Any]:
        return self._settings.model_dump()


_provider: SecretsProvider | None = None


def get_secrets_provider() -> SecretsProvider:
    global _provider
    if _provider is None:
        _provider = EnvSecretsProvider()
    return _provider
