"""Shared fixtures for adapter unit tests.

Every adapter test runs against respx-mocked HTTP (or mocked sockets / SDK) —
no test makes a real network call.

Fixtures:
- ``_fast_retry`` (autouse): neutralises ``asyncio.sleep`` so tenacity's
  exponential backoff and any token-bucket waits are instant. Keeps the
  failure/retry/circuit-breaker tests fast.
- ``live_mode``: flips ``MOCK_ADAPTERS`` off and clears the settings cache so an
  adapter constructed inside the test exercises its real HTTP code path. Restored
  on teardown so mock-mode (the suite default) is back for every other test.
"""

import asyncio

import pytest

from sentinel.config import get_settings


@pytest.fixture(autouse=True)
def _fast_retry(monkeypatch):
    """Make tenacity backoff + token-bucket sleeps instant for adapter tests."""

    async def _noop(*_args, **_kwargs):
        return None

    monkeypatch.setattr(asyncio, "sleep", _noop)


@pytest.fixture
def live_mode(monkeypatch):
    """Construct adapters in live (non-mock) mode for the duration of a test."""
    monkeypatch.setenv("MOCK_ADAPTERS", "false")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
