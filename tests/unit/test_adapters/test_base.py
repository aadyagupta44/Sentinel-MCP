"""BaseAdapter unit tests — circuit breaker, retry, mock mode."""

import pytest
import respx
from httpx import Response

from sentinel.adapters.base import BaseAdapter, CircuitBreaker, CircuitOpenError, CircuitState


class ConcreteAdapter(BaseAdapter):
    adapter_name = "test_adapter"

    async def fetch(self, url: str) -> dict:  # type: ignore[type-arg]
        resp = await self._call("GET", url, span_name="fetch")
        return resp.json()


class TestCircuitBreaker:
    def test_initial_state_is_closed(self):
        cb = CircuitBreaker(name="test")
        assert cb.state == CircuitState.CLOSED
        assert cb.is_open() is False

    async def test_opens_after_threshold_failures(self):
        cb = CircuitBreaker(failure_threshold=3, name="test")
        for _ in range(3):
            await cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.is_open() is True

    async def test_resets_on_success(self):
        cb = CircuitBreaker(failure_threshold=3, name="test")
        for _ in range(3):
            await cb.record_failure()
        assert cb.is_open()
        await cb.record_success()
        assert cb.state == CircuitState.CLOSED
        assert cb.is_open() is False

    async def test_transitions_to_half_open_after_recovery_timeout(self):
        import time
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01, name="test")
        await cb.record_failure()
        assert cb.is_open()
        # Wait past the recovery timeout
        time.sleep(0.02)
        # Accessing state should transition to HALF_OPEN
        assert cb.state == CircuitState.HALF_OPEN
        assert cb.is_open() is False

    async def test_does_not_open_below_threshold(self):
        cb = CircuitBreaker(failure_threshold=5, name="test")
        for _ in range(4):
            await cb.record_failure()
        assert cb.state == CircuitState.CLOSED


class TestBaseAdapterCircuitBreaker:
    @respx.mock
    async def test_raises_circuit_open_error_when_circuit_is_open(self):
        adapter = ConcreteAdapter()
        # Force circuit open
        for _ in range(5):
            await adapter._breaker.record_failure()
        assert adapter._breaker.is_open()

        with pytest.raises(CircuitOpenError):
            await adapter.fetch("http://example.com/api")

        await adapter.close()

    @respx.mock
    async def test_successful_call_resets_failure_count(self):
        respx.get("http://example.com/api").mock(
            return_value=Response(200, json={"status": "ok"})
        )
        adapter = ConcreteAdapter()
        # Add some failures below threshold
        for _ in range(3):
            await adapter._breaker.record_failure()

        result = await adapter.fetch("http://example.com/api")
        assert result == {"status": "ok"}
        assert adapter._breaker._failure_count == 0

        await adapter.close()

    @respx.mock
    async def test_http_error_increments_failure_count(self):
        from httpx import NetworkError
        respx.get("http://bad-host.invalid/api").mock(side_effect=NetworkError("refused"))

        adapter = ConcreteAdapter()
        initial_failures = adapter._breaker._failure_count

        with pytest.raises(Exception):
            await adapter.fetch("http://bad-host.invalid/api")

        assert adapter._breaker._failure_count > initial_failures
        await adapter.close()


class TestCircuitBreakerConcurrency:
    async def test_concurrent_failures_dont_exceed_threshold(self):
        import asyncio
        cb = CircuitBreaker(failure_threshold=5, name="concurrent_test")

        # Fire 10 concurrent failures
        await asyncio.gather(*[cb.record_failure() for _ in range(10)])

        # State should be OPEN (not some weird intermediate state)
        assert cb.state == CircuitState.OPEN
