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
        respx.get("http://example.com/api").mock(return_value=Response(200, json={"status": "ok"}))
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

        with pytest.raises(NetworkError):
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

    async def test_reset_clears_failures_and_closes(self):
        cb = CircuitBreaker(failure_threshold=2, name="reset_test")
        for _ in range(2):
            await cb.record_failure()
        assert cb.is_open()
        cb.reset()
        assert cb.state == CircuitState.CLOSED
        assert cb._failure_count == 0


class TestBaseAdapterContextManager:
    async def test_async_context_manager_enters_and_closes(self):
        async with ConcreteAdapter() as adapter:
            assert isinstance(adapter, ConcreteAdapter)
            assert adapter._client.is_closed is False
        # __aexit__ must have closed the underlying client
        assert adapter._client.is_closed is True


class TestBreakerOnHttpErrors:
    async def test_5xx_responses_open_the_breaker(self, respx_mock):
        respx_mock.get("http://svc.test/api").mock(return_value=Response(500, json={}))
        adapter = ConcreteAdapter()
        for _ in range(5):
            await adapter.fetch("http://svc.test/api")  # graceful — returns body
        assert adapter._breaker.is_open()
        with pytest.raises(CircuitOpenError):
            await adapter.fetch("http://svc.test/api")
        await adapter.close()

    async def test_429_responses_open_the_breaker(self, respx_mock):
        respx_mock.get("http://svc.test/api").mock(return_value=Response(429, json={}))
        adapter = ConcreteAdapter()
        for _ in range(5):
            await adapter.fetch("http://svc.test/api")
        assert adapter._breaker.is_open()
        await adapter.close()

    async def test_2xx_and_404_do_not_open_the_breaker(self, respx_mock):
        respx_mock.get("http://svc.test/ok").mock(return_value=Response(200, json={"ok": True}))
        respx_mock.get("http://svc.test/missing").mock(return_value=Response(404, json={}))
        adapter = ConcreteAdapter()
        for _ in range(5):
            await adapter.fetch("http://svc.test/ok")
            await adapter.fetch("http://svc.test/missing")
        assert adapter._breaker.is_open() is False
        await adapter.close()


class TestRetryPolicyTiming:
    """Assert the retry/backoff *policy* directly (Phase 3 gap).

    The suite neutralises asyncio.sleep for speed, so backoff timing is never
    exercised behaviorally. These tests inspect the tenacity policy attached to
    _retry_request so a regression in the wait schedule / attempt cap / retried
    exception set actually fails a test.
    """

    def _retrying(self):
        # tenacity attaches the controller as `.retry` on the wrapped coroutine
        return BaseAdapter._retry_request.retry

    def test_stops_after_three_attempts(self):
        controller = self._retrying()
        assert controller.stop.max_attempt_number == 3

    def test_exponential_backoff_sequence_is_capped_at_10(self):
        wait = self._retrying().wait  # wait_exponential(multiplier=1, min=1, max=10)

        class _State:
            def __init__(self, n: int) -> None:
                self.attempt_number = n

        # 1s, 2s, 4s, 8s, then capped at 10s (would be 16s uncapped)
        assert wait(_State(1)) == 1
        assert wait(_State(2)) == 2
        assert wait(_State(3)) == 4
        assert wait(_State(4)) == 8
        assert wait(_State(5)) == 10

    def test_only_retries_network_and_timeout_errors(self):
        import httpx

        retry_predicate = self._retrying().retry
        types = retry_predicate.exception_types
        assert httpx.TimeoutException in types
        assert httpx.NetworkError in types
        # A plain HTTP 500 (HTTPStatusError) is NOT a transport error → not retried
        assert not issubclass(httpx.HTTPStatusError, tuple(types))


class TestStateReadIsPure:
    def test_state_read_does_not_mutate_underlying_state(self):
        import time as _time

        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01, name="pure")
        cb._failure_count = 1
        cb._state = CircuitState.OPEN
        cb._last_failure_time = _time.monotonic()
        _time.sleep(0.02)
        # Reading reports HALF_OPEN once the window elapses…
        assert cb.state == CircuitState.HALF_OPEN
        # …but does NOT mutate the stored state (no side effect in the getter).
        assert cb._state == CircuitState.OPEN
