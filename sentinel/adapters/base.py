"""BaseAdapter — every external integration extends this class.

Provides:
- httpx.AsyncClient with sensible timeouts
- tenacity retry (3 attempts, exponential backoff, network errors only)
- Circuit breaker (opens after 5 failures, resets after 60s)
- OpenTelemetry child span per call
- structlog request/response logging (never logs full bodies)
- Mock mode: subclasses override `_mock_response` to return fake data
"""

import asyncio
import time
from abc import ABC, abstractmethod
from enum import Enum
from typing import Any

import httpx
import structlog
from opentelemetry import trace
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from sentinel.config import get_settings

tracer = trace.get_tracer("sentinel.adapters")


class CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitOpenError(Exception):
    """Raised when a call is attempted while the circuit is open."""


class CircuitBreaker:
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        name: str = "unnamed",
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.name = name
        self._failure_count: int = 0
        self._last_failure_time: float = 0.0
        self._state: CircuitState = CircuitState.CLOSED
        self._lock = asyncio.Lock()

    @property
    def state(self) -> CircuitState:
        if self._state == CircuitState.OPEN:
            if time.monotonic() - self._last_failure_time > self.recovery_timeout:
                self._state = CircuitState.HALF_OPEN
        return self._state

    def is_open(self) -> bool:
        return self.state == CircuitState.OPEN

    async def record_success(self) -> None:
        async with self._lock:
            self._failure_count = 0
            self._state = CircuitState.CLOSED

    async def record_failure(self) -> None:
        async with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.monotonic()
            if self._failure_count >= self.failure_threshold:
                old_state = self._state
                self._state = CircuitState.OPEN
                if old_state != CircuitState.OPEN:
                    structlog.get_logger(__name__).warning(
                        "circuit_breaker_opened",
                        adapter=self.name,
                        failures=self._failure_count,
                    )

    def reset(self) -> None:
        self._failure_count = 0
        self._state = CircuitState.CLOSED


class BaseAdapter(ABC):
    """Base class for all external service adapters."""

    adapter_name: str = "base"

    def __init__(self) -> None:
        self._settings = get_settings()
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=5.0),
            follow_redirects=True,
        )
        self._breaker = CircuitBreaker(name=self.adapter_name)
        self._log = structlog.get_logger(f"sentinel.adapters.{self.adapter_name}")

    @property
    def is_mock(self) -> bool:
        return self._settings.mock_adapters

    async def _call(
        self,
        method: str,
        url: str,
        span_name: str,
        **kwargs: Any,
    ) -> httpx.Response:
        """Execute an HTTP call with circuit breaker, retry, and tracing."""
        if self._breaker.is_open():
            self._log.warning("circuit_open_skipping_call", url=url, adapter=self.adapter_name)
            raise CircuitOpenError(f"{self.adapter_name} circuit breaker is open")

        with tracer.start_as_current_span(
            f"{self.adapter_name}.{span_name}",
            kind=trace.SpanKind.CLIENT,
        ) as span:
            span.set_attribute("http.url", url)
            span.set_attribute("http.method", method.upper())
            span.set_attribute("adapter.name", self.adapter_name)

            try:
                resp = await self._retry_request(method, url, **kwargs)
                span.set_attribute("http.status_code", resp.status_code)
                await self._breaker.record_success()
                return resp
            except Exception as exc:
                span.record_exception(exc)
                await self._breaker.record_failure()
                raise

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.NetworkError)),
        reraise=True,
    )
    async def _retry_request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        self._log.debug("adapter_request", method=method.upper(), url=url)
        resp = await self._client.request(method, url, **kwargs)
        self._log.debug("adapter_response", status=resp.status_code, url=url)
        return resp

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "BaseAdapter":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()
