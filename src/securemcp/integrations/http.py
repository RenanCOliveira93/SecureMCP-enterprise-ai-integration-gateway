"""Outbound HTTP with timeouts and retries for transient failures only (ADR-0008)."""

from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx
from opentelemetry import trace
from opentelemetry.propagate import inject

from securemcp.errors import ErrorCode, GatewayError

log = logging.getLogger(__name__)
tracer = trace.get_tracer("securemcp.integrations")

TRANSIENT_STATUS = frozenset({429, 502, 503, 504})


class TransientUpstreamError(Exception):
    def __init__(self, reason: str, retry_after: float | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.retry_after = retry_after


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    base_delay: float = 0.2
    max_retry_after: float = 2.0

    def backoff(self, attempt: int) -> float:
        # Full jitter: uniform(0, base * 2^(attempt-1)).
        return random.uniform(0, self.base_delay * (2 ** (attempt - 1)))  # noqa: S311 - jitter, not crypto


class ResilientHttp:
    def __init__(
        self,
        *,
        service: str,
        base_url: str,
        connect_timeout: float,
        read_timeout: float,
        retry: RetryPolicy,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self.service = service
        self.retry = retry
        self.sleep = sleep
        self.client = httpx.AsyncClient(
            base_url=base_url,
            timeout=httpx.Timeout(read_timeout, connect=connect_timeout),
            transport=transport,
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        await self.client.aclose()

    async def request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str],
        json: Any = None,
        retry_safe: bool,
    ) -> httpx.Response:
        """Send a request. ``retry_safe`` must be False for non-idempotent calls without an idempotency key."""
        attempts = self.retry.max_attempts if retry_safe else 1
        last: TransientUpstreamError | None = None
        for attempt in range(1, attempts + 1):
            started = time.monotonic()
            with tracer.start_as_current_span(f"{self.service} {method}") as span:
                span.set_attribute("securemcp.upstream", self.service)
                span.set_attribute("securemcp.attempt", attempt)
                outgoing = dict(headers)
                inject(outgoing)  # W3C traceparent for downstream correlation
                try:
                    response = await self.client.request(method, path, headers=outgoing, json=json)
                except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout, httpx.RemoteProtocolError) as exc:
                    last = TransientUpstreamError(type(exc).__name__)
                else:
                    span.set_attribute("http.response.status_code", response.status_code)
                    if response.status_code not in TRANSIENT_STATUS:
                        if response.status_code >= 400:
                            log.info("%s rejected request: HTTP %s", self.service, response.status_code)
                            raise GatewayError(ErrorCode.UPSTREAM_REJECTED, f"{self.service} rejected the request")
                        return response
                    retry_after = _parse_retry_after(response.headers.get("retry-after"))
                    last = TransientUpstreamError(f"HTTP {response.status_code}", retry_after)
                span.set_attribute("securemcp.transient_error", last.reason)
            log.info(
                "%s transient failure (%s) attempt %d/%d in %.0f ms",
                self.service,
                last.reason,
                attempt,
                attempts,
                (time.monotonic() - started) * 1000,
            )
            if attempt < attempts:
                delay = self.retry.backoff(attempt)
                if last.retry_after is not None:
                    delay = max(delay, min(last.retry_after, self.retry.max_retry_after))
                await self.sleep(delay)
        raise GatewayError(ErrorCode.UPSTREAM_UNAVAILABLE, f"{self.service} is unavailable, retry later")


def _parse_retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        return None
