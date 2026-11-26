"""Token-bucket rate limiting (ADR-0009). In-process; swap the implementation for Redis when scaling out."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from threading import Lock
from typing import Protocol

from securemcp.security.identity import Principal
from securemcp.security.policy import Bucket, RateLimits


@dataclass(frozen=True)
class RateDecision:
    allowed: bool
    retry_after_seconds: float = 0.0
    bucket: str = ""


class RateLimiter(Protocol):
    def check(self, principal: Principal, op_class: str) -> RateDecision: ...


class _TokenBucket:
    __slots__ = ("capacity", "rate", "tokens", "updated")

    def __init__(self, cfg: Bucket, now: float) -> None:
        self.capacity = float(cfg.capacity)
        self.rate = cfg.refill_per_second
        self.tokens = float(cfg.capacity)
        self.updated = now

    def _refill(self, now: float) -> None:
        self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
        self.updated = now

    def available(self, now: float) -> float:
        self._refill(now)
        return self.tokens

    def wait_time(self) -> float:
        return max(0.0, (1.0 - self.tokens) / self.rate)


class InMemoryRateLimiter:
    """Checks the subject bucket for the operation class and the tenant bucket; consumes from both or neither."""

    def __init__(self, limits: RateLimits, clock: Callable[[], float] = time.monotonic) -> None:
        self.limits = limits
        self.clock = clock
        self._buckets: dict[tuple[str, ...], _TokenBucket] = {}
        self._lock = Lock()

    def _bucket(self, key: tuple[str, ...], cfg: Bucket, now: float) -> _TokenBucket:
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = self._buckets[key] = _TokenBucket(cfg, now)
        return bucket

    def check(self, principal: Principal, op_class: str) -> RateDecision:
        cfg = self.limits.write if op_class == "write" else self.limits.read
        now = self.clock()
        with self._lock:
            subject = self._bucket(("subject", principal.tenant_id, principal.subject, op_class), cfg, now)
            tenant = self._bucket(("tenant", principal.tenant_id), self.limits.tenant, now)
            for name, bucket in (("subject", subject), ("tenant", tenant)):
                if bucket.available(now) < 1.0:
                    return RateDecision(False, bucket.wait_time(), f"{name}:{op_class}")
            subject.tokens -= 1.0
            tenant.tokens -= 1.0
            return RateDecision(True)
