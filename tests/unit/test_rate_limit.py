from securemcp.security.policy import Bucket, RateLimits
from securemcp.security.rate_limit import InMemoryRateLimiter
from tests.helpers import principal


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def limiter(clock, read=3, write=1, tenant=100):
    limits = RateLimits(
        read=Bucket(capacity=read, refill_per_second=1),
        write=Bucket(capacity=write, refill_per_second=0.5),
        tenant=Bucket(capacity=tenant, refill_per_second=1),
    )
    return InMemoryRateLimiter(limits, clock=clock)


def test_burst_then_refill():
    clock = Clock()
    rl = limiter(clock)
    p = principal("ana")
    assert all(rl.check(p, "read").allowed for _ in range(3))
    denied = rl.check(p, "read")
    assert not denied.allowed and 0 < denied.retry_after_seconds <= 1
    clock.t += 1.0
    assert rl.check(p, "read").allowed


def test_write_bucket_is_separate_and_stricter():
    rl = limiter(Clock())
    p = principal("bruno")
    assert rl.check(p, "write").allowed
    assert not rl.check(p, "write").allowed
    assert rl.check(p, "read").allowed


def test_subjects_are_isolated_but_tenant_bucket_is_shared():
    rl = limiter(Clock(), read=2, tenant=3)
    a, b = principal("ana"), principal("bruno")
    assert rl.check(a, "read").allowed and rl.check(a, "read").allowed
    assert rl.check(b, "read").allowed
    d = rl.check(b, "read")
    assert not d.allowed and d.bucket == "tenant:read"
    assert rl.check(principal("eva"), "read").allowed  # other tenant unaffected


def test_denied_request_consumes_nothing():
    clock = Clock()
    rl = limiter(clock, read=1, tenant=1)
    p = principal("ana")
    assert rl.check(p, "read").allowed
    for _ in range(5):
        assert not rl.check(p, "read").allowed
    clock.t += 1.0
    assert rl.check(p, "read").allowed
