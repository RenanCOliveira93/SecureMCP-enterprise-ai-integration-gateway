import httpx
import pytest

from securemcp.errors import ErrorCode, GatewayError
from securemcp.integrations.http import ResilientHttp, RetryPolicy

pytestmark = pytest.mark.anyio


def make(handler, attempts=3):
    sleeps = []

    async def sleep(d):
        sleeps.append(d)

    http = ResilientHttp(
        service="svc",
        base_url="http://svc",
        connect_timeout=1,
        read_timeout=1,
        retry=RetryPolicy(max_attempts=attempts, base_delay=0.2),
        transport=httpx.MockTransport(handler),
        sleep=sleep,
    )
    return http, sleeps


class Seq:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls = 0

    def __call__(self, request):
        self.calls += 1
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


async def test_retries_transient_then_succeeds():
    seq = Seq(httpx.Response(503), httpx.ConnectError("boom"), httpx.Response(200, json={"ok": True}))
    http, sleeps = make(seq)
    response = await http.request("GET", "/x", headers={}, retry_safe=True)
    assert response.json() == {"ok": True} and seq.calls == 3 and len(sleeps) == 2


@pytest.mark.parametrize("status", [400, 401, 403, 404, 409, 422])
async def test_client_errors_are_never_retried(status):
    seq = Seq(httpx.Response(status))
    http, _ = make(seq)
    with pytest.raises(GatewayError) as exc:
        await http.request("POST", "/x", headers={}, retry_safe=True)
    assert exc.value.code is ErrorCode.UPSTREAM_REJECTED and seq.calls == 1


async def test_exhausted_retries_raise_upstream_unavailable():
    seq = Seq(*[httpx.Response(503)] * 3)
    http, _ = make(seq)
    with pytest.raises(GatewayError) as exc:
        await http.request("GET", "/x", headers={}, retry_safe=True)
    assert exc.value.code is ErrorCode.UPSTREAM_UNAVAILABLE and exc.value.retryable and seq.calls == 3


async def test_unsafe_requests_are_sent_once():
    seq = Seq(httpx.Response(503))
    http, _ = make(seq)
    with pytest.raises(GatewayError):
        await http.request("POST", "/x", headers={}, retry_safe=False)
    assert seq.calls == 1


async def test_retry_after_is_honoured_but_capped():
    seq = Seq(httpx.Response(429, headers={"Retry-After": "30"}), httpx.Response(200))
    http, sleeps = make(seq)
    await http.request("GET", "/x", headers={}, retry_safe=True)
    assert sleeps == [2.0]


def test_backoff_has_full_jitter_bounds():
    policy = RetryPolicy(base_delay=0.2)
    assert all(0 <= policy.backoff(1) <= 0.2 for _ in range(50))
    assert all(0 <= policy.backoff(3) <= 0.8 for _ in range(50))
