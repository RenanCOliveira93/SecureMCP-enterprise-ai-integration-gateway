import pytest

from securemcp.config import Settings
from securemcp.security.policy import Bucket, RateLimits
from securemcp.security.rate_limit import InMemoryRateLimiter
from tests.helpers import As, error_of

pytestmark = pytest.mark.anyio

NOTIFY = {
    "client_id": "cli_aur001",
    "template": "ticket_update",
    "reference_id": "tkt_aur00001",
    "audience": "primary_contact",
    "channel": "email",
    "idempotency_key": "resilience-key-00001",
}


async def test_external_service_unavailable(mcp, mock_state):
    mock_state.faults["notifications"].mode = "unavailable"
    with As("carla"):
        r = await mcp.call_tool("send_notification", NOTIFY)
    err = error_of(r)
    assert err["code"] == "UPSTREAM_UNAVAILABLE" and err["retryable"] is True
    assert mock_state.requests["notifications"] == 3  # bounded retries


async def test_transient_failures_recover_transparently(mcp, mock_state):
    mock_state.faults["notifications"].mode = "flaky"
    mock_state.faults["notifications"].failures_remaining = 2
    with As("carla"):
        r = await mcp.call_tool("send_notification", NOTIFY)
    assert r.structured_content["status"] == "completed" and mock_state.requests["notifications"] == 3
    assert len(mock_state.deliveries) == 1


async def test_upstream_rejection_is_not_retried(mcp, mock_state):
    mock_state.faults["notifications"].mode = "reject"
    with As("carla"):
        r = await mcp.call_tool("send_notification", NOTIFY)
    assert error_of(r)["code"] == "UPSTREAM_REJECTED" and error_of(r)["retryable"] is False
    assert mock_state.requests["notifications"] == 1


async def test_timeout(container, mcp, mock_state):
    container.policy.timeout_for = lambda name: 0.3  # tighten the deadline for the test
    mock_state.faults["notifications"].mode = "slow"
    mock_state.faults["notifications"].delay_seconds = 2.0
    with As("carla"):
        r = await mcp.call_tool("send_notification", NOTIFY)
    err = error_of(r)
    assert err["code"] == "TIMEOUT" and err["retryable"] is True


async def test_rate_limit(container, mcp):
    tight = RateLimits(
        read=Bucket(capacity=3, refill_per_second=0.01),
        write=Bucket(capacity=1, refill_per_second=0.01),
        tenant=Bucket(capacity=100, refill_per_second=1),
    )
    container.gateway.rate_limiter = InMemoryRateLimiter(tight)
    with As("ana"):
        results = [await mcp.call_tool("get_client", {"client_id": "cli_aur003"}) for _ in range(5)]
    assert [r.is_error for r in results] == [False, False, False, True, True]
    err = error_of(results[-1])
    assert err["code"] == "RATE_LIMITED" and err["retry_after_seconds"] > 0
    with As("eva"):  # other tenants and users are not affected
        assert not (await mcp.call_tool("get_client", {"client_id": "cli_bor001"})).is_error


def test_settings_defaults_are_bounded():
    s = Settings(_env_file=None)
    assert s.http_read_timeout_seconds <= 5 and s.http_max_attempts <= 5
