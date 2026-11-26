import asyncio

import pytest
from sqlalchemy import func, select

from securemcp.db.models import SupportTicket
from tests.helpers import As, error_of

pytestmark = pytest.mark.anyio

ARGS = {
    "client_id": "cli_aur002",
    "subject": "Queue counts wrong",
    "description": "Queue monitoring counts double",
    "priority": "medium",
    "category": "analytics",
    "idempotency_key": "dup-call-key-00000001",
}


async def ticket_count(container) -> int:
    async with container.db.tenant_session("tnt_aurora") as s:
        return (await s.execute(select(func.count()).select_from(SupportTicket))).scalar_one()


async def test_duplicate_call_replays_without_side_effect(mcp, container):
    before = await ticket_count(container)
    with As("bruno"):
        first = await mcp.call_tool("create_support_ticket", ARGS)
        second = await mcp.call_tool("create_support_ticket", ARGS)
    assert first.structured_content["replayed"] is False and second.structured_content["replayed"] is True
    assert first.structured_content["ticket_id"] == second.structured_content["ticket_id"]
    assert await ticket_count(container) == before + 1


async def test_same_key_different_payload_conflicts(mcp):
    with As("bruno"):
        await mcp.call_tool("create_support_ticket", ARGS)
        r = await mcp.call_tool("create_support_ticket", {**ARGS, "priority": "high"})
    assert error_of(r)["code"] == "IDEMPOTENCY_CONFLICT"


async def test_keys_are_scoped_per_subject(mcp, container):
    with As("bruno"):
        a = await mcp.call_tool("create_support_ticket", ARGS)
    with As("carla"):
        b = await mcp.call_tool("create_support_ticket", ARGS)
    assert b.structured_content["replayed"] is False
    assert a.structured_content["ticket_id"] != b.structured_content["ticket_id"]


async def test_concurrent_duplicates_create_one_ticket(mcp, container):
    before = await ticket_count(container)
    args = {**ARGS, "idempotency_key": "concurrent-key-000001"}

    async def call():
        with As("bruno"):
            return await mcp.call_tool("create_support_ticket", args)

    results = await asyncio.gather(*[call() for _ in range(5)])
    ok = [r for r in results if not r.is_error]
    assert ok and all(r.structured_content["ticket_id"] == ok[0].structured_content["ticket_id"] for r in ok)
    for r in results:
        if r.is_error:
            assert error_of(r)["code"] == "IDEMPOTENCY_IN_PROGRESS" and error_of(r)["retryable"] is True
    assert await ticket_count(container) == before + 1


async def test_failed_attempt_can_be_retried_with_same_key(mcp, mock_state):
    args = {
        "client_id": "cli_aur001",
        "template": "ticket_update",
        "reference_id": "tkt_aur00001",
        "audience": "primary_contact",
        "channel": "email",
        "idempotency_key": "retry-after-fail-0001",
    }
    mock_state.faults["notifications"].mode = "unavailable"
    with As("carla"):
        failed = await mcp.call_tool("send_notification", args)
    assert error_of(failed)["code"] == "UPSTREAM_UNAVAILABLE" and error_of(failed)["retryable"] is True
    mock_state.faults["notifications"].mode = "ok"
    with As("carla"):
        ok = await mcp.call_tool("send_notification", args)
        again = await mcp.call_tool("send_notification", args)
    assert ok.structured_content["status"] == "completed" and again.structured_content["replayed"] is True
    assert len(mock_state.deliveries) == 1


async def test_missing_idempotency_key_is_rejected(mcp):
    args = {k: v for k, v in ARGS.items() if k != "idempotency_key"}
    with As("bruno"):
        r = await mcp.call_tool("create_support_ticket", args)
    assert error_of(r)["code"] == "INVALID_ARGUMENT" and "idempotency_key" in error_of(r)["fields"]
