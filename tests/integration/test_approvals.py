"""Approval workflow at gateway level (the HTTP endpoints are covered in test_mcp_http.py)."""

from datetime import UTC, datetime, timedelta

import pytest

from securemcp.errors import GatewayError
from tests.helpers import As, error_of, principal

pytestmark = pytest.mark.anyio

NOTIFY = {
    "client_id": "cli_aur001",
    "template": "ticket_update",
    "reference_id": "tkt_aur00001",
    "audience": "all_contacts",
    "channel": "email",
    "idempotency_key": "approval-key-0000001",
}


async def request_approval(mcp, args=NOTIFY):
    with As("carla"):
        r = await mcp.call_tool("send_notification", args)
    assert r.structured_content["status"] == "approval_required"
    return r.structured_content["approval"]["approval_id"]


async def decide(container, user, approval_id, decision="approve"):
    with As(principal(user, client="securemcp-approvals")):
        return await container.gateway.invoke("decide_approval", {"approval_id": approval_id, "decision": decision})


async def test_full_approval_flow(mcp, container, mock_state):
    approval_id = await request_approval(mcp)
    with As("carla"):  # retrying the same key before approval replays the pending result
        pending = await mcp.call_tool("send_notification", NOTIFY)
    assert pending.structured_content["approval"]["approval_id"] == approval_id
    with As(principal("diego", client="securemcp-approvals")):
        listed = await container.gateway.invoke("list_approvals", {})
    assert [a.approval_id for a in listed.approvals] == [approval_id]
    assert listed.approvals[0].summary["args"]["audience"] == "all_contacts"
    await decide(container, "diego", approval_id)
    with As("carla"):
        done = await mcp.call_tool("send_notification", {**NOTIFY, "approval_id": approval_id})
        replay = await mcp.call_tool("send_notification", {**NOTIFY, "approval_id": approval_id})
    assert done.structured_content["status"] == "completed" and done.structured_content["recipients_count"] == 2
    assert replay.structured_content["replayed"] is True
    assert len(mock_state.deliveries) == 1


async def test_four_eyes(mcp, container):
    approval_id = await request_approval(mcp)
    with pytest.raises(GatewayError) as exc:
        await decide(container, "carla", approval_id)
    assert exc.value.code == "FORBIDDEN"


async def test_agent_client_cannot_decide(mcp, container):
    approval_id = await request_approval(mcp)
    with As("diego"), pytest.raises(GatewayError) as exc:  # host client token lacks approvals:decide
        await container.gateway.invoke("decide_approval", {"approval_id": approval_id, "decision": "approve"})
    assert exc.value.code == "FORBIDDEN"


async def test_support_agent_cannot_approve(mcp, container):
    approval_id = await request_approval(mcp)
    with pytest.raises(GatewayError) as exc:
        await decide(container, "bruno", approval_id)
    assert exc.value.code == "FORBIDDEN"


async def test_unapproved_or_rejected_approval_does_not_execute(mcp, container, mock_state):
    approval_id = await request_approval(mcp)
    with As("carla"):
        early = await mcp.call_tool("send_notification", {**NOTIFY, "approval_id": approval_id})
    assert error_of(early)["code"] == "APPROVAL_INVALID"
    await decide(container, "diego", approval_id, "reject")
    with As("carla"):
        rejected = await mcp.call_tool("send_notification", {**NOTIFY, "approval_id": approval_id})
    assert "rejected" in error_of(rejected)["message"] and mock_state.deliveries == []


async def test_approval_is_bound_to_arguments(mcp, container, mock_state):
    approval_id = await request_approval(mcp)
    await decide(container, "diego", approval_id)
    swapped = {**NOTIFY, "channel": "sms", "idempotency_key": "approval-key-0000002", "approval_id": approval_id}
    with As("carla"):
        r = await mcp.call_tool("send_notification", swapped)
    assert error_of(r)["code"] == "APPROVAL_INVALID" and mock_state.deliveries == []


async def test_approval_is_bound_to_requester_and_single_use(mcp, container):
    approval_id = await request_approval(mcp)
    await decide(container, "diego", approval_id)
    with As("diego"):  # someone else cannot use carla's approval
        r = await mcp.call_tool("send_notification", {**NOTIFY, "approval_id": approval_id})
    assert error_of(r)["code"] == "APPROVAL_INVALID"
    with As("carla"):
        assert not (await mcp.call_tool("send_notification", {**NOTIFY, "approval_id": approval_id})).is_error
        other_key = {**NOTIFY, "idempotency_key": "approval-key-0000003", "approval_id": approval_id}
        reused = await mcp.call_tool("send_notification", other_key)
    assert error_of(reused)["code"] == "APPROVAL_INVALID"


async def test_expired_approval(mcp, container):
    approval_id = await request_approval(mcp)
    await decide(container, "diego", approval_id)
    container.approvals.clock = lambda: datetime.now(UTC) + timedelta(hours=1)
    with As("carla"):
        r = await mcp.call_tool("send_notification", {**NOTIFY, "approval_id": approval_id})
    assert "expired" in error_of(r)["message"]


async def test_cross_tenant_approval_invisible(mcp, container):
    approval_id = await request_approval(mcp)
    with pytest.raises(GatewayError) as exc:
        await decide(container, "fabio", approval_id)
    assert exc.value.code == "NOT_FOUND"
