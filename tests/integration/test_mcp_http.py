"""Streamable HTTP transport: host/origin validation, probes, and the out-of-band approval API with real tokens."""

import httpx
import pytest

from securemcp.host.session import mcp_client

pytestmark = [pytest.mark.anyio, pytest.mark.http]

HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
PING = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
NOTIFY = {
    "client_id": "cli_aur001",
    "template": "maintenance_notice",
    "reference_id": "mnt_aur00101",
    "audience": "all_contacts",
    "channel": "email",
    "idempotency_key": "http-approval-flow-0001",
}


async def test_probes(stack):
    async with httpx.AsyncClient(base_url=stack.base_url) as http:
        assert (await http.get("/healthz")).json() == {"status": "ok"}
        assert (await http.get("/readyz")).json() == {"status": "ready"}


async def test_dns_rebinding_host_rejected(stack):
    token = await stack.token("bruno")
    async with httpx.AsyncClient() as http:
        response = await http.post(
            stack.mcp_url, json=PING, headers={**HEADERS, "Host": "evil.test", "Authorization": f"Bearer {token}"}
        )
    assert response.status_code == 421


async def test_foreign_origin_rejected(stack):
    token = await stack.token("bruno")
    async with httpx.AsyncClient() as http:
        response = await http.post(
            stack.mcp_url,
            json=PING,
            headers={**HEADERS, "Origin": "https://evil.test", "Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 403


async def test_approval_api_requires_authentication(stack):
    async with httpx.AsyncClient(base_url=stack.base_url) as http:
        response = await http.get("/approvals")
    assert response.status_code == 401
    assert "resource_metadata=" in response.headers["www-authenticate"]


async def test_full_approval_flow_over_http(stack):
    requester = await stack.token("carla")
    async with mcp_client(stack.mcp_url, requester) as client:
        first = await client.call_tool("send_notification", NOTIFY)
    assert first.structured_content["status"] == "approval_required", first
    approval_id = first.structured_content["approval"]["approval_id"]

    async with httpx.AsyncClient(base_url=stack.base_url) as http:
        # the agent-facing token can never approve, even for a user whose role could
        as_agent = await http.get("/approvals", headers={"Authorization": f"Bearer {await stack.token('diego')}"})
        assert as_agent.status_code == 403
        # four-eyes: the requester cannot approve their own request
        own = await http.post(
            f"/approvals/{approval_id}/decision",
            json={"decision": "approve"},
            headers={"Authorization": f"Bearer {await stack.token('carla', 'securemcp-approvals')}"},
        )
        assert own.status_code == 403 and own.json()["error"]["code"] == "FORBIDDEN"

        approver = {"Authorization": f"Bearer {await stack.token('diego', 'securemcp-approvals')}"}
        listed = (await http.get("/approvals", headers=approver)).json()
        assert approval_id in [a["approval_id"] for a in listed["approvals"]]
        bad = await http.post(f"/approvals/{approval_id}/decision", content=b"[1]", headers=approver)
        assert bad.status_code == 400
        decided = await http.post(f"/approvals/{approval_id}/decision", json={"decision": "approve"}, headers=approver)
        assert decided.status_code == 200 and decided.json()["status"] == "approved"

    async with mcp_client(stack.mcp_url, requester) as client:
        done = await client.call_tool("send_notification", {**NOTIFY, "approval_id": approval_id})
    assert done.structured_content["status"] == "completed", done
    assert stack.mocks_app.state.mock.deliveries[-1]["recipients"] == 2


async def test_cross_tenant_approval_is_not_found(stack):
    async with mcp_client(stack.mcp_url, await stack.token("carla")) as client:
        pending = await client.call_tool("send_notification", {**NOTIFY, "idempotency_key": "http-approval-xt-0001"})
    approval_id = pending.structured_content["approval"]["approval_id"]
    other_tenant = await stack.token("fabio", "securemcp-approvals")
    async with httpx.AsyncClient(base_url=stack.base_url) as http:
        response = await http.post(
            f"/approvals/{approval_id}/decision",
            json={"decision": "approve"},
            headers={"Authorization": f"Bearer {other_tenant}"},
        )
    assert response.status_code == 404
