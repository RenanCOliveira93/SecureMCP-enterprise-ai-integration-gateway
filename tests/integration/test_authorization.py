import pytest

from tests.helpers import As, error_of, principal

pytestmark = pytest.mark.anyio

WRITE = {
    "client_id": "cli_aur001",
    "subject": "Camera offline",
    "description": "Camera at entrance offline",
    "priority": "low",
    "category": "camera_offline",
    "idempotency_key": "authz-test-0000000001",
}


async def test_viewer_cannot_write(mcp):
    with As("ana"):
        r = await mcp.call_tool("create_support_ticket", WRITE)
    err = error_of(r)
    assert err["code"] == "FORBIDDEN" and "tickets:write" in err["message"]


async def test_support_agent_can_write_ticket_but_not_notify(mcp):
    with As("bruno"):
        ok = await mcp.call_tool("create_support_ticket", WRITE)
        denied = await mcp.call_tool(
            "send_notification",
            {
                "client_id": "cli_aur001",
                "template": "ticket_update",
                "reference_id": "tkt_aur00001",
                "audience": "primary_contact",
                "channel": "email",
                "idempotency_key": "authz-test-0000000002",
            },
        )
    assert ok.structured_content["status"] == "completed"
    assert error_of(denied)["code"] == "FORBIDDEN"


async def test_delegated_scope_limits_a_powerful_role(mcp):
    with As(principal("diego", scopes={"clients:read"})):
        r = await mcp.call_tool("search_tickets", {})
    assert error_of(r)["code"] == "FORBIDDEN"


async def test_unauthenticated_calls_are_rejected(mcp):
    r = await mcp.call_tool("get_client", {"client_id": "cli_aur001"})
    assert error_of(r)["code"] == "UNAUTHENTICATED"


async def test_unknown_tool_is_denied_and_audited(mcp, container):
    with As("diego"):
        r = await mcp.call_tool("execute_sql", {"sql": "SELECT * FROM clients"})
    assert error_of(r)["code"] == "UNKNOWN_OPERATION"
    events = await container.audit.events("tnt_aurora")
    assert events[-1].operation == "execute_sql" and events[-1].status == "denied"


@pytest.mark.parametrize("user", ["ana", "bruno", "carla", "diego"])
async def test_no_role_reaches_approval_endpoints_through_mcp(mcp, user):
    with As(user):
        tools = {t.name for t in (await mcp.list_tools()).tools}
    assert not tools & {"list_approvals", "decide_approval", "approve", "execute_sql"}
