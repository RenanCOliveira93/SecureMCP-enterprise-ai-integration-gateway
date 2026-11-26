import pytest

from tests.helpers import As, error_of

pytestmark = pytest.mark.anyio

CROSS_TENANT_CALLS = [
    ("get_client", {"client_id": "cli_bor001"}),
    ("list_camera_health", {"client_id": "cli_bor001"}),
    ("get_contract_modules", {"client_id": "cli_bor001"}),
    ("get_maintenance_window", {"client_id": "cli_bor001"}),
    (
        "create_support_ticket",
        {
            "client_id": "cli_bor001",
            "subject": "Hello there",
            "description": "cross tenant attempt",
            "priority": "low",
            "category": "other",
            "idempotency_key": "xtenant-key-000000001",
        },
    ),
]


@pytest.mark.parametrize(("tool", "args"), CROSS_TENANT_CALLS)
async def test_other_tenant_objects_look_nonexistent(mcp, tool, args):
    with As("diego"):  # even a tenant admin of Aurora
        r = await mcp.call_tool(tool, args)
    err = error_of(r)
    assert err["code"] == "NOT_FOUND"


async def test_search_never_returns_other_tenant_rows(mcp):
    with As("bruno"):
        r = await mcp.call_tool("search_tickets", {"limit": 50})
    assert r.structured_content["tickets"]
    assert all(t["ticket_id"].startswith("tkt_aur") for t in r.structured_content["tickets"])
    with As("eva"):
        r = await mcp.call_tool("search_tickets", {"client_id": "cli_aur001"})
    assert r.structured_content["tickets"] == []


async def test_cross_tenant_camera_in_ticket_rejected(mcp):
    with As("bruno"):
        r = await mcp.call_tool(
            "create_support_ticket",
            {
                "client_id": "cli_aur001",
                "camera_id": "cam_bor00101",
                "subject": "Camera",
                "description": "Camera broken here",
                "priority": "low",
                "category": "other",
                "idempotency_key": "xtenant-cam-000000001",
            },
        )
    assert error_of(r)["code"] == "NOT_FOUND"


async def test_cross_tenant_resources_and_prompts(mcp):
    from mcp.shared.exceptions import MCPError

    with As("eva"):
        for uri in ("client://cli_aur001/summary", "camera://cam_aur00101/health", "ticket://tkt_aur00001"):
            with pytest.raises(MCPError) as exc:
                await mcp.read_resource(uri)
            assert exc.value.error.data["error"]["code"] == "NOT_FOUND"
        with pytest.raises(MCPError):
            await mcp.get_prompt("incident_triage", {"client_id": "cli_aur001", "symptom": "all cameras down"})
