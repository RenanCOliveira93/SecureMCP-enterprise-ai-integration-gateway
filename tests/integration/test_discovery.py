"""Discovery: what each caller can see, schema guarantees, and a snapshot against tool poisoning / rug pulls."""

import json

import pytest

from securemcp.schemas import (
    CreateSupportTicketInput,
    GetClientInput,
    GetContractModulesInput,
    GetMaintenanceWindowInput,
    ListCameraHealthInput,
    ScheduleMaintenanceInput,
    SearchTicketsInput,
    SendNotificationInput,
)
from tests.helpers import ROOT, As

pytestmark = pytest.mark.anyio

READ_TOOLS = {"get_client", "list_camera_health", "get_contract_modules", "search_tickets", "get_maintenance_window"}
MODELS = {
    "get_client": GetClientInput,
    "list_camera_health": ListCameraHealthInput,
    "get_contract_modules": GetContractModulesInput,
    "search_tickets": SearchTicketsInput,
    "get_maintenance_window": GetMaintenanceWindowInput,
    "create_support_ticket": CreateSupportTicketInput,
    "schedule_maintenance": ScheduleMaintenanceInput,
    "send_notification": SendNotificationInput,
}


@pytest.mark.parametrize(
    ("user", "expected"),
    [
        ("ana", READ_TOOLS),
        ("bruno", READ_TOOLS | {"create_support_ticket"}),
        ("carla", READ_TOOLS | {"create_support_ticket", "schedule_maintenance", "send_notification"}),
    ],
)
async def test_tools_are_filtered_by_permissions(mcp, user, expected):
    with As(user):
        tools = {t.name for t in (await mcp.list_tools()).tools}
    assert tools == expected


async def test_anonymous_discovery_is_empty(mcp):
    assert (await mcp.list_tools()).tools == []
    assert (await mcp.list_prompts()).prompts == []


async def test_resources_and_prompts_listed(mcp):
    with As("ana"):
        templates = {t.uri_template for t in (await mcp.list_resource_templates()).resource_templates}
        static = {str(r.uri) for r in (await mcp.list_resources()).resources}
        prompts = {p.name for p in (await mcp.list_prompts()).prompts}
    assert templates == {
        "client://{client_id}/summary",
        "camera://{camera_id}/health",
        "docs://manuals/{version}",
        "ticket://{ticket_id}",
    }
    assert static == {"docs://manuals"}
    assert prompts == {"incident_triage", "customer_support_summary", "maintenance_plan"}


async def test_no_tenant_inputs(mcp):
    with As("diego"):
        tools = (await mcp.list_tools()).tools
        prompts = (await mcp.list_prompts()).prompts
        templates = (await mcp.list_resource_templates()).resource_templates
    for tool in tools:
        assert not any("tenant" in name for name in tool.input_schema.get("properties", {})), tool.name
    for prompt in prompts:
        assert not any("tenant" in a.name for a in prompt.arguments or [])
    assert not any("tenant" in t.uri_template for t in templates)


async def test_schemas_are_explicit_and_match_models(mcp):
    with As("diego"):
        tools = {t.name: t for t in (await mcp.list_tools()).tools}
    for name, model in MODELS.items():
        tool = tools[name]
        assert set(tool.input_schema["properties"]) == set(model.model_fields), name
        assert set(tool.input_schema.get("required", [])) == {
            f for f, info in model.model_fields.items() if info.is_required()
        }, name
        assert tool.output_schema is not None and tool.output_schema["type"] == "object"
        assert tool.description and len(tool.description) > 30
    ticket = tools["create_support_ticket"].input_schema["properties"]
    assert ticket["idempotency_key"]["pattern"] and ticket["description"]["maxLength"] == 2000
    assert set(tools["send_notification"].input_schema["properties"]) == {
        "client_id",
        "template",
        "reference_id",
        "audience",
        "channel",
        "idempotency_key",
        "approval_id",
    }


async def test_annotations_and_meta(mcp):
    with As("diego"):
        tools = {t.name: t for t in (await mcp.list_tools()).tools}
    assert tools["get_client"].annotations.read_only_hint is True
    assert tools["schedule_maintenance"].annotations.destructive_hint is True
    assert tools["send_notification"].annotations.open_world_hint is True
    meta = tools["send_notification"].meta["securemcp"]
    assert meta == {
        "risk": "high",
        "permission": "notifications:send",
        "approval_possible": True,
        "idempotency_key_required": True,
    }


async def test_catalog_snapshot(mcp):
    """Fails when a tool's name, description or schema changes: such changes must be reviewed (rug-pull guard)."""
    with As("diego"):
        tools = (await mcp.list_tools()).tools
    current = {
        t.name: {"description": t.description, "input": t.input_schema, "output": t.output_schema}
        for t in sorted(tools, key=lambda t: t.name)
    }
    snapshot_file = ROOT / "tests/integration/catalog_snapshot.json"
    if not snapshot_file.exists():  # first run writes the snapshot; commit it
        snapshot_file.write_text(json.dumps(current, indent=1, sort_keys=True) + "\n")
    assert json.loads(snapshot_file.read_text()) == json.loads(json.dumps(current, sort_keys=True))


def test_tool_catalog_doc_lists_every_tool():
    doc = (ROOT / "docs/tool-catalog.md").read_text()
    for name in MODELS:
        assert f"### `{name}`" in doc or f"### `{name}` —" in doc, name
