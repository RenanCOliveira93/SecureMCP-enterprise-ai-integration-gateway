import pytest

from tests.helpers import As, error_of

pytestmark = pytest.mark.anyio


async def test_get_client_returns_masked_contacts_and_crm(mcp):
    with As("ana"):
        r = await mcp.call_tool("get_client", {"client_id": "cli_aur001"})
    assert not r.is_error
    data = r.structured_content
    assert data["name"] == "Mercado Solar" and data["crm"] == {
        "status": "ok",
        "account_manager": "Paula Ribeiro",
        "health": "yellow",
        "open_opportunities": 2,
    }


async def test_contacts_are_masked(mcp):
    with As("ana"):
        r = await mcp.call_tool("get_client", {"client_id": "cli_aur001"})
    text = r.content[0].text
    assert "@" in text and "joana.prado@" not in text and "95555" not in text
    for contact in r.structured_content["contacts"]:
        assert set(contact) == {"contact_id", "name", "role", "email_masked", "phone_masked", "notify_opt_in"}
        assert "***" in contact["email_masked"] and contact["phone_masked"].startswith("***")


async def test_crm_down_degrades_instead_of_failing(mcp, mock_state):
    mock_state.faults["crm"].mode = "unavailable"
    with As("ana"):
        r = await mcp.call_tool("get_client", {"client_id": "cli_aur002"})
    assert not r.is_error and r.structured_content["crm"]["status"] == "unavailable"
    assert mock_state.requests["crm"] == 3  # transient retries happened, then graceful degradation


async def test_list_camera_health_worst_first_and_truncation(mcp):
    with As("ana"):
        r = await mcp.call_tool("list_camera_health", {"client_id": "cli_aur001", "limit": 3})
    data = r.structured_content
    assert data["truncated"] is True and len(data["cameras"]) == 3
    assert data["cameras"][0]["status"] == "offline" and data["summary"]["total"] == 14
    with As("ana"):
        r = await mcp.call_tool("list_camera_health", {"client_id": "cli_aur001", "status": "online"})
    assert {c["status"] for c in r.structured_content["cameras"]} == {"online"}


async def test_contract_modules(mcp):
    with As("ana"):
        r = await mcp.call_tool("get_contract_modules", {"client_id": "cli_aur002"})
    data = r.structured_content
    enabled = {m["code"] for m in data["modules"] if m["enabled"]}
    assert data["plan"] == "professional" and enabled == {"people_counting", "heatmaps", "queue_monitoring"}


async def test_search_text_is_not_sql(mcp):
    with As("ana"):
        injection = await mcp.call_tool("search_tickets", {"text": "' OR 1=1 --"})
        wildcard = await mcp.call_tool("search_tickets", {"text": "%%"})
        underscore = await mcp.call_tool("search_tickets", {"text": "__"})
        normal = await mcp.call_tool("search_tickets", {"text": "heatmap"})
    assert injection.structured_content["tickets"] == []
    assert wildcard.structured_content["tickets"] == []  # % is matched literally, not as "everything"
    assert underscore.structured_content["tickets"] == []
    assert [t["ticket_id"] for t in normal.structured_content["tickets"]] == ["tkt_aur00002"]


async def test_search_flags_untrusted_injection(mcp):
    with As("ana"):
        r = await mcp.call_tool("search_tickets", {"client_id": "cli_aur001", "status": "open"})
    data = r.structured_content
    assert data["untrusted_fields"] == ["tickets[].subject", "tickets[].description"]
    assert data["injection_suspected"] is True
    assert {"override_instructions", "tool_invocation"} <= set(data["injection_signals"])


async def test_clean_results_are_not_flagged(mcp):
    with As("ana"):
        r = await mcp.call_tool("search_tickets", {"client_id": "cli_aur002"})
    assert r.structured_content["injection_suspected"] is False


async def test_maintenance_calendar(mcp):
    with As("ana"):
        r = await mcp.call_tool("get_maintenance_window", {"client_id": "cli_aur001", "days": 30})
    data = r.structured_content
    assert data["next_window"]["maintenance_id"] == "mnt_aur00101" and len(data["windows"]) == 1


async def test_schema_rejects_bad_input_and_reports_field_names_only(mcp):
    with As("ana"):
        r = await mcp.call_tool("list_camera_health", {"client_id": "cli_aur001", "limit": 1000})
        extra = await mcp.call_tool("get_client", {"client_id": "cli_aur001", "tenant_id": "tnt_boreal"})
    err = error_of(r)
    assert err["code"] == "INVALID_ARGUMENT" and err["fields"] == ["limit"] and "1000" not in err["message"]
    assert error_of(extra)["code"] == "INVALID_ARGUMENT"
