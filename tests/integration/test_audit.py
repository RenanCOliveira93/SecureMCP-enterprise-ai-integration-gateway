import pytest

from tests.helpers import As

pytestmark = pytest.mark.anyio

WRITE = {
    "client_id": "cli_aur001",
    "subject": "Audit me",
    "description": "Ticket created to test auditing",
    "priority": "low",
    "category": "other",
    "idempotency_key": "audit-key-0000000001",
}


async def test_every_attempt_is_audited_with_required_fields(mcp, container):
    with As("ana"):
        await mcp.call_tool("get_client", {"client_id": "cli_aur001"})
        await mcp.call_tool("create_support_ticket", WRITE)  # denied
        await mcp.call_tool("get_client", {"client_id": "bad"})  # invalid
    with As("bruno"):
        await mcp.call_tool("create_support_ticket", WRITE)
        await mcp.call_tool("create_support_ticket", WRITE)  # replay
    events = await container.audit.events("tnt_aurora")
    summary = [(e.operation, e.subject, e.status, e.error_code) for e in events]
    assert summary == [
        ("get_client", "usr_aur_ana", "ok", None),
        ("create_support_ticket", "usr_aur_ana", "denied", "FORBIDDEN"),
        ("get_client", "usr_aur_ana", "rejected", "INVALID_ARGUMENT"),
        ("create_support_ticket", "usr_aur_bruno", "ok", None),
        ("create_support_ticket", "usr_aur_bruno", "replayed", None),
    ]
    for e in events:
        assert e.request_id.startswith("req_") and e.tenant_id == "tnt_aurora" and e.client_id == "securemcp-host"
        assert e.policy_version == container.policy.version and e.kind == "tool" and e.duration_ms >= 0
    write = events[3]
    assert write.policy_id == "rbac.create_support_ticket" and write.risk == "medium"
    assert write.idempotency_key == WRITE["idempotency_key"] and len(write.args_fingerprint) == 64
    assert events[3].args_fingerprint == events[4].args_fingerprint
    assert (await container.audit.verify("tnt_aurora")).valid


async def test_audit_stores_no_argument_values(mcp, container):
    with As("bruno"):
        await mcp.call_tool("create_support_ticket", {**WRITE, "description": "secret customer detail here"})
    for e in await container.audit.events("tnt_aurora"):
        assert "secret customer detail" not in str(e.__dict__)


async def test_injection_signals_are_audited(mcp, container):
    with As("ana"):
        await mcp.call_tool("search_tickets", {"client_id": "cli_aur001"})
    event = (await container.audit.events("tnt_aurora"))[-1]
    assert "override_instructions" in event.injection_signals


async def test_resources_and_prompts_are_audited(mcp, container):
    with As("ana"):
        await mcp.read_resource("client://cli_aur001/summary")
        await mcp.get_prompt("customer_support_summary", {"client_id": "cli_aur001"})
    kinds = [(e.operation, e.kind) for e in await container.audit.events("tnt_aurora")]
    assert kinds == [("client_summary", "resource"), ("customer_support_summary", "prompt")]
