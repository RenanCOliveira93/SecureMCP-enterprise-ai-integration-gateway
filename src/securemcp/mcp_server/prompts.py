"""Prompt adapters: arguments are validated, the gateway authorises and audits, the template is rendered."""

from __future__ import annotations

from typing import TYPE_CHECKING

from mcp.server.mcpserver import UserMessage

from securemcp.errors import GatewayError
from securemcp.schemas import ClientId, FreeText300, RenderedPrompt

if TYPE_CHECKING:
    from securemcp.mcp_server.server import SecureMCPServer


def register(server: SecureMCPServer) -> None:
    from securemcp.mcp_server.server import mcp_error

    gw = server.gateway

    async def render(operation: str, **args: str) -> list[UserMessage]:
        try:
            result = await gw.invoke(operation, args)
        except GatewayError as err:
            raise mcp_error(err) from None
        assert isinstance(result, RenderedPrompt)
        return [UserMessage(m.text) for m in result.messages]

    @server.prompt(
        name="incident_triage",
        title="Incident triage",
        description="Step-by-step triage of a camera incident without side effects.",
    )
    async def incident_triage(client_id: ClientId, symptom: FreeText300) -> list[UserMessage]:
        return await render("incident_triage", client_id=client_id, symptom=symptom)

    @server.prompt(
        name="customer_support_summary",
        title="Customer support summary",
        description="Account summary for a support call.",
    )
    async def customer_support_summary(client_id: ClientId) -> list[UserMessage]:
        return await render("customer_support_summary", client_id=client_id)

    @server.prompt(
        name="maintenance_plan",
        title="Maintenance plan",
        description="Draft a maintenance proposal that respects contract dates, overlaps and approval rules.",
    )
    async def maintenance_plan(client_id: ClientId, goal: FreeText300) -> list[UserMessage]:
        return await render("maintenance_plan", client_id=client_id, goal=goal)
