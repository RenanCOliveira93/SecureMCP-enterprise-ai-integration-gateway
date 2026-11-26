"""End-to-end authentication over Streamable HTTP: discovery, bearer validation, token binding, identity from token."""

import json
import time

import httpx
import pytest

from securemcp.auth_server.tokens import SigningKey, TokenIssuer
from securemcp.host.session import mcp_client

pytestmark = [pytest.mark.anyio, pytest.mark.http]

INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "t", "version": "0"}},
}
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


async def post_mcp(stack, token=None, body=INIT, **extra_headers):
    headers = {**HEADERS, **extra_headers}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    async with httpx.AsyncClient() as http:
        return await http.post(stack.mcp_url, json=body, headers=headers)


def forged(stack, **overrides):
    kwargs = dict(
        subject="usr_aur_diego",
        tenant_id="tnt_aurora",
        roles=["tenant_admin"],
        scopes=["clients:read"],
        client_id="securemcp-host",
        audience=stack.mcp_url,
    )
    kwargs.update(overrides)
    issuer = kwargs.pop("issuer", stack.issuer)
    return issuer.issue(**kwargs)


async def test_unauthenticated_request_gets_discovery_challenge(stack):
    response = await post_mcp(stack)
    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert challenge.startswith("Bearer") and "resource_metadata=" in challenge
    async with httpx.AsyncClient() as http:
        prm = (await http.get(f"{stack.base_url}/.well-known/oauth-protected-resource/mcp")).json()
    assert prm["resource"] == stack.mcp_url
    assert [s.rstrip("/") for s in prm["authorization_servers"]] == [stack.settings.as_issuer]


async def test_valid_token_accepted(stack):
    response = await post_mcp(stack, await stack.token("bruno"))
    assert response.status_code == 200 and response.json()["result"]["serverInfo"]["name"] == "securemcp"


@pytest.mark.parametrize("case", ["garbage", "wrong_audience", "expired", "foreign_key", "wrong_issuer"])
async def test_invalid_tokens_rejected(stack, case):
    now = int(time.time())
    token = {
        "garbage": lambda: "not-a-jwt",
        "wrong_audience": lambda: forged(stack, audience="http://127.0.0.1:1/other-mcp"),
        "expired": lambda: forged(stack, now=now - 7200, ttl_seconds=60),
        "foreign_key": lambda: forged(stack, issuer=TokenIssuer(SigningKey.generate(), stack.settings.as_issuer, 900)),
        "wrong_issuer": lambda: forged(stack, issuer=TokenIssuer(stack.key, "http://evil.test", 900)),
    }[case]()
    response = await post_mcp(stack, token)
    assert response.status_code == 401
    assert "invalid_token" in response.headers["www-authenticate"]


async def test_token_in_query_string_is_ignored(stack):
    token = await stack.token("bruno")
    async with httpx.AsyncClient() as http:
        response = await http.post(f"{stack.mcp_url}?access_token={token}", json=INIT, headers=HEADERS)
    assert response.status_code == 401


async def test_identity_and_tenant_come_from_token(stack):
    async with mcp_client(stack.mcp_url, await stack.token("eva")) as client:  # tnt_boreal support agent
        own = await client.call_tool("get_client", {"client_id": "cli_bor001"})
        other = await client.call_tool("get_client", {"client_id": "cli_aur001"})
        smuggled = await client.call_tool("get_client", {"client_id": "cli_aur001", "tenant_id": "tnt_aurora"})
    assert own.structured_content["client_id"] == "cli_bor001" and not own.is_error
    assert json.loads(other.content[0].text)["error"]["code"] == "NOT_FOUND"
    assert json.loads(smuggled.content[0].text)["error"]["code"] == "INVALID_ARGUMENT"


async def test_discovery_is_filtered_by_token_permissions(stack):
    async with mcp_client(stack.mcp_url, await stack.token("ana")) as viewer:
        viewer_tools = {t.name for t in (await viewer.list_tools()).tools}
    async with mcp_client(stack.mcp_url, await stack.token("carla")) as manager:
        manager_tools = {t.name for t in (await manager.list_tools()).tools}
    assert "create_support_ticket" not in viewer_tools and "get_client" in viewer_tools
    assert {"create_support_ticket", "schedule_maintenance", "send_notification"} <= manager_tools


async def test_scope_downscoping_limits_role(stack):
    """A token carries the intersection of role and requested scopes: a narrow token cannot use the full role."""
    narrow = forged(stack, subject="usr_aur_carla", roles=["operations_manager"], scopes=["clients:read"])
    async with mcp_client(stack.mcp_url, narrow) as client:
        tools = {t.name for t in (await client.list_tools()).tools}
        denied = await client.call_tool("search_tickets", {"status": "open"})
    assert tools == {"get_client"}
    assert json.loads(denied.content[0].text)["error"]["code"] == "FORBIDDEN"


async def test_roles_unknown_to_policy_grant_nothing(stack):
    token = forged(stack, roles=["superuser"], scopes=["clients:read", "tickets:read"])
    async with mcp_client(stack.mcp_url, token) as client:
        assert (await client.list_tools()).tools == []
