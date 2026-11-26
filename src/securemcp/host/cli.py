"""``securemcp-host``: a small MCP host for demos.

It plays the role Claude Desktop, an IDE or a chat UI plays in production: it signs the user in (OAuth 2.1 + PKCE),
holds the token, opens MCP client sessions, shows discovery, runs the LangGraph agent and asks the human for
confirmation. A second sign-in with the ``securemcp-approvals`` client is used by approvers.
"""

from __future__ import annotations

import asyncio
import getpass
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Annotated, Any

import httpx
import jwt
import typer
from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table

from securemcp.config import Settings
from securemcp.host.oauth import OAuthError, TokenSet, login
from securemcp.host.session import mcp_client

app = typer.Typer(no_args_is_help=True, add_completion=False, help="Demo MCP host for SecureMCP.")
approvals_app = typer.Typer(no_args_is_help=True, help="Approve or reject sensitive actions (approver sign-in).")
app.add_typer(approvals_app, name="approvals")
console = Console()


# ------------------------------------------------------------------------------------------- token cache
def _settings() -> Settings:
    return Settings()


def _cache_path(settings: Settings) -> Path:
    return settings.host_token_cache


def _load_cache(settings: Settings) -> dict[str, Any]:
    path = _cache_path(settings)
    return json.loads(path.read_text()) if path.is_file() else {}


def _save_cache(settings: Settings, cache: dict[str, Any]) -> None:
    path = _cache_path(settings)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)  # tokens are credentials: owner-only file
    with os.fdopen(fd, "w") as handle:
        json.dump(cache, handle)


def _token(settings: Settings, client_id: str) -> str:
    entry = _load_cache(settings).get(client_id)
    if not entry:
        console.print(
            f"[red]Not signed in with {client_id}. Run: securemcp-host login --user <name>"
            f"{' --approvals' if client_id == settings.host_approvals_client_id else ''}[/red]"
        )
        raise typer.Exit(2)
    tokens = TokenSet(**entry)
    if tokens.expired:
        console.print("[red]Token expired. Sign in again.[/red]")
        raise typer.Exit(2)
    return tokens.access_token


def _base_url(settings: Settings) -> str:
    return settings.host_mcp_url.rsplit("/mcp", 1)[0]


# ----------------------------------------------------------------------------------------------- commands
@app.command("login")
def login_cmd(
    user: Annotated[str, typer.Option(help="Synthetic user, e.g. bruno (see README).")],
    approvals: Annotated[bool, typer.Option("--approvals", help="Sign in with the approvals client.")] = False,
    password_stdin: Annotated[bool, typer.Option(help="Read the password from stdin (scripts).")] = False,
) -> None:
    """Sign in through the authorization server that protects the MCP server (discovered, not configured)."""
    settings = _settings()
    client_id = settings.host_approvals_client_id if approvals else settings.host_client_id
    redirect = "http://127.0.0.1:8977/callback" if approvals else settings.host_redirect_uri
    password = sys.stdin.readline().rstrip("\n") if password_stdin else getpass.getpass(f"password for {user}: ")
    try:
        tokens = asyncio.run(
            login(
                mcp_url=settings.host_mcp_url,
                username=user,
                password=password,
                client_id=client_id,
                redirect_uri=redirect,
            )
        )
    except (OAuthError, httpx.HTTPError) as exc:
        console.print(f"[red]Sign-in failed: {exc}[/red]")
        raise typer.Exit(1) from exc
    cache = _load_cache(settings)
    cache[client_id] = tokens.__dict__
    _save_cache(settings, cache)
    console.print(f"Signed in as [bold]{user}[/bold] via {client_id}. Scopes: {tokens.scope}")


@app.command()
def logout() -> None:
    """Forget cached tokens."""
    _cache_path(_settings()).unlink(missing_ok=True)
    console.print("Signed out.")


@app.command()
def whoami() -> None:
    """Show the identity the MCP server will see (decoded locally, for display only)."""
    settings = _settings()
    for client_id, entry in _load_cache(settings).items():
        claims = jwt.decode(entry["access_token"], options={"verify_signature": False})
        console.print(
            f"[bold]{client_id}[/bold]: sub={claims['sub']} tenant={claims['tenant_id']} "
            f"roles={claims['roles']} scope={claims['scope']}"
        )


@app.command()
def tools() -> None:
    """Discovery: the tools, resources and prompts this user may use (filtered by the server)."""
    settings = _settings()

    async def run() -> None:
        async with mcp_client(settings.host_mcp_url, _token(settings, settings.host_client_id)) as client:
            table = Table("tool", "kind", "description")
            for tool in (await client.list_tools()).tools:
                read_only = tool.annotations.read_only_hint if tool.annotations else None
                table.add_row(
                    tool.name,
                    "read" if read_only else "[yellow]write[/yellow]",
                    (tool.description or "").split("\n")[0][:90],
                )
            console.print(table)
            templates = (await client.list_resource_templates()).resource_templates
            console.print("resources:", ", ".join(t.uri_template for t in templates))
            console.print("prompts:", ", ".join(p.name for p in (await client.list_prompts()).prompts))

    asyncio.run(run())


@app.command()
def call(
    tool: str,
    arguments: Annotated[str, typer.Argument(help="JSON object with the tool arguments.")] = "{}",
) -> None:
    """Call one tool directly (no agent) and print the result or the structured error."""
    settings = _settings()

    async def run() -> None:
        async with mcp_client(settings.host_mcp_url, _token(settings, settings.host_client_id)) as client:
            result = await client.call_tool(tool, json.loads(arguments))
            body = result.structured_content if not result.is_error else json.loads(result.content[0].text)
            console.print_json(json.dumps(body, default=str))

    asyncio.run(run())


@app.command()
def read(uri: str) -> None:
    """Read one resource, e.g. ticket://tkt_aur00003 or docs://manuals/v4.1."""
    settings = _settings()

    async def run() -> None:
        async with mcp_client(settings.host_mcp_url, _token(settings, settings.host_client_id)) as client:
            console.print((await client.read_resource(uri)).contents[0].text)

    asyncio.run(run())


@app.command()
def chat(
    request: Annotated[str, typer.Argument(help="What you want, e.g. 'Show camera health for cli_aur001'.")],
    planner: Annotated[str | None, typer.Option(help="rule | claude | injection-following")] = None,
    yes: Annotated[bool, typer.Option("--yes", help="Auto-confirm writes (scripted demos only).")] = False,
    thread: Annotated[
        str | None,
        typer.Option(
            help="Conversation id. Reuse it to resume the same action: the agent derives the same idempotency key."
        ),
    ] = None,
    approved: Annotated[
        bool, typer.Option("--approved", help="With --yes: resend actions whose approval an approver already granted.")
    ] = False,
) -> None:
    """Run the LangGraph agent. Every write is shown and needs your confirmation."""
    from securemcp.agent import build_agent, build_planner, run_agent

    settings = _settings()
    planner_name = planner or settings.agent_planner

    async def decide(payload: dict[str, Any]) -> bool:
        if payload["type"] == "confirm":
            console.print(
                f"\n[bold yellow]The agent wants to call {payload['tool']}[/bold yellow] "
                f"({payload.get('rationale', '')}):"
            )
            console.print_json(json.dumps(payload["arguments"]))
            return yes or Confirm.ask("Execute?", default=False)
        console.print(
            f"\n[bold magenta]Approval required[/bold magenta]: {payload['reason']}.\n"
            f"Ask an approver to run: securemcp-host approvals approve {payload['approval_id']}"
        )
        if yes:
            return approved
        return Confirm.ask("Has it been approved? Resend the action now?", default=False)

    async def run() -> None:
        async with mcp_client(settings.host_mcp_url, _token(settings, settings.host_client_id)) as client:
            agent = build_agent(
                client, build_planner(planner_name, model=settings.agent_model), max_steps=settings.agent_max_steps
            )
            thread_id = thread or f"thr-{uuid.uuid4().hex[:12]}"
            result = await run_agent(agent, request, thread_id=thread_id, decide=decide)
            console.print(f"\n[bold]Answer[/bold] (thread {thread_id})\n{result['answer']}")

    asyncio.run(run())


# ------------------------------------------------------------------------------------------- approvals
def _approvals_request(method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    settings = _settings()
    token = _token(settings, settings.host_approvals_client_id)
    response = httpx.request(
        method, f"{_base_url(settings)}{path}", json=body, timeout=10, headers={"Authorization": f"Bearer {token}"}
    )
    payload = response.json()
    if response.status_code >= 400:
        console.print(f"[red]{response.status_code} {payload.get('error', payload)}[/red]")
        raise typer.Exit(1)
    return payload


@approvals_app.command("list")
def approvals_list() -> None:
    """Pending approvals for your tenant."""
    table = Table("approval", "operation", "requested by", "reason", "expires", "arguments")
    for item in _approvals_request("GET", "/approvals")["approvals"]:
        table.add_row(
            item["approval_id"],
            item["operation"],
            item["requested_by"],
            item["reason"],
            item["expires_at"],
            json.dumps(item["summary"].get("args", {}))[:80],
        )
    console.print(table)


def _decide(approval_id: str, decision: str, note: str | None) -> None:
    body = {"decision": decision, **({"note": note} if note else {})}
    result = _approvals_request("POST", f"/approvals/{approval_id}/decision", body)
    console.print(f"{approval_id}: {result['status']}")


@approvals_app.command("approve")
def approvals_approve(approval_id: str, note: Annotated[str | None, typer.Option()] = None) -> None:
    _decide(approval_id, "approve", note)


@approvals_app.command("reject")
def approvals_reject(approval_id: str, note: Annotated[str | None, typer.Option()] = None) -> None:
    _decide(approval_id, "reject", note)


if __name__ == "__main__":  # pragma: no cover
    app()
