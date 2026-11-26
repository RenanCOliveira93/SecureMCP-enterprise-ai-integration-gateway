"""``securemcp`` command line: run the gateway, the local authorization server and the simulated APIs; manage the
database; verify the audit chain; get a token for stdio clients."""

from __future__ import annotations

import asyncio
import getpass
import json
import sys
from pathlib import Path
from typing import Annotated, Literal

import typer
import uvicorn

from securemcp.config import Settings

app = typer.Typer(no_args_is_help=True, add_completion=False, help="SecureMCP enterprise AI integration gateway.")
db_app = typer.Typer(no_args_is_help=True, help="Database schema and synthetic data.")
audit_app = typer.Typer(no_args_is_help=True, help="Audit trail tools.")
app.add_typer(db_app, name="db")
app.add_typer(audit_app, name="audit")


def _owner_url(settings: Settings) -> str:
    from securemcp.db.database import with_secret_password
    from securemcp.security.secrets import build_secret_provider

    if settings.database_owner_url:
        return with_secret_password(
            settings.database_owner_url, settings.database_owner_password_secret, build_secret_provider(settings)
        )
    return with_secret_password(
        settings.database_url, settings.database_password_secret, build_secret_provider(settings)
    )


def _settings(**overrides: object) -> Settings:
    from securemcp.telemetry import configure_logging

    settings = Settings(**{k: v for k, v in overrides.items() if v is not None})  # type: ignore[arg-type]
    configure_logging(settings)
    return settings


@app.command()
def serve(
    transport: Annotated[
        Literal["streamable-http", "stdio"] | None, typer.Option(help="Overrides SECUREMCP_TRANSPORT.")
    ] = None,
) -> None:
    """Run the MCP gateway (Streamable HTTP by default, or stdio for local hosts such as the Inspector)."""
    from securemcp.container import build_container
    from securemcp.mcp_server.server import build_http_app, build_server
    from securemcp.telemetry import configure_logging, configure_tracing

    settings = _settings(transport=transport)
    configure_tracing(settings)
    container = build_container(settings)
    try:
        if settings.transport == "stdio":
            server = build_server(container)
            configure_logging(settings)  # the SDK installs its own handler; logs must stay on stderr
            asyncio.run(server.run_stdio_async())
        else:
            http_app = build_http_app(container)
            configure_logging(settings)
            uvicorn.run(
                http_app,
                host=settings.bind_host,
                port=settings.port,
                log_config=None,
                proxy_headers=False,
                server_header=False,
            )
    finally:
        asyncio.run(container.aclose())


@app.command("auth-server")
def auth_server() -> None:
    """Run the local OAuth 2.1 authorization server (development stand-in for the enterprise IdP)."""
    from securemcp.auth_server import build_auth_app
    from securemcp.telemetry import configure_tracing

    settings = _settings()
    configure_tracing(settings, service_name="securemcp-auth")
    uvicorn.run(
        build_auth_app(settings),
        host=settings.as_bind_host,
        port=settings.as_port,
        log_config=None,
        server_header=False,
    )


@app.command()
def mocks() -> None:
    """Run the simulated CRM and notification APIs (with fault injection for the resilience scenarios)."""
    from securemcp.mocks.app import create_mocks_app
    from securemcp.security.secrets import build_secret_provider

    settings = _settings()
    uvicorn.run(
        create_mocks_app(build_secret_provider(settings)),
        host=settings.mocks_bind_host,
        port=settings.mocks_port,
        log_config=None,
        server_header=False,
    )


@db_app.command("init")
def db_init(
    seed: Annotated[bool, typer.Option(help="Load the synthetic data set.")] = False,
    reset: Annotated[bool, typer.Option(help="Drop all tables first (never in prod).")] = False,
) -> None:
    """Create the schema (and RLS policies on PostgreSQL) using the owner connection."""
    from securemcp.db.database import Database, create_schema
    from securemcp.db.seed import seed as load_seed

    settings = _settings()
    if reset and settings.env == "prod":
        raise typer.BadParameter("--reset is refused when SECUREMCP_ENV=prod")
    owner_url = _owner_url(settings)

    async def run() -> None:
        await create_schema(owner_url, reset=reset)
        if seed:
            db = Database(owner_url)
            try:
                typer.echo(json.dumps(await load_seed(db)))
            finally:
                await db.dispose()

    asyncio.run(run())


@audit_app.command("verify")
def audit_verify(
    tenant: Annotated[list[str] | None, typer.Option(help="Tenant id (repeatable). Default: every tenant.")] = None,
) -> None:
    """Recompute each tenant's hash chain; exit 1 if any event was altered, removed or reordered."""
    from sqlalchemy import select

    from securemcp.db.database import Database
    from securemcp.db.models import Tenant
    from securemcp.gateway.audit import AuditTrail

    settings = _settings()

    async def run() -> bool:
        db = Database(_owner_url(settings))
        try:
            tenants = tenant
            if not tenants:
                async with db.engine.connect() as conn:
                    tenants = list((await conn.execute(select(Tenant.id))).scalars().all())
                if not tenants:  # e.g. RLS hid the tenant list from a non-superuser owner
                    typer.echo("no tenants visible; pass --tenant explicitly", err=True)
                    return False
            ok = True
            for tenant_id in tenants:
                result = await AuditTrail(db).verify(tenant_id)
                status = "valid" if result.valid else f"BROKEN at seq {result.first_bad_seq}"
                typer.echo(f"{tenant_id}: {result.events} events, chain {status}")
                ok &= result.valid
            return ok
        finally:
            await db.dispose()

    if not asyncio.run(run()):
        raise typer.Exit(1)


@app.command()
def token(
    user: Annotated[str, typer.Option(help="Synthetic username, e.g. bruno.")],
    client_id: Annotated[str | None, typer.Option(help="OAuth client (default: SECUREMCP_HOST_CLIENT_ID).")] = None,
    redirect_uri: Annotated[str | None, typer.Option(help="Registered redirect URI of that client.")] = None,
    scope: Annotated[list[str] | None, typer.Option(help="Requested scope (repeatable). Default: all allowed.")] = None,
) -> None:
    """Run the OAuth flow against the gateway's authorization server and print the access token (for stdio use)."""
    from securemcp.host.oauth import OAuthError, login

    settings = _settings()
    password = getpass.getpass(f"password for {user}: ")
    try:
        tokens = asyncio.run(
            login(
                mcp_url=settings.host_mcp_url,
                username=user,
                password=password,
                client_id=client_id or settings.host_client_id,
                redirect_uri=redirect_uri or settings.host_redirect_uri,
                scopes=scope,
            )
        )
    except OAuthError as exc:
        typer.echo(f"login failed: {exc}", err=True)
        raise typer.Exit(1) from exc
    typer.echo(f"scopes: {tokens.scope}", err=True)
    typer.echo(tokens.access_token)


@app.command("hash-password")
def hash_password_cmd() -> None:
    """Print a PBKDF2 hash for config/auth-users.yaml (the password is read without echo)."""
    from securemcp.auth_server.tokens import hash_password

    typer.echo(hash_password(getpass.getpass("password: ")))


@app.command("generate-signing-key")
def generate_signing_key(
    out: Annotated[Path | None, typer.Option(help="Write the PEM here (mode 600) instead of stdout.")] = None,
) -> None:
    """Generate an RSA-2048 signing key for the authorization server (secret ``auth_signing_key``)."""
    from securemcp.auth_server.tokens import SigningKey

    pem = SigningKey.generate().to_pem()
    if out is None:
        sys.stdout.write(pem)
        return
    out.parent.mkdir(parents=True, exist_ok=True)
    out.touch(mode=0o600, exist_ok=True)
    out.write_text(pem)
    typer.echo(f"wrote {out}", err=True)


@app.command()
def scenarios(
    mocks_url: Annotated[str, typer.Option(help="Simulated services (fault-injection control endpoint).")] = (
        "http://localhost:8081"
    ),
    report_file: Annotated[Path | None, typer.Option("--report", help="Write the Markdown report here.")] = None,
    password_stdin: Annotated[bool, typer.Option(help="Read the synthetic users' password from stdin.")] = False,
) -> None:
    """Run the end-to-end scenarios (allowed, denied, tenant isolation, prompt injection, duplicate call, unavailable
    service, approval, rate limit) against a running stack. Exit code 1 if any scenario misbehaves."""
    from securemcp.scenarios import Runner, report

    settings = _settings()
    password = sys.stdin.readline().rstrip("\n") if password_stdin else getpass.getpass("synthetic users' password: ")
    runner = Runner(
        mcp_url=settings.host_mcp_url, mocks_url=mocks_url, password=password, redirect_uri=settings.host_redirect_uri
    )
    results = asyncio.run(runner.run())
    text = report(results, mcp_url=settings.host_mcp_url)
    typer.echo(text)
    if report_file:
        report_file.parent.mkdir(parents=True, exist_ok=True)
        report_file.write_text(text)
    if not all(r.passed for r in results):
        raise typer.Exit(1)


if __name__ == "__main__":  # pragma: no cover
    app()
