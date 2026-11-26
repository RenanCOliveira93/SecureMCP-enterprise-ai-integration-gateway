"""Layer 3 of tenant isolation (ADR-0005): PostgreSQL Row-Level Security under the least-privilege app role.

These tests deliberately run *unfiltered* SQL as the application role to prove that the database itself, not only
the repositories, confines every statement to the tenant of the current transaction.

Run with ``make test-pg`` or set:
  SECUREMCP_TEST_POSTGRES_URL      owner connection (creates schema, RLS policies and grants)
  SECUREMCP_TEST_POSTGRES_APP_URL  connection as the ``securemcp_app`` role (what the gateway uses)
"""

import os

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from securemcp.config import Settings
from securemcp.container import build_container
from securemcp.db.database import Database, create_schema
from securemcp.db.seed import seed
from tests.helpers import ROOT, As, error_of

OWNER_URL = os.environ.get("SECUREMCP_TEST_POSTGRES_URL")
APP_URL = os.environ.get("SECUREMCP_TEST_POSTGRES_APP_URL")

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.postgres,
    pytest.mark.skipif(not (OWNER_URL and APP_URL), reason="PostgreSQL URLs not configured"),
]


@pytest.fixture
async def app_db():
    await create_schema(OWNER_URL, reset=True)
    owner = Database(OWNER_URL)
    await seed(owner)
    await owner.dispose()
    db = Database(APP_URL)
    yield db
    await db.dispose()


async def scalar(db, tenant, sql, **params):
    async with db.tenant_session(tenant) as s:
        return (await s.execute(text(sql), params)).scalar()


async def test_app_role_is_not_privileged(app_db):
    async with app_db.engine.connect() as conn:
        row = (
            await conn.execute(text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"))
        ).one()
    assert tuple(row) == (False, False)


async def test_unfiltered_select_sees_only_current_tenant(app_db):
    sql = "SELECT string_agg(DISTINCT tenant_id, ',') FROM clients"  # no WHERE clause on purpose
    assert await scalar(app_db, "tnt_aurora", sql) == "tnt_aurora"
    assert await scalar(app_db, "tnt_boreal", sql) == "tnt_boreal"
    assert await scalar(app_db, "tnt_aurora", "SELECT count(*) FROM cameras WHERE id LIKE 'cam_bor%'") == 0


async def test_explicit_other_tenant_filter_returns_nothing(app_db):
    sql = "SELECT count(*) FROM tickets WHERE tenant_id = :t"
    assert await scalar(app_db, "tnt_aurora", sql, t="tnt_boreal") == 0


async def test_no_tenant_context_sees_nothing(app_db):
    async with app_db.engine.connect() as conn:
        assert (await conn.execute(text("SELECT count(*) FROM clients"))).scalar() == 0
        assert (await conn.execute(text("SELECT count(*) FROM audit_events"))).scalar() == 0


async def test_tenant_setting_does_not_leak_through_the_pool(app_db):
    assert await scalar(app_db, "tnt_aurora", "SELECT count(*) FROM clients") == 3
    async with app_db.engine.connect() as conn:  # same pooled connection, new transaction
        assert (await conn.execute(text("SELECT current_setting('app.tenant_id', true)"))).scalar() in (None, "")
        assert (await conn.execute(text("SELECT count(*) FROM clients"))).scalar() == 0


async def test_cannot_write_rows_for_another_tenant(app_db):
    with pytest.raises(DBAPIError, match="row-level security"):
        async with app_db.tenant_session("tnt_aurora") as s:
            await s.execute(text("INSERT INTO tenants (id, tenant_id, name) VALUES ('tnt_evil', 'tnt_boreal', 'x')"))


async def test_cannot_move_rows_to_another_tenant(app_db):
    with pytest.raises(DBAPIError, match="row-level security"):
        async with app_db.tenant_session("tnt_aurora") as s:
            await s.execute(text("UPDATE tickets SET tenant_id = 'tnt_boreal' WHERE id = 'tkt_aur00001'"))


async def test_cross_tenant_update_affects_no_rows(app_db):
    async with app_db.tenant_session("tnt_aurora") as s:
        result = await s.execute(text("UPDATE tickets SET status = 'closed' WHERE id = 'tkt_bor00001'"))
    assert result.rowcount == 0


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE audit_events SET status = 'ok'",
        "DELETE FROM audit_events",
        "DELETE FROM tickets",
        "DROP TABLE clients",
        "CREATE TABLE exfil (x text)",
        "ALTER TABLE clients DISABLE ROW LEVEL SECURITY",
    ],
)
async def test_app_role_privileges_are_minimal(app_db, sql):
    with pytest.raises((ProgrammingError, DBAPIError), match="permission denied|must be owner"):
        async with app_db.tenant_session("tnt_aurora") as s:
            await s.execute(text(sql))


async def test_gateway_end_to_end_on_postgres(app_db, tmp_path):
    settings = Settings(
        env="test",
        database_url=APP_URL,
        transport="stdio",
        policy_file=ROOT / "config/policy.yaml",
        docs_dir=ROOT / "data/manuals",
        _env_file=None,
    )
    from tests.helpers import resolve_test_identity

    container = build_container(settings, identity=resolve_test_identity)
    from mcp import Client

    from securemcp.mcp_server.server import build_server

    try:
        async with Client(build_server(container)) as client:
            with As("bruno"):
                own = await client.call_tool("search_tickets", {"status": "open"})
                other = await client.call_tool("get_client", {"client_id": "cli_bor001"})
                created = await client.call_tool(
                    "create_support_ticket",
                    {
                        "client_id": "cli_aur002",
                        "subject": "Camera offline after power cut",
                        "description": "Store reports a black screen since the morning.",
                        "priority": "high",
                        "category": "camera_offline",
                        "idempotency_key": "pg-e2e-ticket-0001",
                    },
                )
        assert {t["ticket_id"][:7] for t in own.structured_content["tickets"]} == {"tkt_aur"}
        assert error_of(other)["code"] == "NOT_FOUND"
        assert created.structured_content["status"] == "completed"
        verification = await container.audit.verify("tnt_aurora")
        assert verification.valid and verification.events == 3
        assert (await container.audit.verify("tnt_boreal")).events == 0
    finally:
        await container.aclose()
