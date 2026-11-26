"""Engine, tenant-scoped transactions and schema bootstrap (including PostgreSQL Row-Level Security)."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from securemcp.db.models import TENANT_TABLES, Base

log = logging.getLogger(__name__)

APP_ROLE = "securemcp_app"

# Audit tables are append-only for the application role (ADR-0010); idempotency rows may be released (deleted).
_GRANTS = {
    "audit_events": "SELECT, INSERT",
    "audit_chain_heads": "SELECT, INSERT, UPDATE",
    "idempotency_records": "SELECT, INSERT, UPDATE, DELETE",
}
_DEFAULT_GRANT = "SELECT, INSERT, UPDATE"


def _sqlite_pragmas(dbapi_connection, _record) -> None:  # pragma: no cover - trivial
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.close()


class Database:
    def __init__(self, url: str, *, echo: bool = False) -> None:
        self.url = url
        self.is_postgres = url.startswith("postgresql")
        kwargs: dict = {"echo": echo, "pool_pre_ping": True}
        if not self.is_postgres:
            # SQLite (tests, quick local runs) allows one writer; a single pooled connection serialises
            # transactions instead of failing with "database is locked". PostgreSQL uses a normal pool.
            kwargs.update(connect_args={"timeout": 30}, pool_size=1, max_overflow=0)
        self.engine: AsyncEngine = create_async_engine(url, **kwargs)
        if not self.is_postgres:
            event.listen(self.engine.sync_engine, "connect", _sqlite_pragmas)
        self._sessions = async_sessionmaker(self.engine, expire_on_commit=False)

    @asynccontextmanager
    async def tenant_session(self, tenant_id: str) -> AsyncIterator[AsyncSession]:
        """One transaction scoped to ``tenant_id``.

        On PostgreSQL the tenant is also pushed into ``app.tenant_id`` with ``is_local = true``, so the RLS
        policies apply and the setting disappears at commit/rollback (safe with pooled connections).
        """
        async with self._sessions() as session, session.begin():
            if self.is_postgres:
                await session.execute(text("SELECT set_config('app.tenant_id', :t, true)"), {"t": tenant_id})
            yield session

    async def ping(self) -> bool:
        try:
            async with self.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    async def dispose(self) -> None:
        await self.engine.dispose()


async def create_schema(owner_url: str, *, reset: bool = False) -> None:
    """Create tables; on PostgreSQL also enable RLS and grant the application role (run as the owner)."""
    db = Database(owner_url)
    try:
        async with db.engine.begin() as conn:
            if reset:
                await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
            if db.is_postgres:
                for statement in rls_statements():
                    await conn.execute(text(statement))
        log.info("schema ready (postgres=%s, rls=%s)", db.is_postgres, db.is_postgres)
    finally:
        await db.dispose()


def rls_statements() -> list[str]:
    """DDL for RLS and grants. Identifiers come from module constants (never from callers), hence the noqa."""
    statements = [
        f"DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN "  # noqa: S608
        f"EXECUTE 'GRANT USAGE ON SCHEMA public TO {APP_ROLE}'; "
        f"EXECUTE 'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {APP_ROLE}'; END IF; END $$;"
    ]
    for table in TENANT_TABLES:
        grant = _GRANTS.get(table, _DEFAULT_GRANT)
        statements += [
            f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
            f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
            f"DROP POLICY IF EXISTS tenant_isolation ON {table}",
            f"CREATE POLICY tenant_isolation ON {table} "
            f"USING (tenant_id = current_setting('app.tenant_id', true)) "
            f"WITH CHECK (tenant_id = current_setting('app.tenant_id', true))",
            f"DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{APP_ROLE}') THEN "  # noqa: S608
            f"EXECUTE 'REVOKE ALL ON {table} FROM {APP_ROLE}'; "
            f"EXECUTE 'GRANT {grant} ON {table} TO {APP_ROLE}'; END IF; END $$;",
        ]
    return statements
