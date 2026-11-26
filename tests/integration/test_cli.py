"""The operator CLI: schema bootstrap with synthetic data, and audit-chain verification with a non-zero exit code."""

import asyncio
import sqlite3

from typer.testing import CliRunner

from securemcp.cli import app
from securemcp.config import Settings
from securemcp.db.database import Database
from securemcp.gateway.audit import AuditRecord, AuditTrail
from tests.helpers import ROOT

runner = CliRunner()


def test_db_init_and_audit_verify(tmp_path, monkeypatch):
    db_file = tmp_path / "cli.db"
    url = f"sqlite+aiosqlite:///{db_file}"
    for key, value in {
        "SECUREMCP_DATABASE_URL": url,
        "SECUREMCP_POLICY_FILE": str(ROOT / "config/policy.yaml"),
        "SECUREMCP_ENV": "test",
    }.items():
        monkeypatch.setenv(key, value)

    init = runner.invoke(app, ["db", "init", "--seed"])
    assert init.exit_code == 0, init.output
    assert '"clients": 5' in init.output

    async def write_events() -> None:
        db = Database(url)
        trail = AuditTrail(db)
        for i in range(3):
            await trail.append(
                AuditRecord(
                    request_id=f"req_{i}",
                    operation="get_client",
                    kind="tool",
                    tenant_id="tnt_aurora",
                    status="error",
                    error_code="FORBIDDEN",
                )
            )
        await db.dispose()

    asyncio.run(write_events())
    ok = runner.invoke(app, ["audit", "verify"])
    assert ok.exit_code == 0 and "tnt_aurora: 3 events, chain valid" in ok.output

    with sqlite3.connect(db_file) as conn:  # an operator with database access edits history
        conn.execute("UPDATE audit_events SET status = 'ok', error_code = NULL WHERE seq = 2")
    broken = runner.invoke(app, ["audit", "verify", "--tenant", "tnt_aurora"])
    assert broken.exit_code == 1 and "BROKEN at seq 2" in broken.output


def test_reset_refused_in_prod(monkeypatch, tmp_path):
    monkeypatch.setenv("SECUREMCP_ENV", "prod")
    monkeypatch.setenv("SECUREMCP_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/x.db")
    result = runner.invoke(app, ["db", "init", "--reset"])
    assert result.exit_code != 0


def test_settings_defaults_are_local_only():
    s = Settings(_env_file=None)
    assert s.bind_host == "127.0.0.1" and s.as_bind_host == "127.0.0.1" and s.mocks_bind_host == "127.0.0.1"
