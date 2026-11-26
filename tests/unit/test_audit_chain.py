import pytest
from sqlalchemy import update

from securemcp.db.database import Database, create_schema
from securemcp.db.models import AuditEvent
from securemcp.gateway.audit import AuditRecord, AuditTrail

pytestmark = pytest.mark.anyio


async def test_chain_verifies_and_detects_tampering(tmp_path):
    url = f"sqlite+aiosqlite:///{tmp_path}/a.db"
    await create_schema(url)
    db = Database(url)
    trail = AuditTrail(db)
    for i in range(5):
        await trail.append(
            AuditRecord(
                request_id=f"req_{i}",
                operation="get_client",
                kind="tool",
                tenant_id="tnt_aurora",
                subject="usr_aur_ana",
                status="ok",
            )
        )
    await trail.append(
        AuditRecord(request_id="req_b", operation="get_client", kind="tool", tenant_id="tnt_boreal", status="ok")
    )
    ok = await trail.verify("tnt_aurora")
    assert ok.valid and ok.events == 5
    events = await trail.events("tnt_aurora")
    assert [e.seq for e in events] == [1, 2, 3, 4, 5]
    assert events[0].prev_hash == "0" * 64 and events[1].prev_hash == events[0].hash

    async with db.tenant_session("tnt_aurora") as s:  # an attacker rewrites history
        await s.execute(update(AuditEvent).where(AuditEvent.seq == 3).values(status="denied"))
    broken = await trail.verify("tnt_aurora")
    assert not broken.valid and broken.first_bad_seq == 3
    assert (await trail.verify("tnt_boreal")).valid  # chains are per tenant
    await db.dispose()
