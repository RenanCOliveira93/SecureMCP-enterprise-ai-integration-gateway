"""Hash-chained, per-tenant audit trail (ADR-0010)."""

from __future__ import annotations

import asyncio
import hashlib
import logging
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime

from sqlalchemy import select

from securemcp.db.database import Database
from securemcp.db.models import AuditChainHead, AuditEvent
from securemcp.security.sanitize import canonical_json, redact

log = logging.getLogger("securemcp.audit")

GENESIS = "0" * 64
NO_TENANT = "-"


@dataclass
class AuditRecord:
    request_id: str
    operation: str
    kind: str
    tenant_id: str = NO_TENANT
    subject: str | None = None
    client_id: str | None = None
    trace_id: str | None = None
    status: str = "error"
    error_code: str | None = None
    policy_id: str | None = None
    policy_version: str | None = None
    risk: str | None = None
    duration_ms: int = 0
    args_fingerprint: str | None = None
    idempotency_key: str | None = None
    approval_id: str | None = None
    injection_signals: list[str] = field(default_factory=list)
    ts: datetime = field(default_factory=lambda: datetime.now(UTC))


def _event_hash(prev_hash: str, seq: int, record: AuditRecord) -> str:
    body = asdict(record)
    body["ts"] = record.ts.astimezone(UTC).isoformat()
    body["seq"] = seq
    return hashlib.sha256((prev_hash + canonical_json(body)).encode()).hexdigest()


@dataclass(frozen=True)
class ChainVerification:
    tenant_id: str
    events: int
    valid: bool
    first_bad_seq: int | None = None


class AuditTrail:
    def __init__(self, db: Database) -> None:
        self.db = db
        # In-process serialisation per tenant; the chain-head row lock covers multiple replicas on PostgreSQL.
        self._locks: defaultdict[str, asyncio.Lock] = defaultdict(asyncio.Lock)

    async def append(self, record: AuditRecord) -> None:
        async with self._locks[record.tenant_id], self.db.tenant_session(record.tenant_id) as s:
            head = (
                await s.execute(
                    select(AuditChainHead).where(AuditChainHead.tenant_id == record.tenant_id).with_for_update()
                )
            ).scalar_one_or_none()
            if head is None:
                head = AuditChainHead(tenant_id=record.tenant_id, seq=0, last_hash=GENESIS)
                s.add(head)
            seq = head.seq + 1
            digest = _event_hash(head.last_hash, seq, record)
            s.add(
                AuditEvent(
                    tenant_id=record.tenant_id,
                    seq=seq,
                    ts=record.ts,
                    request_id=record.request_id,
                    trace_id=record.trace_id,
                    subject=record.subject,
                    client_id=record.client_id,
                    operation=record.operation,
                    kind=record.kind,
                    status=record.status,
                    error_code=record.error_code,
                    policy_id=record.policy_id,
                    policy_version=record.policy_version,
                    risk=record.risk,
                    duration_ms=record.duration_ms,
                    args_fingerprint=record.args_fingerprint,
                    idempotency_key=record.idempotency_key,
                    approval_id=record.approval_id,
                    injection_signals=list(record.injection_signals),
                    prev_hash=head.last_hash,
                    hash=digest,
                )
            )
            head.seq = seq
            head.last_hash = digest

    async def safe_append(self, record: AuditRecord) -> None:
        """Never let an audit failure change the response; keep the (redacted) event in logs for recovery."""
        try:
            await self.append(record)
        except Exception:
            log.exception("AUDIT WRITE FAILED: %s", redact(canonical_json(asdict(record))))

    async def events(self, tenant_id: str, limit: int = 1000) -> list[AuditEvent]:
        async with self.db.tenant_session(tenant_id) as s:
            stmt = select(AuditEvent).where(AuditEvent.tenant_id == tenant_id).order_by(AuditEvent.seq).limit(limit)
            return list((await s.execute(stmt)).scalars().all())

    async def verify(self, tenant_id: str) -> ChainVerification:
        prev = GENESIS
        rows = await self.events(tenant_id, limit=10_000_000)
        for row in rows:
            record = AuditRecord(
                request_id=row.request_id,
                operation=row.operation,
                kind=row.kind,
                tenant_id=row.tenant_id,
                subject=row.subject,
                client_id=row.client_id,
                trace_id=row.trace_id,
                status=row.status,
                error_code=row.error_code,
                policy_id=row.policy_id,
                policy_version=row.policy_version,
                risk=row.risk,
                duration_ms=row.duration_ms,
                args_fingerprint=row.args_fingerprint,
                idempotency_key=row.idempotency_key,
                approval_id=row.approval_id,
                injection_signals=list(row.injection_signals or []),
                ts=row.ts if row.ts.tzinfo else row.ts.replace(tzinfo=UTC),
            )
            if row.prev_hash != prev or _event_hash(prev, row.seq, record) != row.hash:
                return ChainVerification(tenant_id, len(rows), False, row.seq)
            prev = row.hash
        return ChainVerification(tenant_id, len(rows), True)
