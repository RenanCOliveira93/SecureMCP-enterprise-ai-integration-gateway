"""Idempotency records for write operations (ADR-0006)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError

from securemcp.db.database import Database
from securemcp.db.models import IdempotencyRecord
from securemcp.errors import ErrorCode, GatewayError
from securemcp.security.identity import Principal

STALE_IN_PROGRESS = timedelta(seconds=60)


class ClaimOutcome(StrEnum):
    NEW = "new"  # execute
    REPLAY = "replay"  # return stored response, no side effect
    APPROVAL_PENDING = "approval_pending"  # an approval was requested earlier with the same key


@dataclass(frozen=True)
class Claim:
    outcome: ClaimOutcome
    record_id: int
    response: dict[str, Any] | None = None
    approval_id: str | None = None


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


class IdempotencyStore:
    def __init__(self, db: Database, ttl: timedelta, clock=lambda: datetime.now(UTC)) -> None:
        self.db = db
        self.ttl = ttl
        self.clock = clock

    async def claim(self, p: Principal, operation: str, key: str, request_hash: str) -> Claim:
        now = self.clock()
        try:
            async with self.db.tenant_session(p.tenant_id) as s:
                row = (
                    await s.execute(
                        select(IdempotencyRecord).where(
                            IdempotencyRecord.tenant_id == p.tenant_id,
                            IdempotencyRecord.subject == p.subject,
                            IdempotencyRecord.operation == operation,
                            IdempotencyRecord.idempotency_key == key,
                        )
                    )
                ).scalar_one_or_none()
                if row is not None and _aware(row.expires_at) < now:
                    await s.delete(row)
                    await s.flush()
                    row = None
                if row is not None:
                    if row.request_hash != request_hash:
                        raise GatewayError(
                            ErrorCode.IDEMPOTENCY_CONFLICT,
                            "idempotency_key was already used with different arguments; use a new key",
                        )
                    if row.status == "completed":
                        return Claim(ClaimOutcome.REPLAY, row.id, row.response)
                    if row.status == "approval_pending":
                        return Claim(ClaimOutcome.APPROVAL_PENDING, row.id, row.response, row.approval_id)
                    if now - _aware(row.updated_at) < STALE_IN_PROGRESS:
                        raise GatewayError(
                            ErrorCode.IDEMPOTENCY_IN_PROGRESS, "a call with this idempotency_key is still running"
                        )
                    row.updated_at = now  # take over a stale claim left by a crashed worker
                    return Claim(ClaimOutcome.NEW, row.id)
                record = IdempotencyRecord(
                    tenant_id=p.tenant_id,
                    subject=p.subject,
                    operation=operation,
                    idempotency_key=key,
                    request_hash=request_hash,
                    status="in_progress",
                    created_at=now,
                    updated_at=now,
                    expires_at=now + self.ttl,
                )
                s.add(record)
                await s.flush()
                return Claim(ClaimOutcome.NEW, record.id)
        except IntegrityError as exc:  # a concurrent call inserted the same key first
            raise GatewayError(
                ErrorCode.IDEMPOTENCY_IN_PROGRESS, "a call with this idempotency_key is still running"
            ) from exc

    async def resume(self, p: Principal, record_id: int) -> None:
        await self._set(p, record_id, status="in_progress")

    async def complete(self, p: Principal, record_id: int, response: dict[str, Any]) -> None:
        await self._set(p, record_id, status="completed", response=response)

    async def await_approval(self, p: Principal, record_id: int, response: dict[str, Any], approval_id: str) -> None:
        await self._set(p, record_id, status="approval_pending", response=response, approval_id=approval_id)

    async def release(self, p: Principal, record_id: int) -> None:
        """Forget a failed attempt so the caller can retry with the same key."""
        async with self.db.tenant_session(p.tenant_id) as s:
            await s.execute(
                delete(IdempotencyRecord).where(
                    IdempotencyRecord.tenant_id == p.tenant_id, IdempotencyRecord.id == record_id
                )
            )

    async def _set(self, p: Principal, record_id: int, **values: Any) -> None:
        async with self.db.tenant_session(p.tenant_id) as s:
            await s.execute(
                update(IdempotencyRecord)
                .where(IdempotencyRecord.tenant_id == p.tenant_id, IdempotencyRecord.id == record_id)
                .values(updated_at=self.clock(), **values)
            )
