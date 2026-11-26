"""Approval workflow for high-risk writes (ADR-0007)."""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update

from securemcp.db.database import Database
from securemcp.db.models import Approval
from securemcp.errors import ErrorCode, GatewayError, not_found
from securemcp.schemas import ApprovalInfo
from securemcp.security.identity import Principal
from securemcp.security.policy import Decision


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _invalid(reason: str) -> GatewayError:
    return GatewayError(ErrorCode.APPROVAL_INVALID, reason, fields=["approval_id"])


class ApprovalStore:
    def __init__(self, db: Database, *, ttl_seconds: int, four_eyes: bool, clock=lambda: datetime.now(UTC)) -> None:
        self.db = db
        self.ttl = timedelta(seconds=ttl_seconds)
        self.four_eyes = four_eyes
        self.clock = clock

    async def create(
        self, p: Principal, operation: str, args_hash: str, summary: dict[str, Any], decision: Decision
    ) -> ApprovalInfo:
        now = self.clock()
        approval = Approval(
            id=f"apr_{secrets.token_hex(6)}",
            tenant_id=p.tenant_id,
            operation=operation,
            args_hash=args_hash,
            summary=summary,
            risk=decision.risk or "high",
            policy_id=decision.policy_id,
            reason=decision.reason,
            requested_by=p.subject,
            status="pending",
            created_at=now,
            expires_at=now + self.ttl,
        )
        async with self.db.tenant_session(p.tenant_id) as s:
            s.add(approval)
        return ApprovalInfo(
            approval_id=approval.id,
            expires_at=approval.expires_at,
            reason=decision.reason,
            policy_id=decision.policy_id,
        )

    async def consume(self, p: Principal, operation: str, args_hash: str, approval_id: str) -> None:
        """Atomically turn an approved, matching, unexpired approval into ``consumed`` (single use)."""
        now = self.clock()
        async with self.db.tenant_session(p.tenant_id) as s:
            row = (
                await s.execute(select(Approval).where(Approval.tenant_id == p.tenant_id, Approval.id == approval_id))
            ).scalar_one_or_none()
            if row is None:
                raise _invalid("approval not found")
            if row.operation != operation or row.args_hash != args_hash or row.requested_by != p.subject:
                raise _invalid("approval does not match this operation, these arguments or this requester")
            if _aware(row.expires_at) < now:
                raise _invalid("approval expired")
            if row.status != "approved":
                raise _invalid(f"approval is {row.status}")
            result = await s.execute(
                update(Approval)
                .where(Approval.tenant_id == p.tenant_id, Approval.id == approval_id, Approval.status == "approved")
                .values(status="consumed")
            )
            if result.rowcount != 1:
                raise _invalid("approval was already used")

    async def list_pending(self, p: Principal) -> list[dict[str, Any]]:
        now = self.clock()
        async with self.db.tenant_session(p.tenant_id) as s:
            rows = (
                (
                    await s.execute(
                        select(Approval)
                        .where(Approval.tenant_id == p.tenant_id, Approval.status == "pending")
                        .order_by(Approval.created_at)
                    )
                )
                .scalars()
                .all()
            )
        return [self._view(r) for r in rows if _aware(r.expires_at) >= now]

    async def decide(self, p: Principal, approval_id: str, approve: bool, note: str | None) -> dict[str, Any]:
        now = self.clock()
        async with self.db.tenant_session(p.tenant_id) as s:
            row = (
                await s.execute(select(Approval).where(Approval.tenant_id == p.tenant_id, Approval.id == approval_id))
            ).scalar_one_or_none()
            if row is None:
                raise not_found("approval")
            if self.four_eyes and row.requested_by == p.subject:
                raise GatewayError(ErrorCode.FORBIDDEN, "four-eyes rule: the requester cannot decide")
            if row.status != "pending" or _aware(row.expires_at) < now:
                raise GatewayError(ErrorCode.CONFLICT, "approval is no longer pending")
            row.status = "approved" if approve else "rejected"
            row.decided_by = p.subject
            row.decided_at = now
            row.decision_note = note
            return self._view(row)

    @staticmethod
    def _view(row: Approval) -> dict[str, Any]:
        return {
            "approval_id": row.id,
            "operation": row.operation,
            "status": row.status,
            "risk": row.risk,
            "reason": row.reason,
            "policy_id": row.policy_id,
            "requested_by": row.requested_by,
            "decided_by": row.decided_by,
            "summary": row.summary,
            "expires_at": _aware(row.expires_at).isoformat(),
        }
