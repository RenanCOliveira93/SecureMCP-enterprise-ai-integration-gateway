"""Named, parameterised queries. Every method takes ``tenant_id`` first and filters by it (ADR-0005, layer 2).

There is intentionally no method that accepts SQL text, table names, column names or sort expressions from callers.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from securemcp.db.models import (
    Camera,
    Client,
    ClientContact,
    Contract,
    ContractModule,
    MaintenanceWindowRow,
    Notification,
    SupportTicket,
)

_STATUS_SEVERITY = case(
    (Camera.status == "offline", 0),
    (Camera.status == "degraded", 1),
    else_=2,
)


def escape_like(text: str) -> str:
    """Make user text match literally inside LIKE (escape character is backslash)."""
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class ClientRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.s = session

    async def get(self, tenant_id: str, client_id: str) -> Client | None:
        stmt = select(Client).where(Client.tenant_id == tenant_id, Client.id == client_id)
        return (await self.s.execute(stmt)).scalar_one_or_none()

    async def contacts(self, tenant_id: str, client_id: str) -> Sequence[ClientContact]:
        stmt = (
            select(ClientContact)
            .where(ClientContact.tenant_id == tenant_id, ClientContact.client_id == client_id)
            .order_by(ClientContact.is_primary.desc(), ClientContact.id)
        )
        return (await self.s.execute(stmt)).scalars().all()


class CameraRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.s = session

    async def get(self, tenant_id: str, camera_id: str) -> Camera | None:
        stmt = select(Camera).where(Camera.tenant_id == tenant_id, Camera.id == camera_id)
        return (await self.s.execute(stmt)).scalar_one_or_none()

    async def list_for_client(self, tenant_id: str, client_id: str, status: str | None, limit: int) -> Sequence[Camera]:
        stmt = select(Camera).where(Camera.tenant_id == tenant_id, Camera.client_id == client_id)
        if status is not None:
            stmt = stmt.where(Camera.status == status)
        stmt = stmt.order_by(_STATUS_SEVERITY, Camera.health_score, Camera.id).limit(limit)
        return (await self.s.execute(stmt)).scalars().all()

    async def status_counts(self, tenant_id: str, client_id: str) -> dict[str, int]:
        stmt = (
            select(Camera.status, func.count())
            .where(Camera.tenant_id == tenant_id, Camera.client_id == client_id)
            .group_by(Camera.status)
        )
        return {status: count for status, count in (await self.s.execute(stmt)).all()}

    async def existing_ids(self, tenant_id: str, client_id: str, camera_ids: Sequence[str]) -> set[str]:
        stmt = select(Camera.id).where(
            Camera.tenant_id == tenant_id, Camera.client_id == client_id, Camera.id.in_(list(camera_ids))
        )
        return set((await self.s.execute(stmt)).scalars().all())


class ContractRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.s = session

    async def active_for_client(self, tenant_id: str, client_id: str) -> Contract | None:
        stmt = (
            select(Contract)
            .where(Contract.tenant_id == tenant_id, Contract.client_id == client_id, Contract.status == "active")
            .order_by(Contract.end_date.desc())
            .limit(1)
        )
        return (await self.s.execute(stmt)).scalar_one_or_none()

    async def modules(self, tenant_id: str, contract_id: str) -> Sequence[ContractModule]:
        stmt = (
            select(ContractModule)
            .where(ContractModule.tenant_id == tenant_id, ContractModule.contract_id == contract_id)
            .order_by(ContractModule.code)
        )
        return (await self.s.execute(stmt)).scalars().all()


class TicketRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.s = session

    async def get(self, tenant_id: str, ticket_id: str) -> SupportTicket | None:
        stmt = select(SupportTicket).where(SupportTicket.tenant_id == tenant_id, SupportTicket.id == ticket_id)
        return (await self.s.execute(stmt)).scalar_one_or_none()

    async def search(
        self,
        tenant_id: str,
        *,
        client_id: str | None,
        status: str | None,
        priority: str | None,
        text: str | None,
        limit: int,
    ) -> Sequence[SupportTicket]:
        stmt = select(SupportTicket).where(SupportTicket.tenant_id == tenant_id)
        if client_id is not None:
            stmt = stmt.where(SupportTicket.client_id == client_id)
        if status is not None:
            stmt = stmt.where(SupportTicket.status == status)
        if priority is not None:
            stmt = stmt.where(SupportTicket.priority == priority)
        if text:
            pattern = f"%{escape_like(text)}%"
            stmt = stmt.where(
                or_(
                    SupportTicket.subject.ilike(pattern, escape="\\"),
                    SupportTicket.description.ilike(pattern, escape="\\"),
                )
            )
        stmt = stmt.order_by(SupportTicket.created_at.desc(), SupportTicket.id).limit(limit)
        return (await self.s.execute(stmt)).scalars().all()

    async def count_open(self, tenant_id: str, client_id: str) -> int:
        stmt = select(func.count()).where(
            SupportTicket.tenant_id == tenant_id,
            SupportTicket.client_id == client_id,
            SupportTicket.status.in_(["open", "in_progress"]),
        )
        return int((await self.s.execute(stmt)).scalar_one())

    async def add(self, ticket: SupportTicket) -> None:
        self.s.add(ticket)
        await self.s.flush()


class MaintenanceRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.s = session

    async def get(self, tenant_id: str, maintenance_id: str) -> MaintenanceWindowRow | None:
        stmt = select(MaintenanceWindowRow).where(
            MaintenanceWindowRow.tenant_id == tenant_id, MaintenanceWindowRow.id == maintenance_id
        )
        return (await self.s.execute(stmt)).scalar_one_or_none()

    async def between(
        self, tenant_id: str, client_id: str, start: datetime, end: datetime
    ) -> Sequence[MaintenanceWindowRow]:
        stmt = (
            select(MaintenanceWindowRow)
            .where(
                MaintenanceWindowRow.tenant_id == tenant_id,
                MaintenanceWindowRow.client_id == client_id,
                MaintenanceWindowRow.ends_at >= start,
                MaintenanceWindowRow.starts_at <= end,
            )
            .order_by(MaintenanceWindowRow.starts_at)
        )
        return (await self.s.execute(stmt)).scalars().all()

    async def scheduled_overlapping(
        self, tenant_id: str, client_id: str, start: datetime, end: datetime
    ) -> Sequence[MaintenanceWindowRow]:
        stmt = select(MaintenanceWindowRow).where(
            MaintenanceWindowRow.tenant_id == tenant_id,
            MaintenanceWindowRow.client_id == client_id,
            MaintenanceWindowRow.status == "scheduled",
            MaintenanceWindowRow.starts_at < end,
            MaintenanceWindowRow.ends_at > start,
        )
        return (await self.s.execute(stmt)).scalars().all()

    async def add(self, row: MaintenanceWindowRow) -> None:
        self.s.add(row)
        await self.s.flush()


class NotificationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self.s = session

    async def add(self, row: Notification) -> None:
        self.s.add(row)
        await self.s.flush()
