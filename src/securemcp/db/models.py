"""Relational schema. Every business table carries ``tenant_id``; PostgreSQL enforces it again with RLS."""

from __future__ import annotations

from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


# BigInteger primary keys must autoincrement on SQLite too (it only does so for INTEGER PRIMARY KEY).
AutoId = BigInteger().with_variant(Integer(), "sqlite")


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(32), nullable=False)  # == id; uniform RLS policy
    name: Mapped[str] = mapped_column(String(120))


class Client(Base):
    __tablename__ = "clients"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    segment: Mapped[str] = mapped_column(String(40))
    region: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20))
    account_tier: Mapped[str] = mapped_column(String(20))


class ClientContact(Base):
    __tablename__ = "client_contacts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    role: Mapped[str] = mapped_column(String(60))
    email: Mapped[str] = mapped_column(String(160))
    phone: Mapped[str] = mapped_column(String(40))
    is_primary: Mapped[bool] = mapped_column(Boolean, default=False)
    notify_opt_in: Mapped[bool] = mapped_column(Boolean, default=True)


class Camera(Base):
    __tablename__ = "cameras"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    site_name: Mapped[str] = mapped_column(String(80))
    model: Mapped[str] = mapped_column(String(60))
    firmware_version: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20))
    health_score: Mapped[int] = mapped_column(Integer)
    last_heartbeat_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    issue_code: Mapped[str | None] = mapped_column(String(40), nullable=True)


class Contract(Base):
    __tablename__ = "contracts"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    plan: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(20))
    start_date: Mapped[date] = mapped_column(Date)
    end_date: Mapped[date] = mapped_column(Date)
    sla_hours: Mapped[int] = mapped_column(Integer)


class ContractModule(Base):
    __tablename__ = "contract_modules"
    id: Mapped[int] = mapped_column(AutoId, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    contract_id: Mapped[str] = mapped_column(ForeignKey("contracts.id"), index=True)
    code: Mapped[str] = mapped_column(String(40))
    name: Mapped[str] = mapped_column(String(80))
    enabled: Mapped[bool] = mapped_column(Boolean)
    seats: Mapped[int] = mapped_column(Integer)


class SupportTicket(Base):
    __tablename__ = "tickets"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    camera_id: Mapped[str | None] = mapped_column(ForeignKey("cameras.id"), nullable=True)
    subject: Mapped[str] = mapped_column(String(120))
    description: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(20))
    priority: Mapped[str] = mapped_column(String(20))
    category: Mapped[str] = mapped_column(String(30))
    created_by: Mapped[str] = mapped_column(String(64))
    source: Mapped[str] = mapped_column(String(20), default="agent")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class MaintenanceWindowRow(Base):
    __tablename__ = "maintenance_windows"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    camera_ids: Mapped[list[str]] = mapped_column(JSON)
    starts_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ends_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(String(200))
    created_by: Mapped[str] = mapped_column(String(64))


class Notification(Base):
    __tablename__ = "notifications"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    client_id: Mapped[str] = mapped_column(ForeignKey("clients.id"), index=True)
    template: Mapped[str] = mapped_column(String(40))
    reference_id: Mapped[str] = mapped_column(String(32))
    audience: Mapped[str] = mapped_column(String(20))
    channel: Mapped[str] = mapped_column(String(10))
    recipients_count: Mapped[int] = mapped_column(Integer)
    external_id: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20))
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    operation: Mapped[str] = mapped_column(String(60))
    args_hash: Mapped[str] = mapped_column(String(64))
    summary: Mapped[dict[str, Any]] = mapped_column(JSON)
    risk: Mapped[str] = mapped_column(String(10))
    policy_id: Mapped[str] = mapped_column(String(120))
    reason: Mapped[str] = mapped_column(String(300))
    requested_by: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20))  # pending | approved | rejected | consumed
    decided_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    decision_note: Mapped[str | None] = mapped_column(String(300), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class IdempotencyRecord(Base):
    __tablename__ = "idempotency_records"
    __table_args__ = (UniqueConstraint("tenant_id", "subject", "operation", "idempotency_key", name="uq_idem"),)
    id: Mapped[int] = mapped_column(AutoId, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"))
    subject: Mapped[str] = mapped_column(String(64))
    operation: Mapped[str] = mapped_column(String(60))
    idempotency_key: Mapped[str] = mapped_column(String(64))
    request_hash: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(20))  # in_progress | approval_pending | completed
    response: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    approval_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "seq", name="uq_audit_seq"),
        Index("ix_audit_tenant_ts", "tenant_id", "ts"),
    )
    id: Mapped[int] = mapped_column(AutoId, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(32))  # may be "-" for unauthenticated attempts
    seq: Mapped[int] = mapped_column(BigInteger)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    request_id: Mapped[str] = mapped_column(String(64))
    trace_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    subject: Mapped[str | None] = mapped_column(String(64), nullable=True)
    client_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    operation: Mapped[str] = mapped_column(String(60))
    kind: Mapped[str] = mapped_column(String(12))
    status: Mapped[str] = mapped_column(String(24))
    error_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    policy_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    risk: Mapped[str | None] = mapped_column(String(10), nullable=True)
    duration_ms: Mapped[int] = mapped_column(Integer)
    args_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    idempotency_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approval_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    injection_signals: Mapped[list[str]] = mapped_column(JSON, default=list)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))


class AuditChainHead(Base):
    __tablename__ = "audit_chain_heads"
    tenant_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    seq: Mapped[int] = mapped_column(BigInteger)
    last_hash: Mapped[str] = mapped_column(String(64))


TENANT_TABLES = [
    "tenants",
    "clients",
    "client_contacts",
    "cameras",
    "contracts",
    "contract_modules",
    "tickets",
    "maintenance_windows",
    "notifications",
    "approvals",
    "idempotency_records",
    "audit_events",
    "audit_chain_heads",
]
