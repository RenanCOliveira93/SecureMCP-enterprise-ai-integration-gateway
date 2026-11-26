"""Business rules for the Nexus Sight domain. Services know nothing about MCP; they receive a verified
``Principal`` plus a validated input model and return an output model.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import UTC, datetime, time, timedelta
from pathlib import Path

from securemcp.db.database import Database
from securemcp.db.models import MaintenanceWindowRow, Notification, SupportTicket
from securemcp.db.repositories import (
    CameraRepository,
    ClientRepository,
    ContractRepository,
    MaintenanceRepository,
    NotificationRepository,
    TicketRepository,
)
from securemcp.errors import ErrorCode, GatewayError, not_found
from securemcp.integrations.clients import CrmClient, NotificationClient
from securemcp.schemas import (
    CameraHealth,
    CameraHealthInput,
    CameraHealthList,
    CameraSummary,
    ClientSummary,
    ClientSummaryInput,
    ClientView,
    Contact,
    ContractModule,
    ContractModules,
    CreateSupportTicketInput,
    CrmAccount,
    GetClientInput,
    GetContractModulesInput,
    GetMaintenanceWindowInput,
    ListCameraHealthInput,
    MaintenanceCalendar,
    MaintenanceScheduled,
    MaintenanceWindow,
    Manual,
    ManualIndex,
    ManualInput,
    NoInput,
    NotificationSent,
    ScheduleMaintenanceInput,
    SearchTicketsInput,
    SendNotificationInput,
    Ticket,
    TicketCreated,
    TicketInput,
    TicketSearchResult,
    TicketView,
)
from securemcp.security.identity import Principal
from securemcp.security.sanitize import mask_email, mask_phone

log = logging.getLogger(__name__)

CRM_BUDGET_SECONDS = 1.5  # get_client degrades instead of failing when the CRM is slower than this
MIN_LEAD_TIME = timedelta(hours=1)


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_hex(5)}"


def _aware(value: datetime) -> datetime:
    # SQLite returns naive datetimes; everything we store is UTC.
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _camera(row) -> CameraHealth:
    return CameraHealth(
        camera_id=row.id,
        client_id=row.client_id,
        site_name=row.site_name,
        model=row.model,
        firmware_version=row.firmware_version,
        status=row.status,
        health_score=row.health_score,
        last_heartbeat_at=_aware(row.last_heartbeat_at),
        issue_code=row.issue_code,
    )


def _ticket(row) -> Ticket:
    return Ticket(
        ticket_id=row.id,
        client_id=row.client_id,
        camera_id=row.camera_id,
        subject=row.subject,
        description=row.description,
        status=row.status,
        priority=row.priority,
        category=row.category,
        created_at=_aware(row.created_at),
    )


def _window(row) -> MaintenanceWindow:
    return MaintenanceWindow(
        maintenance_id=row.id,
        starts_at=_aware(row.starts_at),
        ends_at=_aware(row.ends_at),
        status=row.status,
        camera_ids=list(row.camera_ids),
        reason=row.reason,
    )


def _summary(counts: dict[str, int]) -> CameraSummary:
    online, degraded, offline = counts.get("online", 0), counts.get("degraded", 0), counts.get("offline", 0)
    return CameraSummary(online=online, degraded=degraded, offline=offline, total=online + degraded + offline)


class NexusServices:
    def __init__(
        self,
        db: Database,
        crm: CrmClient,
        notifications: NotificationClient,
        docs_dir: Path,
        clock=lambda: datetime.now(UTC),
    ) -> None:
        self.db = db
        self.crm = crm
        self.notifications = notifications
        self.docs_dir = docs_dir
        self.clock = clock

    # ------------------------------------------------------------------ clients
    async def get_client(self, p: Principal, inp: GetClientInput) -> ClientView:
        async with self.db.tenant_session(p.tenant_id) as s:
            repo = ClientRepository(s)
            client = await repo.get(p.tenant_id, inp.client_id)
            if client is None:
                raise not_found("client")
            contacts = await repo.contacts(p.tenant_id, client.id)
        return ClientView(
            client_id=client.id,
            name=client.name,
            segment=client.segment,
            region=client.region,
            status=client.status,
            account_tier=client.account_tier,
            contacts=[
                Contact(
                    contact_id=c.id,
                    name=c.name,
                    role=c.role,
                    email_masked=mask_email(c.email),
                    phone_masked=mask_phone(c.phone),
                    notify_opt_in=c.notify_opt_in,
                )
                for c in contacts
            ],
            crm=await self._crm_account(p, client.id),
        )

    async def _crm_account(self, p: Principal, client_id: str) -> CrmAccount:
        try:
            async with asyncio.timeout(CRM_BUDGET_SECONDS):
                data = await self.crm.get_account(p, client_id)
            return CrmAccount(
                status="ok",
                account_manager=data.get("account_manager"),
                health=data.get("health"),
                open_opportunities=data.get("open_opportunities"),
            )
        except (GatewayError, TimeoutError, ValueError) as exc:
            log.warning("CRM degraded for get_client: %s", getattr(exc, "code", type(exc).__name__))
            return CrmAccount(status="unavailable")

    async def client_summary(self, p: Principal, inp: ClientSummaryInput) -> ClientSummary:
        async with self.db.tenant_session(p.tenant_id) as s:
            client = await ClientRepository(s).get(p.tenant_id, inp.client_id)
            if client is None:
                raise not_found("client")
            counts = await CameraRepository(s).status_counts(p.tenant_id, client.id)
            contract = await ContractRepository(s).active_for_client(p.tenant_id, client.id)
            open_tickets = await TicketRepository(s).count_open(p.tenant_id, client.id)
            now = self.clock()
            windows = await MaintenanceRepository(s).between(p.tenant_id, client.id, now, now + timedelta(days=90))
        upcoming = [w for w in windows if w.status == "scheduled"]
        return ClientSummary(
            client_id=client.id,
            name=client.name,
            segment=client.segment,
            status=client.status,
            plan=contract.plan if contract else None,
            cameras=_summary(counts),
            open_tickets=open_tickets,
            next_maintenance_at=_aware(upcoming[0].starts_at) if upcoming else None,
        )

    async def ensure_client(self, p: Principal, client_id: str) -> None:
        async with self.db.tenant_session(p.tenant_id) as s:
            if await ClientRepository(s).get(p.tenant_id, client_id) is None:
                raise not_found("client")

    # ------------------------------------------------------------------ cameras
    async def list_camera_health(self, p: Principal, inp: ListCameraHealthInput) -> CameraHealthList:
        async with self.db.tenant_session(p.tenant_id) as s:
            if await ClientRepository(s).get(p.tenant_id, inp.client_id) is None:
                raise not_found("client")
            repo = CameraRepository(s)
            rows = await repo.list_for_client(p.tenant_id, inp.client_id, inp.status, inp.limit + 1)
            counts = await repo.status_counts(p.tenant_id, inp.client_id)
        return CameraHealthList(
            client_id=inp.client_id,
            summary=_summary(counts),
            cameras=[_camera(r) for r in rows[: inp.limit]],
            truncated=len(rows) > inp.limit,
        )

    async def camera_health(self, p: Principal, inp: CameraHealthInput) -> CameraHealth:
        async with self.db.tenant_session(p.tenant_id) as s:
            row = await CameraRepository(s).get(p.tenant_id, inp.camera_id)
        if row is None:
            raise not_found("camera")
        return _camera(row)

    # ---------------------------------------------------------------- contracts
    async def get_contract_modules(self, p: Principal, inp: GetContractModulesInput) -> ContractModules:
        async with self.db.tenant_session(p.tenant_id) as s:
            if await ClientRepository(s).get(p.tenant_id, inp.client_id) is None:
                raise not_found("client")
            repo = ContractRepository(s)
            contract = await repo.active_for_client(p.tenant_id, inp.client_id)
            if contract is None:
                raise not_found("active contract")
            modules = await repo.modules(p.tenant_id, contract.id)
        return ContractModules(
            client_id=inp.client_id,
            contract_id=contract.id,
            plan=contract.plan,
            status=contract.status,
            start_date=contract.start_date,
            end_date=contract.end_date,
            sla_hours=contract.sla_hours,
            modules=[ContractModule(code=m.code, name=m.name, enabled=m.enabled, seats=m.seats) for m in modules],
        )

    # ------------------------------------------------------------------ tickets
    async def search_tickets(self, p: Principal, inp: SearchTicketsInput) -> TicketSearchResult:
        async with self.db.tenant_session(p.tenant_id) as s:
            rows = await TicketRepository(s).search(
                p.tenant_id,
                client_id=inp.client_id,
                status=inp.status,
                priority=inp.priority,
                text=inp.text,
                limit=inp.limit,
            )
        return TicketSearchResult(
            tickets=[_ticket(r) for r in rows],
            untrusted_fields=["tickets[].subject", "tickets[].description"],
        )

    async def get_ticket(self, p: Principal, inp: TicketInput) -> TicketView:
        async with self.db.tenant_session(p.tenant_id) as s:
            row = await TicketRepository(s).get(p.tenant_id, inp.ticket_id)
        if row is None:
            raise not_found("ticket")
        return TicketView(ticket=_ticket(row), untrusted_fields=["ticket.subject", "ticket.description"])

    async def create_support_ticket(self, p: Principal, inp: CreateSupportTicketInput) -> TicketCreated:
        async with self.db.tenant_session(p.tenant_id) as s:
            if await ClientRepository(s).get(p.tenant_id, inp.client_id) is None:
                raise not_found("client")
            if inp.camera_id is not None:
                found = await CameraRepository(s).existing_ids(p.tenant_id, inp.client_id, [inp.camera_id])
                if not found:
                    raise not_found("camera")
            ticket = SupportTicket(
                id=new_id("tkt"),
                tenant_id=p.tenant_id,
                client_id=inp.client_id,
                camera_id=inp.camera_id,
                subject=inp.subject,
                description=inp.description,
                status="open",
                priority=inp.priority,
                category=inp.category,
                created_by=p.subject,
                source="agent",
                created_at=self.clock(),
            )
            await TicketRepository(s).add(ticket)
        return TicketCreated(
            status="completed",
            ticket_id=ticket.id,
            ticket_status="open",
            priority=inp.priority,
            client_id=inp.client_id,
        )

    # -------------------------------------------------------------- maintenance
    async def get_maintenance_window(self, p: Principal, inp: GetMaintenanceWindowInput) -> MaintenanceCalendar:
        start_day = inp.from_date or self.clock().date()
        start = datetime.combine(start_day, time.min, tzinfo=UTC)
        end = start + timedelta(days=inp.days)
        async with self.db.tenant_session(p.tenant_id) as s:
            if await ClientRepository(s).get(p.tenant_id, inp.client_id) is None:
                raise not_found("client")
            rows = await MaintenanceRepository(s).between(p.tenant_id, inp.client_id, start, end)
        windows = [_window(r) for r in rows]
        now = self.clock()
        upcoming = [w for w in windows if w.status == "scheduled" and w.starts_at >= now]
        return MaintenanceCalendar(
            client_id=inp.client_id, windows=windows, next_window=upcoming[0] if upcoming else None
        )

    async def schedule_maintenance(self, p: Principal, inp: ScheduleMaintenanceInput) -> MaintenanceScheduled:
        if len(set(inp.camera_ids)) != len(inp.camera_ids):
            raise GatewayError(ErrorCode.INVALID_ARGUMENT, "camera_ids must be unique", fields=["camera_ids"])
        starts_at = inp.starts_at.astimezone(UTC)
        if starts_at < self.clock() + MIN_LEAD_TIME:
            raise GatewayError(
                ErrorCode.INVALID_ARGUMENT, "starts_at must be at least 1 hour in the future", fields=["starts_at"]
            )
        ends_at = starts_at + timedelta(minutes=inp.duration_minutes)
        async with self.db.tenant_session(p.tenant_id) as s:
            if await ClientRepository(s).get(p.tenant_id, inp.client_id) is None:
                raise not_found("client")
            found = await CameraRepository(s).existing_ids(p.tenant_id, inp.client_id, inp.camera_ids)
            if found != set(inp.camera_ids):
                raise not_found("camera")
            contract = await ContractRepository(s).active_for_client(p.tenant_id, inp.client_id)
            if contract is None or not (
                contract.start_date <= starts_at.date() and ends_at.date() <= contract.end_date
            ):
                raise GatewayError(ErrorCode.CONFLICT, "window is outside the active contract period")
            repo = MaintenanceRepository(s)
            for other in await repo.scheduled_overlapping(p.tenant_id, inp.client_id, starts_at, ends_at):
                if set(other.camera_ids) & set(inp.camera_ids):
                    raise GatewayError(ErrorCode.CONFLICT, f"overlaps maintenance window {other.id}")
            row = MaintenanceWindowRow(
                id=new_id("mnt"),
                tenant_id=p.tenant_id,
                client_id=inp.client_id,
                camera_ids=list(inp.camera_ids),
                starts_at=starts_at,
                ends_at=ends_at,
                status="scheduled",
                reason=inp.reason,
                created_by=p.subject,
            )
            await repo.add(row)
        return MaintenanceScheduled(
            status="completed",
            maintenance_id=row.id,
            starts_at=starts_at,
            ends_at=ends_at,
            camera_count=len(inp.camera_ids),
        )

    # ------------------------------------------------------------ notifications
    async def send_notification(self, p: Principal, inp: SendNotificationInput) -> NotificationSent:
        async with self.db.tenant_session(p.tenant_id) as s:
            client = await ClientRepository(s).get(p.tenant_id, inp.client_id)
            if client is None:
                raise not_found("client")
            if inp.template == "maintenance_notice":
                if not inp.reference_id.startswith("mnt_"):
                    raise GatewayError(
                        ErrorCode.INVALID_ARGUMENT, "maintenance_notice needs a maintenance id", fields=["reference_id"]
                    )
                window = await MaintenanceRepository(s).get(p.tenant_id, inp.reference_id)
                if window is None or window.client_id != client.id:
                    raise not_found("maintenance window")
                body = (
                    f"Scheduled maintenance for {client.name}: {_aware(window.starts_at):%Y-%m-%d %H:%M} UTC to "
                    f"{_aware(window.ends_at):%H:%M} UTC, {len(window.camera_ids)} camera(s). Reference {window.id}."
                )
            else:
                if not inp.reference_id.startswith("tkt_"):
                    raise GatewayError(
                        ErrorCode.INVALID_ARGUMENT, f"{inp.template} needs a ticket id", fields=["reference_id"]
                    )
                ticket = await TicketRepository(s).get(p.tenant_id, inp.reference_id)
                if ticket is None or ticket.client_id != client.id:
                    raise not_found("ticket")
                # Only structured fields go out: free text written by others is never forwarded to customers.
                body = (
                    f"Update on support ticket {ticket.id} for {client.name}: status {ticket.status}, "
                    f"priority {ticket.priority}. Our team will contact you if action is needed."
                )
            contacts = [c for c in await ClientRepository(s).contacts(p.tenant_id, client.id) if c.notify_opt_in]
            if inp.audience == "primary_contact":
                contacts = [c for c in contacts if c.is_primary]
            if not contacts:
                raise GatewayError(ErrorCode.CONFLICT, "no opted-in contact matches the requested audience")
            recipients = [c.email if inp.channel == "email" else c.phone for c in contacts]

        result = await self.notifications.send(
            p,
            {
                "channel": inp.channel,
                "template": inp.template,
                "recipients": recipients,
                "subject": f"[Nexus Sight] {inp.template.replace('_', ' ').title()}",
                "body": body,
                "reference_id": inp.reference_id,
            },
            inp.idempotency_key,
        )
        notification_id = new_id("ntf")
        async with self.db.tenant_session(p.tenant_id) as s:
            await NotificationRepository(s).add(
                Notification(
                    id=notification_id,
                    tenant_id=p.tenant_id,
                    client_id=client.id,
                    template=inp.template,
                    reference_id=inp.reference_id,
                    audience=inp.audience,
                    channel=inp.channel,
                    recipients_count=len(recipients),
                    external_id=str(result.get("message_id", "")),
                    status=str(result.get("status", "queued")),
                    created_by=p.subject,
                    created_at=self.clock(),
                )
            )
        return NotificationSent(
            status="completed",
            notification_id=notification_id,
            recipients_count=len(recipients),
            delivery_status="queued" if result.get("status") != "sent" else "sent",
        )

    # --------------------------------------------------------------------- docs
    def _manual_path(self, version: str) -> Path:
        base = self.docs_dir.resolve()
        path = (base / f"{version}.md").resolve()
        if base not in path.parents:  # defense in depth; the version pattern already forbids separators
            raise not_found("manual")
        return path

    async def manual(self, p: Principal, inp: ManualInput) -> Manual:
        path = self._manual_path(inp.version)
        if not path.is_file():
            raise not_found("manual")
        body = path.read_text(encoding="utf-8")
        title = next((line.lstrip("# ").strip() for line in body.splitlines() if line.startswith("#")), inp.version)
        return Manual(version=inp.version, title=title, body_markdown=body, untrusted_fields=["body_markdown"])

    async def manual_index(self, p: Principal, inp: NoInput) -> ManualIndex:
        versions = sorted(path.stem for path in self.docs_dir.glob("v*.md"))
        return ManualIndex(versions=versions)
