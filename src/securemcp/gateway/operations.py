"""Binds every allowed operation name to its input model, output model and service handler."""

from __future__ import annotations

from securemcp.gateway.approvals import ApprovalStore
from securemcp.gateway.pipeline import Gateway
from securemcp.schemas import (
    ApprovalList,
    ApprovalView,
    CameraHealth,
    CameraHealthInput,
    CameraHealthList,
    ClientSummary,
    ClientSummaryInput,
    ClientView,
    ContractModules,
    CreateSupportTicketInput,
    CustomerSupportSummaryInput,
    DecideApprovalInput,
    GetClientInput,
    GetContractModulesInput,
    GetMaintenanceWindowInput,
    IncidentTriageInput,
    ListCameraHealthInput,
    MaintenanceCalendar,
    MaintenancePlanInput,
    MaintenanceScheduled,
    Manual,
    ManualIndex,
    ManualInput,
    NoInput,
    NotificationSent,
    RenderedPrompt,
    ScheduleMaintenanceInput,
    SearchTicketsInput,
    SendNotificationInput,
    TicketCreated,
    TicketInput,
    TicketSearchResult,
    TicketView,
)
from securemcp.security.identity import Principal
from securemcp.services.domain import NexusServices
from securemcp.services.prompts import PromptService


def register_operations(gw: Gateway, svc: NexusServices, prompts: PromptService, approvals: ApprovalStore) -> None:
    # tools
    gw.register("get_client", GetClientInput, ClientView, svc.get_client)
    gw.register("list_camera_health", ListCameraHealthInput, CameraHealthList, svc.list_camera_health)
    gw.register("get_contract_modules", GetContractModulesInput, ContractModules, svc.get_contract_modules)
    gw.register("search_tickets", SearchTicketsInput, TicketSearchResult, svc.search_tickets)
    gw.register("get_maintenance_window", GetMaintenanceWindowInput, MaintenanceCalendar, svc.get_maintenance_window)
    gw.register("create_support_ticket", CreateSupportTicketInput, TicketCreated, svc.create_support_ticket)
    gw.register("schedule_maintenance", ScheduleMaintenanceInput, MaintenanceScheduled, svc.schedule_maintenance)
    gw.register("send_notification", SendNotificationInput, NotificationSent, svc.send_notification)
    # resources
    gw.register("client_summary", ClientSummaryInput, ClientSummary, svc.client_summary)
    gw.register("camera_health", CameraHealthInput, CameraHealth, svc.camera_health)
    gw.register("manual", ManualInput, Manual, svc.manual)
    gw.register("manual_index", NoInput, ManualIndex, svc.manual_index)
    gw.register("ticket", TicketInput, TicketView, svc.get_ticket)
    # prompts
    gw.register("incident_triage", IncidentTriageInput, RenderedPrompt, prompts.incident_triage)
    gw.register(
        "customer_support_summary", CustomerSupportSummaryInput, RenderedPrompt, prompts.customer_support_summary
    )
    gw.register("maintenance_plan", MaintenancePlanInput, RenderedPrompt, prompts.maintenance_plan)

    # out-of-band approval endpoints (HTTP, never MCP)
    async def list_approvals(p: Principal, _: NoInput) -> ApprovalList:
        return ApprovalList(approvals=[ApprovalView.model_validate(a) for a in await approvals.list_pending(p)])

    async def decide_approval(p: Principal, inp: DecideApprovalInput) -> ApprovalView:
        view = await approvals.decide(p, inp.approval_id, inp.decision == "approve", inp.note)
        return ApprovalView.model_validate(view)

    gw.register("list_approvals", NoInput, ApprovalList, list_approvals)
    gw.register("decide_approval", DecideApprovalInput, ApprovalView, decide_approval)
