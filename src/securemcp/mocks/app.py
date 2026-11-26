"""Simulated downstream systems: a CRM and a notification API, with fault injection for resilience scenarios.

Both require the server-to-server API key (from the secret provider) and a tenant header. The notification API
deduplicates by ``Idempotency-Key`` exactly like a real provider would. ``/_faults`` is a test-only control plane;
it is bound to the Compose network and never exposed in production.
"""

from __future__ import annotations

import asyncio
import hmac
import secrets
from typing import Any, Literal

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from securemcp.security.secrets import SecretProvider

Target = Literal["crm", "notifications"]

CRM_ACCOUNTS: dict[tuple[str, str], dict[str, Any]] = {
    ("tnt_aurora", "cli_aur001"): {"account_manager": "Paula Ribeiro", "health": "yellow", "open_opportunities": 2},
    ("tnt_aurora", "cli_aur002"): {"account_manager": "Paula Ribeiro", "health": "green", "open_opportunities": 1},
    ("tnt_aurora", "cli_aur003"): {"account_manager": "Marcos Teixeira", "health": "red", "open_opportunities": 0},
    ("tnt_boreal", "cli_bor001"): {"account_manager": "Helena Duarte", "health": "green", "open_opportunities": 3},
    ("tnt_boreal", "cli_bor002"): {"account_manager": "Helena Duarte", "health": "yellow", "open_opportunities": 0},
}


class Fault(BaseModel):
    mode: Literal["ok", "unavailable", "slow", "reject", "flaky"] = "ok"
    delay_seconds: float = Field(default=0.0, ge=0, le=30)
    failures_remaining: int = Field(default=0, ge=0, le=100)


class FaultRequest(Fault):
    target: Target


class MockState:
    def __init__(self) -> None:
        self.faults: dict[str, Fault] = {"crm": Fault(), "notifications": Fault()}
        self.messages: dict[str, dict[str, Any]] = {}  # idempotency key -> stored response
        self.requests: dict[str, int] = {"crm": 0, "notifications": 0}
        self.deliveries: list[dict[str, Any]] = []

    def reset(self) -> None:
        self.__init__()  # type: ignore[misc]


async def _apply_fault(state: MockState, target: str) -> JSONResponse | None:
    state.requests[target] += 1
    fault = state.faults[target]
    if fault.mode == "slow":
        await asyncio.sleep(fault.delay_seconds)
    elif fault.mode == "unavailable":
        return JSONResponse({"error": "service unavailable"}, status_code=503, headers={"Retry-After": "0"})
    elif fault.mode == "reject":
        return JSONResponse({"error": "rejected by provider"}, status_code=400)
    elif fault.mode == "flaky" and fault.failures_remaining > 0:
        fault.failures_remaining -= 1
        return JSONResponse({"error": "temporary failure"}, status_code=503)
    return None


def create_mocks_app(secrets_provider: SecretProvider) -> FastAPI:
    app = FastAPI(title="Nexus Sight simulated downstream APIs", docs_url=None, redoc_url=None)
    state = MockState()
    app.state.mock = state

    def check_key(name: str, provided: str | None) -> None:
        expected = secrets_provider.get(name).get_secret_value()
        if provided is None or not hmac.compare_digest(provided, expected):
            raise HTTPException(status_code=401, detail="invalid api key")

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    # ------------------------------------------------------------------------- CRM
    @app.get("/crm/accounts/{client_id}")
    async def crm_account(
        client_id: str,
        x_api_key: str | None = Header(default=None),
        x_tenant_id: str | None = Header(default=None),
    ) -> Any:
        check_key("crm_api_key", x_api_key)
        if (fault := await _apply_fault(state, "crm")) is not None:
            return fault
        account = CRM_ACCOUNTS.get((x_tenant_id or "", client_id))
        if account is None:
            raise HTTPException(status_code=404, detail="account not found")
        return {"client_id": client_id, **account}

    # --------------------------------------------------------------- notifications
    @app.post("/notifications/messages")
    async def send_message(
        request: Request,
        x_api_key: str | None = Header(default=None),
        x_tenant_id: str | None = Header(default=None),
        idempotency_key: str | None = Header(default=None),
    ) -> Any:
        check_key("notifications_api_key", x_api_key)
        if not idempotency_key or not x_tenant_id:
            raise HTTPException(status_code=400, detail="Idempotency-Key and X-Tenant-Id are required")
        if (fault := await _apply_fault(state, "notifications")) is not None:
            return fault
        if idempotency_key in state.messages:
            return state.messages[idempotency_key]
        payload = await request.json()
        response = {
            "message_id": f"msg_{secrets.token_hex(6)}",
            "status": "queued",
            "accepted_recipients": len(payload.get("recipients", [])),
        }
        state.messages[idempotency_key] = response
        state.deliveries.append(
            {
                "tenant_id": x_tenant_id,
                "channel": payload.get("channel"),
                "template": payload.get("template"),
                "recipients": len(payload.get("recipients", [])),
            }
        )
        return response

    # ------------------------------------------------------- fault-injection control
    @app.get("/_faults")
    async def get_faults() -> dict[str, Any]:
        return {
            "faults": {k: v.model_dump() for k, v in state.faults.items()},
            "requests": state.requests,
            "deliveries": len(state.deliveries),
        }

    @app.post("/_faults")
    async def set_fault(body: FaultRequest) -> dict[str, Any]:
        state.faults[body.target] = Fault(**body.model_dump(exclude={"target"}))
        return {"ok": True}

    @app.post("/_reset")
    async def reset() -> dict[str, bool]:
        state.reset()
        return {"ok": True}

    return app
