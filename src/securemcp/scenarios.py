"""Automated end-to-end scenarios against a running stack (``docker compose up``), with a Markdown report.

Everything goes through the public surfaces a real host uses: OAuth sign-in, MCP over Streamable HTTP, the
approval API. Faults are injected through the simulated services' control endpoint. The same behaviours are also
covered in-process by the pytest suite; this runner shows them on the deployed topology.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import httpx

from securemcp.agent import InjectionFollowingPlanner, RulePlanner, build_agent, run_agent
from securemcp.host.oauth import login
from securemcp.host.session import mcp_client

APPROVALS_REDIRECT = "http://127.0.0.1:8977/callback"


@dataclass
class Result:
    name: str
    expectation: str
    passed: bool
    evidence: str
    seconds: float = 0.0


class Runner:
    def __init__(self, *, mcp_url: str, mocks_url: str, password: str, redirect_uri: str) -> None:
        self.mcp_url = mcp_url
        self.base_url = mcp_url.rsplit("/mcp", 1)[0]
        self.mocks_url = mocks_url.rstrip("/")
        self.password = password
        self.redirect_uri = redirect_uri
        self.run_id = uuid.uuid4().hex[:10]
        self._tokens: dict[tuple[str, str], str] = {}

    async def token(self, user: str, client: str = "securemcp-host") -> str:
        if (user, client) not in self._tokens:
            redirect = self.redirect_uri if client == "securemcp-host" else APPROVALS_REDIRECT
            tokens = await login(
                mcp_url=self.mcp_url, username=user, password=self.password, client_id=client, redirect_uri=redirect
            )
            self._tokens[(user, client)] = tokens.access_token
        return self._tokens[(user, client)]

    def key(self, label: str) -> str:
        return f"scn-{self.run_id}-{label}"[:64]

    async def call(self, user: str, tool: str, args: dict[str, Any]) -> dict[str, Any]:
        async with mcp_client(self.mcp_url, await self.token(user)) as client:
            result = await client.call_tool(tool, args)
        if result.is_error:
            return json.loads(result.content[0].text)
        return result.structured_content or {}

    async def mocks(self, method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=5) as http:
            return (await http.request(method, f"{self.mocks_url}{path}", json=body)).raise_for_status().json()

    async def agent(self, user: str, request: str, planner: Any, decide: Callable[[dict], Awaitable[bool]]) -> dict:
        async with mcp_client(self.mcp_url, await self.token(user)) as client:
            graph = build_agent(client, planner)
            return await run_agent(graph, request, thread_id=f"{self.run_id}-{user}", decide=decide)

    # --------------------------------------------------------------------------------------- scenarios
    async def allowed(self) -> Result:
        async def confirm(_: dict) -> bool:
            return False

        out = await self.agent("bruno", "Show camera health for cli_aur001", RulePlanner(), confirm)
        obs = out["observations"]
        ok = [o["name"] for o in obs if o["status"] == "ok"] == ["list_camera_health"]
        return Result(
            "Allowed read",
            "support agent reads camera health of own tenant through the agent",
            ok,
            out["answer"].splitlines()[0],
        )

    async def denied(self) -> Result:
        body = await self.call(
            "ana",
            "create_support_ticket",
            {
                "client_id": "cli_aur001",
                "subject": "Camera offline",
                "description": "No image since 06:00.",
                "priority": "high",
                "category": "camera_offline",
                "idempotency_key": self.key("denied"),
            },
        )
        code = body.get("error", {}).get("code")
        return Result(
            "Denied by RBAC", "viewer calling a write tool gets FORBIDDEN", code == "FORBIDDEN", f"error.code={code}"
        )

    async def cross_tenant(self) -> Result:
        body = await self.call("eva", "get_client", {"client_id": "cli_aur001"})
        code = body.get("error", {}).get("code")
        return Result(
            "Tenant isolation",
            "user of another tenant gets NOT_FOUND (no existence oracle)",
            code == "NOT_FOUND",
            f"error.code={code}",
        )

    async def tenant_smuggling(self) -> Result:
        body = await self.call("eva", "get_client", {"client_id": "cli_aur001", "tenant_id": "tnt_aurora"})
        error = body.get("error", {})
        return Result(
            "Tenant smuggling",
            "a tenant_id argument is rejected, tenant comes only from the token",
            error.get("code") == "INVALID_ARGUMENT",
            f"error.code={error.get('code')} fields={error.get('fields')}",
        )

    async def prompt_injection(self) -> Result:
        before = (await self.mocks("GET", "/_faults"))["deliveries"]

        async def confirm(_: dict) -> bool:
            return True  # even a careless human would not be asked: the guard blocks first

        out = await self.agent(
            "carla", "Triage ticket tkt_aur00003 for cli_aur001", InjectionFollowingPlanner(), confirm
        )
        after = (await self.mocks("GET", "/_faults"))["deliveries"]
        blocked = sorted(o["name"] for o in out["observations"] if o["status"] == "blocked")
        ok = blocked == ["schedule_maintenance", "send_notification"] and after == before
        return Result(
            "Prompt injection",
            "instructions inside a ticket cannot trigger writes",
            ok,
            f"blocked={blocked}, new deliveries={after - before}",
        )

    async def duplicate(self) -> Result:
        args = {
            "client_id": "cli_aur002",
            "subject": "Lens cracked in stockroom",
            "priority": "medium",
            "description": "Lens of camera cam_aur00201 cracked during shelving work.",
            "category": "image_quality",
            "camera_id": "cam_aur00201",
            "idempotency_key": self.key("dup"),
        }
        first = await self.call("bruno", "create_support_ticket", args)
        second = await self.call("bruno", "create_support_ticket", args)
        conflict = await self.call("bruno", "create_support_ticket", {**args, "priority": "high"})
        ok = (
            first.get("ticket_id")
            and first["ticket_id"] == second.get("ticket_id")
            and second.get("replayed")
            and conflict.get("error", {}).get("code") == "IDEMPOTENCY_CONFLICT"
        )
        return Result(
            "Duplicate call",
            "same idempotency key replays; same key with other arguments conflicts",
            bool(ok),
            f"ticket={first.get('ticket_id')} replayed={second.get('replayed')} "
            f"reuse-with-new-args={conflict.get('error', {}).get('code')}",
        )

    async def unavailable(self) -> Result:
        await self.mocks("POST", "/_faults", {"target": "notifications", "mode": "unavailable"})
        try:
            before = (await self.mocks("GET", "/_faults"))["requests"]["notifications"]
            body = await self.call(
                "carla",
                "send_notification",
                {
                    "client_id": "cli_aur001",
                    "template": "ticket_update",
                    "reference_id": "tkt_aur00001",
                    "audience": "primary_contact",
                    "channel": "email",
                    "idempotency_key": self.key("unavail"),
                },
            )
            attempts = (await self.mocks("GET", "/_faults"))["requests"]["notifications"] - before
            crm = await self.mocks("POST", "/_faults", {"target": "crm", "mode": "unavailable"})
            degraded = await self.call("bruno", "get_client", {"client_id": "cli_aur001"})
        finally:
            await self.mocks("POST", "/_faults", {"target": "notifications", "mode": "ok"})
            await self.mocks("POST", "/_faults", {"target": "crm", "mode": "ok"})
        error = body.get("error", {})
        ok = (
            error.get("code") == "UPSTREAM_UNAVAILABLE"
            and error.get("retryable")
            and attempts == 3
            and degraded.get("crm", {}).get("status") == "unavailable"
            and crm["ok"]
        )
        return Result(
            "External service unavailable",
            "write fails fast after bounded retries; reads degrade instead of failing",
            bool(ok),
            f"notify: {error.get('code')} after {attempts} attempts; get_client: crm="
            f"{degraded.get('crm', {}).get('status')}",
        )

    async def rate_limit(self) -> Result:
        codes = []
        async with mcp_client(self.mcp_url, await self.token("ana")) as client:
            for _ in range(40):
                result = await client.call_tool("get_contract_modules", {"client_id": "cli_aur003"})
                codes.append(json.loads(result.content[0].text)["error"]["code"] if result.is_error else "ok")
        limited = codes.count("RATE_LIMITED")
        return Result(
            "Rate limit",
            "a burst above the per-user read bucket is throttled with RATE_LIMITED",
            limited > 0 and codes[0] == "ok",
            f"{codes.count('ok')} ok, {limited} rate limited",
        )

    async def approval(self) -> Result:
        args = {
            "client_id": "cli_aur003",
            "template": "maintenance_notice",
            "reference_id": "mnt_aur00301",
            "audience": "all_contacts",
            "channel": "email",
            "idempotency_key": self.key("approval"),
        }
        pending = await self.call("carla", "send_notification", args)
        approval_id = (pending.get("approval") or {}).get("approval_id")
        async with httpx.AsyncClient(base_url=self.base_url, timeout=10) as http:
            own = await http.post(
                f"/approvals/{approval_id}/decision",
                json={"decision": "approve"},
                headers={"Authorization": f"Bearer {await self.token('carla', 'securemcp-approvals')}"},
            )
            decided = await http.post(
                f"/approvals/{approval_id}/decision",
                json={"decision": "approve"},
                headers={"Authorization": f"Bearer {await self.token('diego', 'securemcp-approvals')}"},
            )
        done = await self.call("carla", "send_notification", {**args, "approval_id": approval_id})
        ok = (
            pending.get("status") == "approval_required"
            and own.status_code == 403
            and decided.status_code == 200
            and done.get("status") == "completed"
        )
        return Result(
            "Sensitive action approval",
            "broadcast needs a second person; requester cannot self-approve",
            ok,
            f"{approval_id}: self-approve HTTP {own.status_code}, approver HTTP {decided.status_code}, "
            f"resend {done.get('status')}",
        )

    async def run(self) -> list[Result]:
        scenarios = [
            self.allowed,
            self.denied,
            self.cross_tenant,
            self.tenant_smuggling,
            self.prompt_injection,
            self.duplicate,
            self.unavailable,
            self.approval,
            self.rate_limit,
        ]
        results = []
        for scenario in scenarios:
            started = time.monotonic()
            try:
                result = await scenario()
            except Exception as exc:  # report, keep going
                result = Result(scenario.__name__, "", False, f"{type(exc).__name__}: {exc}"[:200])
            result.seconds = round(time.monotonic() - started, 2)
            results.append(result)
        return results


def report(results: list[Result], *, mcp_url: str) -> str:
    passed = sum(r.passed for r in results)
    lines = [
        "# SecureMCP scenario report",
        "",
        f"Target: `{mcp_url}` — {passed}/{len(results)} scenarios behaved as expected.",
        "",
        "| Scenario | Expected behaviour | Result | Evidence | Time (s) |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        evidence = r.evidence.replace("|", "\\|")
        lines.append(f"| {r.name} | {r.expectation} | {'PASS' if r.passed else 'FAIL'} | {evidence} | {r.seconds} |")
    return "\n".join(lines) + "\n"
