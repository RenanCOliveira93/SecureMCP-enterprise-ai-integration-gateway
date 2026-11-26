"""The agent as an explicit state machine (LangGraph).

    discover ─► plan ─┬─► guard ─┬─► act ─┬─► plan …
                      │          │        └─► await_approval ─► act
                      │          └─► plan   (blocked or declined: the planner sees why)
                      └─► respond

- ``discover``: list the tools *this user* may call (the server filters by role and scope).
- ``plan``: the planner proposes one step. It cannot execute anything.
- ``guard``: deterministic checks before any call — tool discovered, arguments match the advertised schema,
  writes bound to what the user asked for (``requested_writes``), human confirmation for every write
  (``interrupt``), step budget.
- ``act``: calls the MCP server. The agent derives the idempotency key from (thread, step, tool, arguments), so a
  retry of the same step reuses it. Only errors the server marks ``retryable`` are retried.
- ``await_approval``: the server answered ``approval_required``; pause until a human approver decides, then the
  same call is resent with ``approval_id`` and the same idempotency key.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from typing import Any, Protocol, TypedDict

import jsonschema
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from securemcp.agent.intents import WRITE_TOOLS, requested_writes
from securemcp.agent.planners import Final, Planner

log = logging.getLogger(__name__)

# Retry budget. The gateway already retries transient downstream failures (ADR-0009), so an UPSTREAM_UNAVAILABLE
# it returns means its own attempts were exhausted: the agent adds at most one more attempt to avoid multiplying
# load. Lost connections between agent and gateway get two retries (the idempotency key makes them safe).
MAX_TRANSPORT_RETRIES = 2
MAX_SERVER_RETRIES = 1
MAX_BACKOFF_SECONDS = 5.0


class McpLike(Protocol):
    async def list_tools(self) -> Any: ...
    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any: ...
    async def read_resource(self, uri: str) -> Any: ...


class AgentState(TypedDict, total=False):
    request: str
    thread_id: str
    catalog: list[dict[str, Any]]
    allowed_writes: list[str]
    observations: list[dict[str, Any]]
    pending: dict[str, Any] | None
    steps: int
    answer: str


def idempotency_key(thread_id: str, step: int, name: str, arguments: dict[str, Any]) -> str:
    material = json.dumps([thread_id, step, name, arguments], sort_keys=True, separators=(",", ":"), default=str)
    return "agt-" + hashlib.sha256(material.encode()).hexdigest()[:40]


def _is_write(tool: dict[str, Any] | None, name: str) -> bool:
    if tool is not None and tool.get("read_only") is not None:
        return not tool["read_only"]
    return name in WRITE_TOOLS


def _parse_result(result: Any) -> dict[str, Any]:
    if getattr(result, "is_error", False):
        try:
            err = json.loads(result.content[0].text)["error"]
        except (ValueError, KeyError, IndexError, AttributeError):
            err = {"code": "INTERNAL", "message": "unreadable error", "retryable": False}
        return {
            "status": "error",
            "error_code": err.get("code"),
            "message": err.get("message"),
            "retryable": bool(err.get("retryable")),
            "retry_after": err.get("retry_after_seconds"),
        }
    data = getattr(result, "structured_content", None)
    if data is None:
        try:
            data = json.loads(result.content[0].text)
        except (ValueError, IndexError, AttributeError):
            data = {"text": getattr(result.content[0], "text", "")} if getattr(result, "content", None) else {}
    if data.get("status") == "approval_required":
        return {"status": "approval_pending", "data": data, "approval_id": data["approval"]["approval_id"]}
    return {"status": "ok", "data": data, "injection_signals": data.get("injection_signals") or []}


def build_agent(mcp: McpLike, planner: Planner, *, max_steps: int = 8, checkpointer: Any = None):
    async def discover(state: AgentState) -> AgentState:
        tools = (await mcp.list_tools()).tools
        catalog = [
            {
                "name": t.name,
                "description": t.description or "",
                "input_schema": t.input_schema,
                "read_only": getattr(t.annotations, "read_only_hint", None) if t.annotations else None,
            }
            for t in tools
        ]
        return {
            "catalog": catalog,
            "allowed_writes": sorted(requested_writes(state["request"])),
            "observations": [],
            "steps": 0,
            "pending": None,
        }

    async def plan(state: AgentState) -> AgentState:
        if state["steps"] >= max_steps:
            return {"pending": None, "answer": f"Stopped after {max_steps} steps (step budget)."}
        step = await planner.plan(state["request"], state["catalog"], state["observations"])
        if isinstance(step, Final):
            return {"pending": None, "answer": step.answer}
        call_id = step.call_id or f"call_{state['steps'] + 1}"
        return {
            "pending": {
                "name": step.name,
                "arguments": step.arguments,
                "kind": step.kind,
                "rationale": step.rationale,
                "call_id": call_id,
                "step": state["steps"] + 1,
            },
            "steps": state["steps"] + 1,
        }

    def _observe(state: AgentState, pending: dict[str, Any], **outcome: Any) -> AgentState:
        obs = {"name": pending["name"], "call_id": pending["call_id"], "arguments": pending["arguments"], **outcome}
        return {"observations": [*state["observations"], obs], "pending": None}

    async def guard(state: AgentState) -> AgentState:
        pending = dict(state["pending"] or {})
        if pending["kind"] == "resource":
            return {"pending": {**pending, "cleared": True}}
        tool = next((t for t in state["catalog"] if t["name"] == pending["name"]), None)
        if tool is None:
            return _observe(
                state, pending, status="blocked", reason="tool not available to this user (not in discovery)"
            )
        args = {k: v for k, v in pending["arguments"].items() if k not in ("idempotency_key", "approval_id")}
        is_write = _is_write(tool, pending["name"])
        if is_write:
            args["idempotency_key"] = idempotency_key(state["thread_id"], pending["step"], pending["name"], args)
        try:
            jsonschema.validate(args, tool["input_schema"])
        except jsonschema.ValidationError as exc:
            field = ".".join(str(p) for p in exc.absolute_path) or "(root)"
            return _observe(state, pending, status="blocked", reason=f"arguments do not match the schema ({field})")
        if is_write:
            if pending["name"] not in state["allowed_writes"]:
                log.warning("blocked %s: not requested by the user (possible prompt injection)", pending["name"])
                return _observe(
                    state,
                    pending,
                    status="blocked",
                    reason="write action not requested by the user (possible prompt injection)",
                )
            confirmed = interrupt(
                {"type": "confirm", "tool": pending["name"], "arguments": args, "rationale": pending["rationale"]}
            )
            if not confirmed:
                return _observe(state, pending, status="declined")
        return {"pending": {**pending, "arguments": args, "cleared": True}}

    async def _call(pending: dict[str, Any]) -> dict[str, Any]:
        if pending["kind"] == "resource":
            try:
                result = await mcp.read_resource(pending["name"])
            except Exception as exc:  # MCPError carries our error body in data
                data = getattr(getattr(exc, "error", None), "data", None) or getattr(exc, "data", None) or {}
                err = data.get("error", {}) if isinstance(data, dict) else {}
                return {
                    "status": "error",
                    "error_code": err.get("code", "ERROR"),
                    "message": err.get("message", str(exc)[:200]),
                    "retryable": bool(err.get("retryable")),
                }
            data = (
                json.loads(result.contents[0].text)
                if result.contents[0].text.startswith("{")
                else {"text": result.contents[0].text}
            )
            return {"status": "ok", "data": data, "injection_signals": data.get("injection_signals") or []}
        return _parse_result(await mcp.call_tool(pending["name"], pending["arguments"]))

    async def act(state: AgentState) -> AgentState:
        pending = state["pending"] or {}
        attempt = 0
        server_retries = 0
        while True:
            try:
                outcome = await _call(pending)
            except (OSError, TimeoutError) as exc:  # lost connection: safe to resend, the key dedupes writes
                outcome = {
                    "status": "error",
                    "error_code": "TRANSPORT",
                    "message": type(exc).__name__,
                    "retryable": True,
                }
            if outcome["status"] != "error" or not outcome.get("retryable") or attempt >= MAX_TRANSPORT_RETRIES:
                break
            if outcome["error_code"] != "TRANSPORT":
                if server_retries >= MAX_SERVER_RETRIES:
                    break
                server_retries += 1
            attempt += 1
            delay = min(MAX_BACKOFF_SECONDS, outcome.get("retry_after") or 0.2 * 2**attempt)
            log.info("retrying %s after %s (attempt %d)", pending["name"], outcome["error_code"], attempt + 1)
            await asyncio.sleep(delay)
        outcome["attempts"] = attempt + 1
        if outcome["status"] == "approval_pending":
            return {"pending": {**pending, "approval_id": outcome["approval_id"], "approval": outcome["data"]}}
        return _observe(state, pending, **outcome)

    async def await_approval(state: AgentState) -> AgentState:
        pending = state["pending"] or {}
        approved = interrupt(
            {
                "type": "approval",
                "tool": pending["name"],
                "approval_id": pending["approval_id"],
                "reason": pending["approval"]["approval"]["reason"],
            }
        )
        if not approved:
            return _observe(state, pending, status="approval_pending", approval_id=pending["approval_id"])
        return {
            "pending": {
                **pending,
                "arguments": {**pending["arguments"], "approval_id": pending["approval_id"]},
                "approval_id": None,
            }
        }

    def after_plan(state: AgentState) -> str:
        return "guard" if state.get("pending") else "respond"

    def after_guard(state: AgentState) -> str:
        return "act" if (state.get("pending") or {}).get("cleared") else "plan"

    def after_act(state: AgentState) -> str:
        return "await_approval" if (state.get("pending") or {}).get("approval_id") else "plan"

    def after_approval(state: AgentState) -> str:
        return "act" if state.get("pending") else "plan"

    async def respond(state: AgentState) -> AgentState:
        return {"answer": state.get("answer") or "(no answer)"}

    graph = StateGraph(AgentState)
    for name, node in [
        ("discover", discover),
        ("plan", plan),
        ("guard", guard),
        ("act", act),
        ("await_approval", await_approval),
        ("respond", respond),
    ]:
        graph.add_node(name, node)
    graph.add_edge(START, "discover")
    graph.add_edge("discover", "plan")
    graph.add_conditional_edges("plan", after_plan, ["guard", "respond"])
    graph.add_conditional_edges("guard", after_guard, ["act", "plan"])
    graph.add_conditional_edges("act", after_act, ["await_approval", "plan"])
    graph.add_conditional_edges("await_approval", after_approval, ["act", "plan"])
    graph.add_edge("respond", END)
    return graph.compile(checkpointer=checkpointer or InMemorySaver())


async def run_agent(agent: Any, request: str, *, thread_id: str, decide: Any) -> dict[str, Any]:
    """Drive the graph to completion. ``decide(payload) -> bool`` answers each interrupt (confirm / approval)."""
    from langgraph.types import Command

    config = {"configurable": {"thread_id": thread_id}}
    result = await agent.ainvoke({"request": request, "thread_id": thread_id}, config)
    while result.get("__interrupt__"):
        result = await agent.ainvoke(Command(resume=await decide(result["__interrupt__"][0].value)), config)
    return result
