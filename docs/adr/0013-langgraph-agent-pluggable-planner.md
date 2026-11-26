# ADR-0013: LangGraph agent with a pluggable planner

## Context
The project must show an agent consuming the MCP server. Tests and CI cannot depend on a paid LLM API, and
security behaviour must be reproducible.

## Decision
- A LangGraph `StateGraph` with nodes `discover → plan → guard → act → observe → … → respond`, an
  `InMemorySaver` checkpointer, and `interrupt()` for human confirmation before writes.
- The **planner** (the only part that would use an LLM) is an interface:
  - `RulePlanner` (default, offline, deterministic) — maps recognised intents to tool plans; used by tests and
    scenarios.
  - `ClaudePlanner` — uses the official Anthropic Python SDK with the discovered MCP tool schemas as tool
    definitions (`SECUREMCP_AGENT_PLANNER=claude`, model `SECUREMCP_AGENT_MODEL`, default `claude-opus-5-5`).
  - `NaivePlanner` (tests only) — follows instructions found in tool output, simulating a successful injection.
- Guards (allowlist of discovered tools, intent binding, confirmation, step budget, retry only on retryable errors
  with the same idempotency key) live in the graph, not in the planner, so they apply to every planner.

## Alternatives considered
- **LangChain MCP adapters + prebuilt ReAct agent**: less code, but hides the tool-call loop and gives no place for
  deterministic guards.
- **LLM-only, no offline mode**: non-reproducible tests, cost in CI.

## Consequences
- The offline planner understands a limited set of phrasings; it is a test double, not a product.
