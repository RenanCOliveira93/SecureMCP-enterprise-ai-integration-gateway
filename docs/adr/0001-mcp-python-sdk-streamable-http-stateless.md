# ADR-0001: MCP Python SDK 2.x, Streamable HTTP, stateless JSON responses

## Context
The server must be consumable by real MCP hosts (Inspector, desktop clients, our LangGraph agent), must support
OAuth bearer tokens, and should scale horizontally behind a load balancer. MCP offers stdio and Streamable HTTP
transports; Streamable HTTP can keep a server-side session (`Mcp-Session-Id`) and stream responses over SSE.

## Decision
- Use the official **MCP Python SDK 2.x** (`mcp.server.mcpserver.MCPServer`), which generates JSON Schemas from typed
  Python signatures and Pydantic return types, implements Protected Resource Metadata and bearer authentication, and
  speaks both the modern (`server/discover`, 2026-07-28) and legacy (`initialize`) protocol flows.
- Serve **Streamable HTTP at `/mcp` with `stateless_http=True` and `json_response=True`**.
- Keep **stdio** available for local use, with identity from `SECUREMCP_STDIO_ACCESS_TOKEN`.
- Subclass `MCPServer` (`SecureMCPServer`) only to filter discovery and to map gateway errors to MCP results; tool
  functions stay ordinary decorated functions.

## Alternatives considered
- **Stateful sessions with SSE**: enables server-initiated requests (sampling, elicitation, progress). None of our
  operations needs them, and sessions require sticky routing and session-hijack protections.
- **Low-level `Server` API**: full control, but we would hand-write JSON Schemas and lose signature-driven validation.
- **SDK 1.x (`FastMCP`)**: widely documented, but superseded; starting a new project on it means a migration later.

## Consequences
- Every request carries and re-validates its token; there is no session to steal.
- No progress notifications or elicitation. Human confirmation is implemented by approvals (ADR-0007) instead of MCP
  elicitation, which also keeps the approval channel outside the agent's control.
- We depend on a young major version of the SDK; the integration tests exercise the real HTTP transport to catch
  upgrades that change behaviour.
