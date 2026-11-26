# ADR-0002: Layered gateway and no generic SQL

## Context
The specification requires separating protocol, business rules and data access, and forbids handlers that execute
SQL produced by an LLM. Security checks (identity, policy, idempotency, audit) must be identical for tools,
resources and prompts, and must be testable without an MCP transport.

## Decision
Four layers with one-way dependencies:

1. **Protocol adapters** (`mcp_server/`): declare typed signatures, call `gateway.invoke()`, translate errors.
2. **Gateway pipeline** (`gateway/`): identity → allowlist → rate limit → policy → idempotency → approval →
   deadline → service → output validation → audit. Protocol-independent.
3. **Services** (`services/`): business rules per domain. Receive a `Principal` and typed input.
4. **Repositories and integrations** (`db/`, `integrations/`): named, parameterised queries and HTTP clients.

There is no tool, resource or prompt that accepts SQL, a table name, a column name, an URL or a shell command.

## Alternatives considered
- **Checks inside each handler**: simple, but every new tool is a chance to forget one check.
- **A generic `query_database` tool with an SQL allowlist/parser**: flexible for analysts, but SQL validation is a
  losing game (functions, `COPY`, side-channel timing) and it bypasses tenant and PII rules.

## Consequences
- Adding a capability means: schema + policy entry + service method + adapter + test. More code, but each piece is
  small and reviewable.
- The pipeline is unit-testable with a fake principal and a SQLite database.
