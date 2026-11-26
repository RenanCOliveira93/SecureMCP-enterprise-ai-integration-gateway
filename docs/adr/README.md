# Architecture decision records

Each ADR records one decision: the context that forced it, what was decided, the alternatives that were rejected and
the consequences we accept. Status is `Accepted` unless noted.

| ADR | Decision |
|---|---|
| [0001](0001-mcp-python-sdk-streamable-http-stateless.md) | MCP Python SDK 2.x `MCPServer`, Streamable HTTP, stateless JSON responses |
| [0002](0002-layered-gateway-no-generic-sql.md) | Protocol adapters → gateway pipeline → services → repositories; no generic SQL |
| [0003](0003-local-oauth-jwt-audience-binding.md) | Local OAuth 2.1 server, RS256 JWT access tokens bound to the MCP resource |
| [0004](0004-rbac-scopes-declarative-policy.md) | RBAC ∩ OAuth scopes, evaluated by a declarative, deny-by-default policy file |
| [0005](0005-tenant-isolation-three-layers.md) | Tenant isolation: token-derived tenant, repository filter, PostgreSQL RLS |
| [0006](0006-idempotency-keys-in-postgres.md) | Mandatory idempotency keys for writes, stored with a request hash |
| [0007](0007-out-of-band-approvals-four-eyes.md) | Out-of-band approvals with four-eyes, bound to the argument hash |
| [0008](0008-transient-only-retries-with-deadline.md) | Retries only for transient failures, inside an operation deadline |
| [0009](0009-in-memory-token-bucket-rate-limit.md) | In-process token-bucket rate limiting behind an interface |
| [0010](0010-hash-chained-audit-trail.md) | Hash-chained, per-tenant audit trail in PostgreSQL |
| [0011](0011-permission-filtered-discovery.md) | Discovery filtered by the caller's effective permissions |
| [0012](0012-prompt-injection-defense-in-depth.md) | Prompt injection: untrusted-data marking, closed templates, intent binding |
| [0013](0013-langgraph-agent-pluggable-planner.md) | LangGraph agent with a pluggable planner (offline rules by default, Claude optional) |
| [0014](0014-opentelemetry-and-sanitized-logs.md) | OpenTelemetry tracing and sanitized structured logs |
| [0015](0015-secret-provider-abstraction.md) | Secrets through a `SecretProvider` (env, files / Docker secrets) |
