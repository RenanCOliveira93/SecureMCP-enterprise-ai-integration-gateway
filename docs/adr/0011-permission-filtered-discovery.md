# ADR-0011: Discovery filtered by effective permissions

## Context
`tools/list` tells the model what it can do. Advertising tools the caller cannot use wastes context, invites the
model to try them, and reveals capabilities to roles that do not need to know them.

## Decision
`SecureMCPServer` overrides `list_tools`, `list_resource_templates`, `list_resources` and `list_prompts` to return
only the entries whose required permission is in the caller's effective permissions. Calls are still authorized
independently.

## Alternatives considered
- **Advertise everything**: simpler and cache-friendly, but leaks and confuses.
- **Separate servers per role**: duplicated deployment.

## Consequences
- Tool lists differ per user. Hosts that cache tool lists must key the cache by identity; the server sends no
  shared cache hints for list results.
