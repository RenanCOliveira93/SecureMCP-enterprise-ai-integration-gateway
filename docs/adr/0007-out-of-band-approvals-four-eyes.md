# ADR-0007: Out-of-band approvals with four-eyes, bound to the argument hash

## Context
Some writes are acceptable only after a human agrees (critical tickets page on-call staff; long maintenance windows
blind stores; mass SMS reaches customers). The agent must not be able to grant that agreement to itself, and the
approved action must be exactly the one executed.

## Decision
- When policy says `APPROVAL_REQUIRED`, the gateway creates an `approvals` row (tenant, operation, requester,
  SHA-256 of canonical arguments, summary, risk, `expires_at`) and returns `status: "approval_required"`.
- Decisions happen through HTTP endpoints outside MCP (`/approvals`), require `approvals:decide`, and the deciding
  subject must differ from the requester.
- The `securemcp-host` OAuth client can never obtain `approvals:decide`; only `securemcp-approvals` can.
- Re-submitting with `approval_id` succeeds only for the same tenant, operation, requester and argument hash, before
  expiry, once.

## Alternatives considered
- **MCP elicitation** (server asks the client to confirm): the confirmation travels through the host, which the agent
  influences, and requires stateful sessions (ADR-0001).
- **Host-side confirmation only**: good UX, still used by our host, but it is not an enforcement point.

## Consequences
- Two round trips for high-risk actions; the agent must handle `approval_required` as a normal outcome.
- Approval decisions are audited like any other operation.
