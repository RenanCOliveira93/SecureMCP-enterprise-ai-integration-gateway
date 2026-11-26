# ADR-0010: Hash-chained, per-tenant audit trail

## Context
The audit trail must answer "who did what, for which tenant, under which policy, with what outcome" and should make
silent tampering detectable. It must not become a second copy of sensitive data.

## Decision
- One `audit_events` row per attempt with the fields listed in authorization-model §7.
- Arguments are stored only as a **fingerprint** (SHA-256 of canonical JSON) — enough to correlate with approvals
  and idempotency records, not enough to read PII.
- Each event stores `prev_hash` and `hash = SHA-256(prev_hash || canonical(event))`, chained per tenant with a
  sequence number. The chain head lives in `audit_chain_heads` and is updated in the same transaction (row lock).
- `securemcp audit verify` recomputes the chains.
- The application role only gets `INSERT`/`SELECT` on audit tables.

## Alternatives considered
- **Logs only**: easy to lose, easy to edit, mixed with debugging noise.
- **External ledger / WORM bucket**: stronger; documented as the production export target.

## Consequences
- Audit writes serialize per tenant (chain head lock). At demo scale this is negligible; at high volume, batch or
  shard the chain.
- The audit event is written after the operation finishes, in its own transaction, so it records the real outcome.
  If that write fails, the outcome returned to the caller is unchanged and the sanitized event is logged at `ERROR`
  (`AUDIT WRITE FAILED`) so it can be replayed. Failing the request instead would not undo a side effect that
  already happened downstream. Production follow-up: a transactional outbox that commits the audit event together
  with the business change, plus an alert on that log line.
