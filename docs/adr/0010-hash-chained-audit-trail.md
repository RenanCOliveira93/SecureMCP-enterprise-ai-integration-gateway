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
- Audit writing failure fails the request closed (no unaudited side effects) for writes; for reads it is logged and
  the read still returns.
