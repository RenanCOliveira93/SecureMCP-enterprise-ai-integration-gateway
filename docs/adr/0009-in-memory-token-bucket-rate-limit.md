# ADR-0009: In-process token-bucket rate limiting

## Context
A looping agent can issue hundreds of calls per minute. Limits must apply per subject (fairness), per tenant
(noisy neighbour) and be stricter for writes.

## Decision
A token bucket per key — `(tenant, subject, class)` and `(tenant)` — kept in process memory behind a
`RateLimiter` interface, configured in `policy.yaml`. Rejections return `RATE_LIMITED` with
`retry_after_seconds` and are audited.

## Alternatives considered
- **Redis (`INCR` + `EXPIRE` or GCRA)**: correct across replicas; the right choice for production.
- **PostgreSQL counters**: no extra service, but a write per request on the hot path.

## Consequences
- With N replicas the effective limit is up to N× the configured one. Acceptable for the single-replica demo;
  documented as a production requirement in the threat model.
