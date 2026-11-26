# ADR-0008: Retries only for transient failures, inside an operation deadline

## Context
Downstream APIs fail. Retrying a `400 Bad Request` or a `403` is pointless; retrying a non-idempotent POST can
duplicate side effects; unbounded retries amplify outages.

## Decision
- Retry only on: connection errors, read timeouts, `429` (honouring `Retry-After` up to 2 s), `502`, `503`, `504`.
- At most 3 attempts, exponential backoff (0.2 s, 0.4 s) with full jitter.
- POSTs are retried only when they carry an `Idempotency-Key`.
- All attempts run inside the operation **deadline** from `policy.yaml` (3 s reads, 8 s writes); when the deadline
  expires the gateway returns `TIMEOUT`.
- After retries are exhausted the error is `UPSTREAM_UNAVAILABLE` (retryable for the caller). 4xx responses map to
  `UPSTREAM_REJECTED` (not retryable).
- Reads that have a safe partial answer degrade instead of failing (`get_client` returns `crm.status=unavailable`).

## Alternatives considered
- **Retry everything N times**: causes duplicates and retry storms.
- **Circuit breaker**: valuable at scale; documented as a production follow-up. The deadline plus capped retries
  already bound the damage per request.

## Consequences
- Retry behaviour is encoded once (`integrations/http.py`) and unit-tested against a fake transport.
