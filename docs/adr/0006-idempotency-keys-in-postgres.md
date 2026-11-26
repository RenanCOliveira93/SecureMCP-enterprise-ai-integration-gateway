# ADR-0006: Mandatory idempotency keys stored in PostgreSQL

## Context
Agents retry: the network drops a response, the LLM repeats a step, the user presses enter twice. Without
protection, each retry creates another ticket, maintenance window or SMS.

## Decision
- Every write tool requires `idempotency_key` (16–64 URL-safe characters).
- The gateway stores `(tenant_id, subject, operation, key)` → `request_hash`, `status`, `response`, `expires_at`
  (24 h) in `idempotency_records`, inserting the row **before** executing (unique constraint = lock).
  - Same key, same hash, completed → return the stored response with `replayed: true`; no side effect.
  - Same key, different hash → `IDEMPOTENCY_CONFLICT`.
  - Same key, still running → `IDEMPOTENCY_IN_PROGRESS` (retryable).
  - Execution failed with a retryable error → the record is released so the same key can be retried.
- The key is propagated to the notification API as an `Idempotency-Key` header, so downstream deduplicates too.
- `approval_required` results are stored as well: retrying the same key returns the same `approval_id`.

## Alternatives considered
- **Natural-key deduplication** (same subject + client in 5 minutes): guesses intent, false positives.
- **Redis with TTL**: fast, but another dependency and not transactional with the business write.

## Consequences
- The client must generate a new key per intended action and reuse it on retries. The LangGraph agent derives it
  from `(thread_id, step)`.
- Keys are scoped per subject: two users cannot collide or read each other's results.
