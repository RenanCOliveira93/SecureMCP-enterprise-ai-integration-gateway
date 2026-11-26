# ADR-0005: Tenant isolation in three layers

## Context
Two partner tenants share one deployment and one database. A single missed `WHERE tenant_id = …` would leak
customer data across companies. An LLM can also be tricked into asking for another tenant's identifiers.

## Decision
1. **Tenant from the token only.** No input schema contains a tenant field.
2. **Repository discipline.** Every repository method has `tenant_id` as its first parameter and filters by it.
   Cross-tenant ids produce `NOT_FOUND` (no existence oracle).
3. **PostgreSQL Row-Level Security** on every tenant table (`USING (tenant_id = current_setting('app.tenant_id'))`,
   `FORCE ROW LEVEL SECURITY`). The application connects as `securemcp_app`, which is neither the owner nor
   `BYPASSRLS`. Each transaction sets `app.tenant_id` with `set_config(…, true)` (transaction-local, so pooled
   connections cannot leak the setting).

## Alternatives considered
- **Database or schema per tenant**: strongest isolation, but migrations, pooling and cross-tenant operations for
  the vendor become complex for a two-tenant demo.
- **Application filtering only**: one bug away from a breach.

## Consequences
- SQLite (used by fast unit tests) has no RLS; layers 1–2 are tested on SQLite and layer 3 is tested on PostgreSQL
  (`tests/integration/test_rls_postgres.py`, run in CI and with `make test-pg`).
- Migrations must run as the owner role; the server must never be configured with owner credentials.
