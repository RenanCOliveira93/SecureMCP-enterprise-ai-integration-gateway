# Authorization model

This document answers one question: **given a request, who is calling, on behalf of which tenant, and is this exact
operation with these exact arguments allowed right now?** The source of truth for the rules is
[`config/policy.yaml`](../config/policy.yaml); the evaluator is `securemcp.security.policy`.

## 1. Identity

### 1.1 Authentication flow

1. The host (demo CLI) runs **OAuth 2.1 authorization code + PKCE (S256)** against the local authorization server,
   asking for a set of scopes and for `resource=<SECUREMCP_PUBLIC_URL>` (RFC 8707 resource indicator).
2. The authorization server authenticates the (synthetic) user, intersects the requested scopes with
   *what the OAuth client may request* and *what the user's roles grant*, and issues a **15-minute RS256 JWT**.
3. The host sends that token as `Authorization: Bearer …` on every MCP request.
4. The MCP server verifies it with the authorization server's **JWKS** (cached, refreshed on unknown `kid`).

### 1.2 Access-token claims

| Claim | Example | Used for |
|---|---|---|
| `iss` | `http://localhost:9000` | Must equal `SECUREMCP_AUTH_ISSUER`. |
| `aud` | `http://localhost:8000/mcp` | Must equal `SECUREMCP_PUBLIC_URL`. Tokens minted for any other resource are refused (no token passthrough, no confused deputy). |
| `sub` | `usr_aur_bruno` | Stable pseudonymous user id. Logged and audited instead of names or e-mails. |
| `client_id` | `securemcp-host` | Which application acts for the user. |
| `tenant_id` | `tnt_aurora` | The **only** source of tenant scope in the whole system. |
| `roles` | `["support_agent"]` | RBAC. |
| `scope` | `"clients:read tickets:read tickets:write"` | What the user delegated to this client. |
| `exp`, `iat`, `nbf`, `jti` | | Lifetime and uniqueness. Clock skew tolerance: 30 s. |

The verified token becomes a `Principal(subject, tenant_id, roles, scopes, client_id, token_id)`. Nothing in the
request body can change it.

### 1.3 Synthetic identities (development only)

| User (login) | Subject | Tenant | Role |
|---|---|---|---|
| `ana` | `usr_aur_ana` | `tnt_aurora` | `viewer` |
| `bruno` | `usr_aur_bruno` | `tnt_aurora` | `support_agent` |
| `carla` | `usr_aur_carla` | `tnt_aurora` | `operations_manager` |
| `diego` | `usr_aur_diego` | `tnt_aurora` | `tenant_admin` |
| `eva` | `usr_bor_eva` | `tnt_boreal` | `support_agent` |
| `fabio` | `usr_bor_fabio` | `tnt_boreal` | `operations_manager` |

Passwords are stored as PBKDF2-SHA256 hashes in `config/auth-users.yaml`; the shared development password is
documented in the README. None of these are real people or companies.

| OAuth client | Type | May request |
|---|---|---|
| `securemcp-host` | public, PKCE | every scope **except** `approvals:decide` |
| `securemcp-approvals` | public, PKCE | `approvals:decide` only |

Because the agent's client can never obtain `approvals:decide`, a compromised agent cannot approve its own actions,
even when the logged-in human is a manager.

## 2. Permissions, roles and scopes

Permissions are named `<domain>:<action>` and double as OAuth scopes.

| Permission | viewer | support_agent | operations_manager | tenant_admin |
|---|:-:|:-:|:-:|:-:|
| `clients:read` | ✓ | ✓ | ✓ | ✓ |
| `cameras:read` | ✓ | ✓ | ✓ | ✓ |
| `contracts:read` | ✓ | ✓ | ✓ | ✓ |
| `tickets:read` | ✓ | ✓ | ✓ | ✓ |
| `maintenance:read` | ✓ | ✓ | ✓ | ✓ |
| `docs:read` | ✓ | ✓ | ✓ | ✓ |
| `tickets:write` | | ✓ | ✓ | ✓ |
| `maintenance:write` | | | ✓ | ✓ |
| `notifications:send` | | | ✓ | ✓ |
| `approvals:decide` | | | ✓ | ✓ |

**Effective permissions = permissions granted by the principal's roles ∩ scopes in the token.**

- Roles say what the *person* may do.
- Scopes say what the person *delegated to this application*.
- Both are re-checked by the gateway on every call, even though the authorization server already intersected
  them, because role mappings in `policy.yaml` may change during a token's lifetime.

## 3. Operation policy

Every tool, resource template and prompt is an **operation** with an entry in `policy.yaml`. Operations that are not
listed do not exist (allowlist, deny by default).

| Operation | Kind | Required permission | Risk | Approval required when | Idempotency key |
|---|---|---|---|---|---|
| `get_client` | tool | `clients:read` | low | never | — |
| `list_camera_health` | tool | `cameras:read` | low | never | — |
| `get_contract_modules` | tool | `contracts:read` | low | never | — |
| `search_tickets` | tool | `tickets:read` | low | never | — |
| `get_maintenance_window` | tool | `maintenance:read` | low | never | — |
| `create_support_ticket` | tool | `tickets:write` | medium | `priority == critical` (pages on-call staff) | required |
| `schedule_maintenance` | tool | `maintenance:write` | high | `duration_minutes > 120` or `len(camera_ids) > 10` | required |
| `send_notification` | tool | `notifications:send` | high | `audience == all_contacts` or `channel == sms` | required |
| `client_summary` | resource `client://{client_id}/summary` | `clients:read` | low | never | — |
| `camera_health` | resource `camera://{camera_id}/health` | `cameras:read` | low | never | — |
| `manual` | resource `docs://manuals/{version}` | `docs:read` | low | never | — |
| `ticket` | resource `ticket://{ticket_id}` | `tickets:read` | low | never | — |
| `incident_triage` | prompt | `tickets:read` | low | never | — |
| `customer_support_summary` | prompt | `clients:read` | low | never | — |
| `maintenance_plan` | prompt | `maintenance:read` | low | never | — |

### 3.1 Decision algorithm

```
evaluate(principal, operation, input):
  1. operation not in policy                      → DENY  UNKNOWN_OPERATION
  2. required permission ∉ effective permissions  → DENY  FORBIDDEN       (policy id: rbac.<operation>)
  3. any approval condition matches input          → APPROVAL_REQUIRED     (policy id: approval.<operation>.<rule>)
  4. otherwise                                     → ALLOW                 (policy id: rbac.<operation>)
```

Conditions are declarative (`eq`, `in`, `gt`, `count_gt` over named input fields). There is no expression
language, no `eval`, and unknown operators fail policy loading at startup. The policy file carries a `version` that
is written into every audit event, so an auditor can tell which rules were in force.

### 3.2 Approvals (human in the loop)

When the decision is `APPROVAL_REQUIRED`, the tool returns a **normal result** with `status: "approval_required"`
and an `approval_id`; nothing is executed. Then:

1. A human with `approvals:decide` (through the `securemcp-approvals` client) lists and decides the approval via
   `POST /approvals/{id}/decision`.
2. **Four-eyes rule**: the approver's `sub` must differ from the requester's `sub`.
3. The agent repeats the call with the same arguments plus `approval_id`. The gateway checks that the approval is
   `approved`, belongs to the same tenant, the same operation, the same requester and the **same argument hash**,
   and has not expired (`ttl_seconds`, default 900). It is then marked `consumed` — single use.

Changing any argument after approval (for example, swapping the recipients) invalidates the approval.

## 4. Tenant isolation

Isolation is enforced in three independent layers ([ADR-0005](adr/0005-tenant-isolation-three-layers.md)):

1. **No tenant input.** No schema has a `tenant_id` field; a test asserts this for every advertised tool,
   resource template and prompt. The tenant comes from the verified token.
2. **Repository filter.** Every repository method takes `tenant_id` first and adds `WHERE tenant_id = :tenant_id`.
   Lookups of another tenant's object return *not found*.
3. **PostgreSQL Row-Level Security.** Each transaction runs `set_config('app.tenant_id', …, true)` and the
   application role (`securemcp_app`, no `BYPASSRLS`, not the table owner) can only see rows whose `tenant_id`
   matches. Even a bug in layer 2 cannot read across tenants.

Cross-tenant requests are answered with `NOT_FOUND`, never `FORBIDDEN`, so a caller cannot probe which ids exist in
other tenants (no enumeration oracle).

## 5. Confused-deputy protections

The MCP server holds credentials for downstream systems (notification API key). A confused deputy would use them on
behalf of a caller who should not have that power. Controls:

| Control | Where |
|---|---|
| Tokens must carry `aud = SECUREMCP_PUBLIC_URL`; tokens for other resources are rejected. | `JwtTokenVerifier`, SDK `validate_token_resource` |
| The caller's token is **never forwarded** downstream; downstream calls use the server's own credential from the secret provider, plus the tenant and subject taken from the verified principal. | `integrations/*` |
| Downstream requests derive tenant and recipient lists server-side: `send_notification` accepts a template name and an audience class, never addresses or free text. Recipients are contacts on file, opted-in, in the caller's tenant. | `services/notifications.py` |
| Approval scope cannot be obtained by the agent's OAuth client. | authorization server client registry |
| Idempotency records and approvals are bound to `(tenant, subject, operation)`; a key or approval id from someone else is useless. | `gateway/idempotency.py`, `gateway/approvals.py` |

## 6. Rate limits and timeouts

Configured in `policy.yaml` and applied per principal:

| Limit | Key | Default |
|---|---|---|
| reads | `(tenant, subject)` | burst 30, refill 2/s |
| writes | `(tenant, subject)` | burst 5, refill 0.2/s |
| tenant total | `tenant` | burst 200, refill 20/s |

Exceeding a limit returns `RATE_LIMITED` with `retry_after_seconds`. Timeouts: 3 s for reads, 8 s for writes,
covering the whole service execution including downstream retries.

## 7. What is audited

Every operation attempt — allowed, denied, failed, replayed, or waiting for approval — produces one audit event
with: `request_id`, `trace_id`, `subject`, `client_id`, `tenant_id`, `operation`, `kind`, `status`, `error_code`,
`policy_id`, `policy_version`, `risk`, `duration_ms`, an `args_fingerprint` (SHA-256 of canonical arguments — not
the arguments), `idempotency_key`, `approval_id` and injection flags. Events are hash-chained per tenant; see
[ADR-0010](adr/0010-hash-chained-audit-trail.md).
