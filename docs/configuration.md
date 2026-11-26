# Configuration reference

All runtime settings are environment variables with the prefix `SECUREMCP_`, read by `securemcp.config.Settings`
(also from a local `.env` file; see `.env.example`). Secrets are **not** settings: they are read through the secret
provider (last section). `tests/unit/test_config_docs.py` fails when a setting exists in code but not in this page.

Defaults are safe for a laptop: every listener binds to `127.0.0.1` and nothing needs a secret to start in `dev`.

## General

| Variable | Default | Description |
|---|---|---|
| `SECUREMCP_ENV` | `dev` | `dev`, `test` or `prod`. In `prod` missing secrets are fatal (no development fallbacks) and `db init --reset` is refused. |
| `SECUREMCP_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING` or `ERROR`. |
| `SECUREMCP_LOG_FORMAT` | `console` | `console` for people, `json` for log pipelines. Both pass through the redaction filter and go to stderr (stdout is the MCP channel under stdio). |

## MCP gateway

| Variable | Default | Description |
|---|---|---|
| `SECUREMCP_PUBLIC_URL` | `http://localhost:8000/mcp` | The URL hosts use to reach the MCP endpoint. It is the OAuth *resource*: access tokens must carry it as `aud` (RFC 8707), and it is published in the Protected Resource Metadata. |
| `SECUREMCP_BIND_HOST` | `127.0.0.1` | Listen address. `0.0.0.0` only inside a container network. |
| `SECUREMCP_PORT` | `8000` | Listen port. |
| `SECUREMCP_TRANSPORT` | `streamable-http` | `streamable-http` (OAuth-protected, multi-user) or `stdio` (one local user, see `SECUREMCP_STDIO_ACCESS_TOKEN`). `securemcp serve --transport` overrides it. |
| `SECUREMCP_ALLOWED_HOSTS` | `localhost:*,127.0.0.1:*` | Comma-separated `Host` header allowlist (DNS-rebinding protection). Other hosts get HTTP 421. |
| `SECUREMCP_ALLOWED_ORIGINS` | `http://localhost:*,http://127.0.0.1:*` | Comma-separated `Origin` allowlist for browser-based hosts. Other origins get HTTP 403. |
| `SECUREMCP_POLICY_FILE` | `config/policy.yaml` | Declarative policy: roles, permissions, approval rules, rate limits, timeouts (ADR-0004). Validated strictly at start-up. |
| `SECUREMCP_DOCS_DIR` | `data/manuals` | Directory served by the `docs://manuals/{version}` resource. |
| `SECUREMCP_STDIO_ACCESS_TOKEN` | — | Only for `stdio`: an access token (from `securemcp token`) verified exactly like a bearer token on every call. Without it every stdio call is `UNAUTHENTICATED`. |
| `SECUREMCP_IDEMPOTENCY_TTL_HOURS` | `24` | How long a write's idempotency record is kept; a retry after that is treated as a new action. |

## Database

| Variable | Default | Description |
|---|---|---|
| `SECUREMCP_DATABASE_URL` | `sqlite+aiosqlite:///./securemcp.db` | SQLAlchemy async URL the gateway uses. On PostgreSQL this must be the least-privilege `securemcp_app` role so Row-Level Security applies (ADR-0005). SQLite is for tests and quick local runs (no RLS). |
| `SECUREMCP_DATABASE_OWNER_URL` | — | Owner connection used by `securemcp db init` and `audit verify` (creates tables, RLS policies and grants). Defaults to `SECUREMCP_DATABASE_URL`. |
| `SECUREMCP_DATABASE_PASSWORD_SECRET` | — | Name of the secret holding the password of `SECUREMCP_DATABASE_URL` (e.g. `postgres_app_password`), so the password never appears in the URL or environment. |
| `SECUREMCP_DATABASE_OWNER_PASSWORD_SECRET` | — | Same, for `SECUREMCP_DATABASE_OWNER_URL`. |

## Token verification (the gateway as OAuth resource server)

| Variable | Default | Description |
|---|---|---|
| `SECUREMCP_AUTH_ISSUER` | `http://localhost:9000` | Expected `iss` of access tokens, and the authorization server advertised to hosts. Must be the URL hosts see. |
| `SECUREMCP_AUTH_JWKS_URL` | `<issuer>/jwks.json` | Where signing keys are fetched. Set it when the gateway reaches the issuer through another address (e.g. `http://auth:9000/jwks.json` inside Compose). Keys are cached and refetched on unknown `kid` at most every 10 s. |
| `SECUREMCP_AUTH_CLOCK_SKEW_SECONDS` | `30` | Leeway for `exp`/`nbf`/`iat`. |

## Downstream systems

| Variable | Default | Description |
|---|---|---|
| `SECUREMCP_CRM_URL` | `http://localhost:8081/crm` | Base URL of the CRM (simulated). |
| `SECUREMCP_NOTIFICATIONS_URL` | `http://localhost:8081/notifications` | Base URL of the notification provider (simulated). |
| `SECUREMCP_HTTP_CONNECT_TIMEOUT_SECONDS` | `1.0` | Connect timeout per attempt. |
| `SECUREMCP_HTTP_READ_TIMEOUT_SECONDS` | `2.0` | Read timeout per attempt. The whole operation is also bounded by the policy timeout (`timeouts` in the policy file). |
| `SECUREMCP_HTTP_MAX_ATTEMPTS` | `3` | Attempts for transient failures only (connect errors, timeouts, 429/502/503/504), with jittered backoff; requests without an idempotency guarantee are never retried (ADR-0008). |

## Secrets backend

| Variable | Default | Description |
|---|---|---|
| `SECUREMCP_SECRETS_BACKEND` | `env` | `env` reads `SECUREMCP_SECRET_<NAME>` variables (development); `file` reads one file per secret (Compose/Kubernetes secrets). |
| `SECUREMCP_SECRETS_DIR` | `/run/secrets` | Directory for the `file` backend. |

## Telemetry

| Variable | Default | Description |
|---|---|---|
| `SECUREMCP_OTEL_ENABLED` | `false` | Export traces with OTLP/HTTP. The endpoint comes from the standard `OTEL_EXPORTER_OTLP_ENDPOINT` (Compose: the collector). |
| `SECUREMCP_OTEL_SERVICE_NAME` | `securemcp-gateway` | `service.name` resource attribute. |

## Local authorization server

| Variable | Default | Description |
|---|---|---|
| `SECUREMCP_AS_ISSUER` | `http://localhost:9000` | Issuer URL in metadata and in the `iss` claim. |
| `SECUREMCP_AS_BIND_HOST` | `127.0.0.1` | Listen address. |
| `SECUREMCP_AS_PORT` | `9000` | Listen port. |
| `SECUREMCP_AS_USERS_FILE` | `config/auth-users.yaml` | Synthetic users (PBKDF2 password hashes, tenant, roles) and pre-registered clients (exact redirect URIs, allowed scopes). |
| `SECUREMCP_AS_TOKEN_TTL_SECONDS` | `900` | Access-token lifetime. Short on purpose: there are no refresh tokens. |
| `SECUREMCP_AS_ALLOWED_RESOURCES` | `http://localhost:8000/mcp` | Comma-separated resources (audiences) this server issues tokens for. Requests for any other `resource` are refused. |

## Simulated services

| Variable | Default | Description |
|---|---|---|
| `SECUREMCP_MOCKS_BIND_HOST` | `127.0.0.1` | Listen address of the simulated CRM and notification API. |
| `SECUREMCP_MOCKS_PORT` | `8081` | Listen port. Its `/_faults` endpoint injects failures for the scenarios; never expose it beyond localhost. |

## Demo host and agent

| Variable | Default | Description |
|---|---|---|
| `SECUREMCP_HOST_MCP_URL` | `http://localhost:8000/mcp` | MCP server the demo host connects to. Everything else (authorization server, endpoints) is discovered from it. |
| `SECUREMCP_HOST_CLIENT_ID` | `securemcp-host` | OAuth client used for agent work (cannot hold `approvals:decide`). |
| `SECUREMCP_HOST_APPROVALS_CLIENT_ID` | `securemcp-approvals` | OAuth client used by approvers (holds only `approvals:decide`). |
| `SECUREMCP_HOST_REDIRECT_URI` | `http://127.0.0.1:8976/callback` | Registered redirect URI of the host client. |
| `SECUREMCP_HOST_TOKEN_CACHE` | `.securemcp/tokens.json` | Where the host keeps access tokens (created with mode `600`, git-ignored). |
| `SECUREMCP_AGENT_PLANNER` | `rule` | `rule` (deterministic, offline), `claude` (Claude via the official `anthropic` SDK; needs `ANTHROPIC_API_KEY`) or `injection-following` (adversarial test double). |
| `SECUREMCP_AGENT_MODEL` | `claude-opus-5-5` | Model id for the `claude` planner. |
| `SECUREMCP_AGENT_MAX_STEPS` | `8` | Step budget per request; the agent stops and answers when it is reached. |

## Other environment variables

| Variable | Used by | Description |
|---|---|---|
| `OTEL_EXPORTER_OTLP_ENDPOINT` | gateway | Standard OpenTelemetry variable; e.g. `http://otel-collector:4318`. |
| `ANTHROPIC_API_KEY` | demo host with `--planner claude` | Read by the `anthropic` SDK. Never sent to the MCP server. |
| `SECUREMCP_SECRET_<NAME>` | `env` secrets backend | Development-only secret values, e.g. `SECUREMCP_SECRET_CRM_API_KEY`. |
| `SECUREMCP_TEST_POSTGRES_URL` | tests | Owner URL of a disposable PostgreSQL for `test_rls_postgres.py` (`make test-pg` sets it). |
| `SECUREMCP_TEST_POSTGRES_APP_URL` | tests | Same database as the `securemcp_app` role. |
| `SECUREMCP_TEST_BACKEND` | tests | `postgres` runs the whole integration suite on that database instead of SQLite. |

## Secrets

| Name | Used by | Notes |
|---|---|---|
| `auth_signing_key` | authorization server | RSA private key (PEM). In `dev`/`test`, if absent, an ephemeral key is generated (tokens stop verifying after a restart). Required in `prod`. |
| `crm_api_key` | gateway, simulated CRM | In `dev`/`test`, falls back to a fixed, obviously insecure value with a warning. |
| `notifications_api_key` | gateway, simulated notification API | Same fallback rule. |
| `postgres_owner_password` | PostgreSQL, `db init` | Never falls back. |
| `postgres_app_password` | PostgreSQL init script, gateway | Never falls back. |

`make secrets` creates all of them for Compose (see `deploy/secrets/README.md`).
