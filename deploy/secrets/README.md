# Local secrets

`make secrets` creates one file per secret in this directory. They are git-ignored and mounted into the containers
as Compose secrets under `/run/secrets/<name>`, which `SECUREMCP_SECRETS_BACKEND=file` reads (ADR-0015).

| File | Used by | Content |
|---|---|---|
| `auth_signing_key` | authorization server | RSA-2048 private key (PEM) that signs access tokens |
| `crm_api_key` | gateway, simulated CRM | server-to-server API key |
| `notifications_api_key` | gateway, simulated notification API | server-to-server API key |
| `postgres_owner_password` | PostgreSQL, `migrate` | password of the schema owner |
| `postgres_app_password` | PostgreSQL init, gateway | password of the least-privilege `securemcp_app` role |

The directory is `700`; the files are `644` because the containers run as a non-root user that must read the
bind-mounted file. To rotate a secret, delete its file, run `make secrets` and recreate the containers (the database
passwords are applied only when the PostgreSQL volume is first created: rotate them with `ALTER ROLE`).

In production these come from a secret manager (Vault, AWS Secrets Manager, Kubernetes secrets): implement
`SecretProvider.get(name)` for it; nothing else changes.
