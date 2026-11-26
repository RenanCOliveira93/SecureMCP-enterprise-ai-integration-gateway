#!/bin/sh
# Runs once, on first start of the PostgreSQL container (docker-entrypoint-initdb.d).
# Creates the least-privilege role the gateway connects with. Tables, RLS policies and grants are created later by
# `securemcp db init` (as the owner); see src/securemcp/db/database.py and ADR-0005.
set -eu
APP_PASSWORD="$(cat "${POSTGRES_APP_PASSWORD_FILE:-/run/secrets/postgres_app_password}")"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -v app_password="$APP_PASSWORD" <<'SQL'
CREATE ROLE securemcp_app LOGIN PASSWORD :'app_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
SELECT format('GRANT CONNECT ON DATABASE %I TO securemcp_app', current_database()) \gexec
SQL
