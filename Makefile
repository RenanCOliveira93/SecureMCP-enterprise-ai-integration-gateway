# Podman users: `make up COMPOSE="podman compose"` or export DOCKER_HOST to the Podman socket and keep the default.
COMPOSE ?= docker compose
SECRETS := deploy/secrets
PG_TEST_OWNER := postgresql+psycopg://securemcp_owner:owner-test-only@127.0.0.1:55432/securemcp
PG_TEST_APP := postgresql+psycopg://securemcp_app:app-test-only@127.0.0.1:55432/securemcp

.PHONY: install lint test test-pg secrets up down logs ps scenarios demo audit token inspector clean

install:  ## Create .venv with runtime and dev dependencies
	uv sync

lint:  ## Ruff lint + format check
	uv run ruff check src tests
	uv run ruff format --check src tests

test:  ## Full suite on SQLite (PostgreSQL-only tests are skipped)
	uv run pytest

test-pg:  ## RLS tests + whole integration suite on a disposable PostgreSQL
	$(COMPOSE) --profile test up -d --wait postgres-test
	SECUREMCP_TEST_POSTGRES_URL=$(PG_TEST_OWNER) SECUREMCP_TEST_POSTGRES_APP_URL=$(PG_TEST_APP) \
	  uv run pytest tests/integration/test_rls_postgres.py
	SECUREMCP_TEST_BACKEND=postgres SECUREMCP_TEST_POSTGRES_URL=$(PG_TEST_OWNER) \
	  SECUREMCP_TEST_POSTGRES_APP_URL=$(PG_TEST_APP) uv run pytest tests/integration -m "not http"
	$(COMPOSE) --profile test rm -sf postgres-test

secrets:  ## Generate local secrets once (never committed; see deploy/secrets/README.md)
	@mkdir -p $(SECRETS) && chmod 700 $(SECRETS)
	@test -f $(SECRETS)/auth_signing_key || uv run securemcp generate-signing-key --out $(SECRETS)/auth_signing_key
	@for name in crm_api_key notifications_api_key postgres_owner_password postgres_app_password; do \
	  test -f $(SECRETS)/$$name || python3 -c "import secrets; print(secrets.token_urlsafe(32), end='')" > $(SECRETS)/$$name; \
	done
	@chmod 644 $(SECRETS)/*  # readable by the non-root container user; the directory itself stays 700
	@echo "secrets ready in $(SECRETS)/"

up: secrets  ## Build and start the stack (gateway, auth, mocks, postgres, otel-collector, jaeger)
	$(COMPOSE) build mcp
	$(COMPOSE) up -d --wait

down:  ## Stop the stack (keeps the database volume)
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f mcp

ps:
	$(COMPOSE) ps

scenarios:  ## Run the end-to-end scenarios against the running stack and write reports/scenarios.md
	@echo nexus-demo-2026 | uv run securemcp scenarios --password-stdin --report reports/scenarios.md

demo:  ## Guided demo with the demo host (see README)
	@echo nexus-demo-2026 | uv run securemcp-host login --user carla --password-stdin
	uv run securemcp-host tools
	uv run securemcp-host chat "Show camera health for cli_aur001"
	uv run securemcp-host chat "Triage ticket tkt_aur00003 for cli_aur001" --planner injection-following

audit:  ## Verify the audit hash chain of every tenant (owner connection)
	$(COMPOSE) run --rm migrate audit verify

token:  ## Print an access token for USER (e.g. make token USER=bruno), for the Inspector
	@uv run securemcp token --user $(USER)

inspector:  ## MCP Inspector (needs Node.js). Paste a token from `make token` as Bearer authentication.
	npx -y @modelcontextprotocol/inspector

clean:  ## Remove the stack, its volume and local caches
	$(COMPOSE) down -v
	rm -rf .securemcp reports .pytest_cache
