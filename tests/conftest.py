from __future__ import annotations

import os

import httpx
import pytest
from mcp import Client

from securemcp.config import Settings
from securemcp.container import build_container
from securemcp.db.database import Database, create_schema
from securemcp.db.seed import seed
from securemcp.integrations.http import RetryPolicy
from securemcp.mcp_server.server import build_server
from securemcp.mocks.app import create_mocks_app
from securemcp.security.secrets import build_secret_provider
from tests.helpers import ROOT, resolve_test_identity


@pytest.fixture
def anyio_backend():
    # Test modules set ``pytestmark = pytest.mark.anyio``: async tests and their async fixtures then run in one
    # task, which the MCP client's anyio cancel scopes require.
    return "asyncio"


# SECUREMCP_TEST_BACKEND=postgres runs the whole suite as the RLS-constrained app role (see `make test-pg`).
PG_OWNER_URL = os.environ.get("SECUREMCP_TEST_POSTGRES_URL")
PG_APP_URL = os.environ.get("SECUREMCP_TEST_POSTGRES_APP_URL")
ON_POSTGRES = os.environ.get("SECUREMCP_TEST_BACKEND") == "postgres" and bool(PG_OWNER_URL and PG_APP_URL)


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        env="test",
        database_url=PG_APP_URL if ON_POSTGRES else f"sqlite+aiosqlite:///{tmp_path}/securemcp.db",
        transport="stdio",
        policy_file=ROOT / "config/policy.yaml",
        docs_dir=ROOT / "data/manuals",
        crm_url="http://mocks/crm",
        notifications_url="http://mocks/notifications",
        http_max_attempts=3,
        _env_file=None,
    )


@pytest.fixture
def mocks_app(settings):
    return create_mocks_app(build_secret_provider(settings))


@pytest.fixture
async def container(settings, mocks_app):
    if ON_POSTGRES:
        await create_schema(PG_OWNER_URL, reset=True)
    else:
        await create_schema(settings.database_url)
    transport = httpx.ASGITransport(app=mocks_app)
    c = build_container(
        settings,
        identity=resolve_test_identity,
        crm_transport=transport,
        notifications_transport=transport,
        retry=RetryPolicy(max_attempts=3, base_delay=0.01),
    )
    if ON_POSTGRES:
        owner = Database(PG_OWNER_URL)
        await seed(owner)
        await owner.dispose()
    else:
        await seed(c.db)
    yield c
    await c.aclose()


@pytest.fixture
def mock_state(mocks_app):
    return mocks_app.state.mock


@pytest.fixture
async def mcp(container):
    async with Client(build_server(container)) as client:
        yield client
