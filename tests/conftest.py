from __future__ import annotations

import httpx
import pytest
from mcp import Client

from securemcp.config import Settings
from securemcp.container import build_container
from securemcp.db.database import create_schema
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


@pytest.fixture
def settings(tmp_path) -> Settings:
    return Settings(
        env="test",
        database_url=f"sqlite+aiosqlite:///{tmp_path}/securemcp.db",
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
    await create_schema(settings.database_url)
    transport = httpx.ASGITransport(app=mocks_app)
    c = build_container(
        settings,
        identity=resolve_test_identity,
        crm_transport=transport,
        notifications_transport=transport,
        retry=RetryPolicy(max_attempts=3, base_delay=0.01),
    )
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
