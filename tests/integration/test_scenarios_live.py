"""The scenario runner end to end: authorization server, simulated services and gateway as real HTTP servers."""

import asyncio

import pytest

from securemcp.auth_server import build_auth_app
from securemcp.auth_server.tokens import SigningKey
from securemcp.config import Settings
from securemcp.container import build_container
from securemcp.db.database import Database, create_schema
from securemcp.db.seed import seed
from securemcp.integrations.http import RetryPolicy
from securemcp.mcp_server.server import build_http_app
from securemcp.mocks.app import create_mocks_app
from securemcp.scenarios import Runner, report
from securemcp.security.secrets import build_secret_provider
from tests.helpers import ROOT
from tests.integration.conftest import DEV_PASSWORD
from tests.servers import ServerThread, free_port

pytestmark = [pytest.mark.anyio, pytest.mark.http]


@pytest.fixture(scope="module")
def live(tmp_path_factory):
    as_port, gw_port, mocks_port = free_port(), free_port(), free_port()
    mcp_url = f"http://127.0.0.1:{gw_port}/mcp"
    db_url = f"sqlite+aiosqlite:///{tmp_path_factory.mktemp('live')}/securemcp.db"
    settings = Settings(
        env="test",
        transport="streamable-http",
        public_url=mcp_url,
        host_mcp_url=mcp_url,
        auth_issuer=f"http://127.0.0.1:{as_port}",
        as_issuer=f"http://127.0.0.1:{as_port}",
        as_allowed_resources=[mcp_url],
        database_url=db_url,
        policy_file=ROOT / "config/policy.yaml",
        docs_dir=ROOT / "data/manuals",
        crm_url=f"http://127.0.0.1:{mocks_port}/crm",
        notifications_url=f"http://127.0.0.1:{mocks_port}/notifications",
        _env_file=None,
    )

    async def prepare():
        await create_schema(db_url)
        db = Database(db_url)
        await seed(db)
        await db.dispose()

    asyncio.run(prepare())
    container = build_container(settings, retry=RetryPolicy(max_attempts=3, base_delay=0.01))
    with (
        ServerThread(create_mocks_app(build_secret_provider(settings)), mocks_port),
        ServerThread(build_auth_app(settings, key=SigningKey.generate()), as_port),
        ServerThread(build_http_app(container), gw_port),
    ):
        yield settings, f"http://127.0.0.1:{mocks_port}"


async def test_all_scenarios_behave(live):
    settings, mocks_url = live
    runner = Runner(
        mcp_url=settings.host_mcp_url,
        mocks_url=mocks_url,
        password=DEV_PASSWORD,
        redirect_uri=settings.host_redirect_uri,
    )
    results = await runner.run()
    text = report(results, mcp_url=settings.host_mcp_url)
    assert all(r.passed for r in results), text
    assert len(results) == 9 and "9/9 scenarios" in text
