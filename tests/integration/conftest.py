from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import httpx
import pytest

from securemcp.auth_server import build_auth_app
from securemcp.auth_server.tokens import SigningKey, TokenIssuer
from securemcp.config import Settings
from securemcp.container import build_container
from securemcp.db.database import Database, create_schema
from securemcp.db.seed import seed
from securemcp.host.oauth import login
from securemcp.integrations.http import RetryPolicy
from securemcp.mcp_server.server import build_http_app
from securemcp.mocks.app import create_mocks_app
from securemcp.security.secrets import build_secret_provider
from tests.helpers import ROOT
from tests.servers import ServerThread, free_port

DEV_PASSWORD = "nexus-demo-2026"  # documented synthetic password of config/auth-users.yaml
APPROVALS_REDIRECT = "http://127.0.0.1:8977/callback"


@dataclass
class Stack:
    settings: Settings
    key: SigningKey
    issuer: TokenIssuer
    mocks_app: object
    mcp_url: str
    base_url: str
    _tokens: dict[tuple[str, str], str] = field(default_factory=dict)

    async def token(self, user: str, client: str = "securemcp-host") -> str:
        """Real OAuth 2.1 flow (discovery → PKCE → sign-in → code exchange); cached per user and client."""
        if (user, client) not in self._tokens:
            redirect = self.settings.host_redirect_uri if client == "securemcp-host" else APPROVALS_REDIRECT
            tokens = await login(
                mcp_url=self.mcp_url, username=user, password=DEV_PASSWORD, client_id=client, redirect_uri=redirect
            )
            self._tokens[(user, client)] = tokens.access_token
        return self._tokens[(user, client)]


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    """Authorization server and gateway on real localhost ports; the gateway fetches JWKS over HTTP."""
    as_port, gw_port = free_port(), free_port()
    mcp_url = f"http://127.0.0.1:{gw_port}/mcp"
    db_url = f"sqlite+aiosqlite:///{tmp_path_factory.mktemp('http')}/securemcp.db"
    settings = Settings(
        env="test",
        transport="streamable-http",
        public_url=mcp_url,
        auth_issuer=f"http://127.0.0.1:{as_port}",
        as_issuer=f"http://127.0.0.1:{as_port}",
        as_allowed_resources=[mcp_url],
        as_users_file=ROOT / "config/auth-users.yaml",
        database_url=db_url,
        policy_file=ROOT / "config/policy.yaml",
        docs_dir=ROOT / "data/manuals",
        crm_url="http://mocks/crm",
        notifications_url="http://mocks/notifications",
        _env_file=None,
    )

    async def prepare() -> None:
        await create_schema(db_url)
        db = Database(db_url)
        await seed(db)
        await db.dispose()

    asyncio.run(prepare())
    key = SigningKey.generate()
    mocks_app = create_mocks_app(build_secret_provider(settings))
    transport = httpx.ASGITransport(app=mocks_app)
    container = build_container(
        settings,
        crm_transport=transport,
        notifications_transport=transport,
        retry=RetryPolicy(max_attempts=3, base_delay=0.01),
    )
    with ServerThread(build_auth_app(settings, key=key), as_port), ServerThread(build_http_app(container), gw_port):
        yield Stack(
            settings, key, TokenIssuer(key, settings.as_issuer, 900), mocks_app, mcp_url, f"http://127.0.0.1:{gw_port}"
        )
