"""All runtime configuration, read from environment variables (prefix ``SECUREMCP_``).

Every field below is documented in ``docs/configuration.md``; ``tests/unit/test_config_docs.py`` fails if a field
is added here without documentation. Secrets are *not* configured here: they come from the
``SecretProvider`` (see ``securemcp.security.secrets``).
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

CommaList = Annotated[list[str], NoDecode]


def _split(value: object) -> object:
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return value


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SECUREMCP_", env_file=".env", extra="ignore")

    # ------------------------------------------------------------------ general
    env: Literal["dev", "test", "prod"] = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    log_format: Literal["json", "console"] = "console"

    # ------------------------------------------------------------- MCP gateway
    public_url: str = "http://localhost:8000/mcp"
    bind_host: str = "127.0.0.1"
    port: int = 8000
    transport: Literal["streamable-http", "stdio"] = "streamable-http"
    allowed_hosts: CommaList = Field(default_factory=lambda: ["localhost:*", "127.0.0.1:*"])
    allowed_origins: CommaList = Field(default_factory=lambda: ["http://localhost:*", "http://127.0.0.1:*"])
    policy_file: Path = Path("config/policy.yaml")
    docs_dir: Path = Path("data/manuals")
    stdio_access_token: str | None = None
    idempotency_ttl_hours: int = 24

    # ----------------------------------------------------------------- database
    database_url: str = "sqlite+aiosqlite:///./securemcp.db"
    database_owner_url: str | None = None
    database_password_secret: str | None = None
    database_owner_password_secret: str | None = None

    # ------------------------------------------------- token verification (RS)
    auth_issuer: str = "http://localhost:9000"
    auth_jwks_url: str | None = None
    auth_clock_skew_seconds: int = 30

    # ------------------------------------------------------ downstream systems
    crm_url: str = "http://localhost:8081/crm"
    notifications_url: str = "http://localhost:8081/notifications"
    http_connect_timeout_seconds: float = 1.0
    http_read_timeout_seconds: float = 2.0
    http_max_attempts: int = 3

    # ------------------------------------------------------------------ secrets
    secrets_backend: Literal["env", "file"] = "env"
    secrets_dir: Path = Path("/run/secrets")

    # ---------------------------------------------------------------- telemetry
    otel_enabled: bool = False
    otel_service_name: str = "securemcp-gateway"

    # ------------------------------------------------ authorization server (AS)
    as_issuer: str = "http://localhost:9000"
    as_bind_host: str = "127.0.0.1"
    as_port: int = 9000
    as_users_file: Path = Path("config/auth-users.yaml")
    as_token_ttl_seconds: int = 900
    as_allowed_resources: CommaList = Field(default_factory=lambda: ["http://localhost:8000/mcp"])

    # ---------------------------------------------------------------- mock APIs
    mocks_bind_host: str = "127.0.0.1"
    mocks_port: int = 8081

    # ------------------------------------------------------------ host / agent
    host_mcp_url: str = "http://localhost:8000/mcp"
    host_client_id: str = "securemcp-host"
    host_approvals_client_id: str = "securemcp-approvals"
    host_redirect_uri: str = "http://127.0.0.1:8976/callback"
    host_token_cache: Path = Path(".securemcp/tokens.json")
    agent_planner: Literal["rule", "claude"] = "rule"
    agent_model: str = "claude-opus-5-5"
    agent_max_steps: int = 8

    _split_hosts = field_validator("allowed_hosts", "allowed_origins", "as_allowed_resources", mode="before")(
        classmethod(lambda cls, v: _split(v))
    )

    @property
    def jwks_url(self) -> str:
        return self.auth_jwks_url or f"{self.auth_issuer.rstrip('/')}/jwks.json"

    @property
    def is_postgres(self) -> bool:
        return self.database_url.startswith("postgresql")


@lru_cache
def get_settings() -> Settings:
    return Settings()
