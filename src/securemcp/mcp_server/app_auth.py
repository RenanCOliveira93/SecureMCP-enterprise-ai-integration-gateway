"""MCP SDK auth wiring: this server is an OAuth 2.1 *resource server* (it never issues tokens)."""

from __future__ import annotations

from mcp.server.auth.settings import AuthSettings

from securemcp.config import Settings


def auth_settings(settings: Settings) -> AuthSettings:
    return AuthSettings(
        issuer_url=settings.auth_issuer,  # advertised in Protected Resource Metadata (RFC 9728)
        resource_server_url=settings.public_url,  # the audience tokens must be bound to (RFC 8707)
        validate_token_resource=True,  # SDK re-checks AccessToken.resource == resource_server_url
        required_scopes=[],  # per-operation permissions are enforced by the gateway policy instead
    )
