"""Local OAuth 2.1 authorization server (development stand-in for an enterprise IdP)."""

from __future__ import annotations

import logging

from fastapi import FastAPI

from securemcp.auth_server.app import Directory, create_auth_app
from securemcp.auth_server.tokens import SigningKey, TokenIssuer
from securemcp.config import Settings
from securemcp.security.policy import PolicyEngine
from securemcp.security.secrets import SecretNotFound, build_secret_provider

log = logging.getLogger(__name__)


def load_signing_key(settings: Settings) -> SigningKey:
    try:
        return SigningKey.from_pem(build_secret_provider(settings).get("auth_signing_key").get_secret_value())
    except SecretNotFound:
        if settings.env == "prod":
            raise
        log.warning("auth_signing_key not configured: using an ephemeral key (tokens die with this process)")
        return SigningKey.generate()


def build_auth_app(settings: Settings, key: SigningKey | None = None) -> FastAPI:
    issuer = TokenIssuer(key or load_signing_key(settings), settings.as_issuer, settings.as_token_ttl_seconds)
    return create_auth_app(
        issuer=issuer,
        directory=Directory.from_file(settings.as_users_file),
        policy=PolicyEngine.from_file(settings.policy_file),
        allowed_resources=settings.as_allowed_resources,
    )
