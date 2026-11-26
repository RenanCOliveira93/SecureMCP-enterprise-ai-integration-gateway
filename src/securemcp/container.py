"""Dependency wiring. One place builds every component from Settings, so tests can swap any piece."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

import httpx
from mcp.server.auth.middleware.auth_context import get_access_token

from securemcp.config import Settings
from securemcp.db.database import Database
from securemcp.gateway.approvals import ApprovalStore
from securemcp.gateway.audit import AuditTrail
from securemcp.gateway.idempotency import IdempotencyStore
from securemcp.gateway.operations import register_operations
from securemcp.gateway.pipeline import Gateway, IdentityResolver
from securemcp.integrations.clients import CrmClient, NotificationClient
from securemcp.integrations.http import ResilientHttp, RetryPolicy
from securemcp.security.identity import Principal, principal_from_access_token
from securemcp.security.jwt_verifier import JwksCache, JwtTokenVerifier
from securemcp.security.policy import PolicyEngine
from securemcp.security.rate_limit import InMemoryRateLimiter, RateLimiter
from securemcp.security.secrets import SecretProvider, build_secret_provider
from securemcp.services.domain import NexusServices
from securemcp.services.prompts import PromptService


@dataclass
class Container:
    settings: Settings
    secrets: SecretProvider
    db: Database
    policy: PolicyEngine
    verifier: JwtTokenVerifier
    gateway: Gateway
    services: NexusServices
    audit: AuditTrail
    approvals: ApprovalStore
    crm_http: ResilientHttp
    notifications_http: ResilientHttp

    async def aclose(self) -> None:
        await self.crm_http.aclose()
        await self.notifications_http.aclose()
        await self.db.dispose()


def make_identity_resolver(settings: Settings, verifier: JwtTokenVerifier) -> IdentityResolver:
    """HTTP: the SDK bearer middleware already verified the token and put it in a contextvar.
    stdio: there are no headers, so the token configured in SECUREMCP_STDIO_ACCESS_TOKEN is verified per call."""

    async def resolve() -> Principal | None:
        token = get_access_token()
        if token is not None:
            return principal_from_access_token(token)
        if settings.transport == "stdio" and settings.stdio_access_token:
            verified = await verifier.verify_token(settings.stdio_access_token)
            return principal_from_access_token(verified) if verified else None
        return None

    return resolve


def build_container(
    settings: Settings,
    *,
    verifier: JwtTokenVerifier | None = None,
    identity: IdentityResolver | None = None,
    rate_limiter: RateLimiter | None = None,
    crm_transport: httpx.AsyncBaseTransport | None = None,
    notifications_transport: httpx.AsyncBaseTransport | None = None,
    retry: RetryPolicy | None = None,
) -> Container:
    secrets = build_secret_provider(settings)
    db = Database(settings.database_url)
    policy = PolicyEngine.from_file(settings.policy_file)
    verifier = verifier or JwtTokenVerifier(
        issuer=settings.auth_issuer,
        audience=settings.public_url,
        jwks=JwksCache(settings.jwks_url),
        leeway_seconds=settings.auth_clock_skew_seconds,
    )
    retry = retry or RetryPolicy(max_attempts=settings.http_max_attempts)
    http_kwargs = {
        "connect_timeout": settings.http_connect_timeout_seconds,
        "read_timeout": settings.http_read_timeout_seconds,
        "retry": retry,
    }
    crm_http = ResilientHttp(service="crm", base_url=settings.crm_url, transport=crm_transport, **http_kwargs)
    notif_http = ResilientHttp(
        service="notifications", base_url=settings.notifications_url, transport=notifications_transport, **http_kwargs
    )
    services = NexusServices(
        db, CrmClient(crm_http, secrets), NotificationClient(notif_http, secrets), settings.docs_dir
    )
    audit = AuditTrail(db)
    approvals = ApprovalStore(
        db, ttl_seconds=policy.doc.approvals.ttl_seconds, four_eyes=policy.doc.approvals.four_eyes
    )
    gateway = Gateway(
        policy=policy,
        rate_limiter=rate_limiter or InMemoryRateLimiter(policy.doc.rate_limits),
        idempotency=IdempotencyStore(db, timedelta(hours=settings.idempotency_ttl_hours)),
        approvals=approvals,
        audit=audit,
        identity=identity or make_identity_resolver(settings, verifier),
    )
    register_operations(gateway, services, PromptService(services), approvals)
    return Container(
        settings=settings,
        secrets=secrets,
        db=db,
        policy=policy,
        verifier=verifier,
        gateway=gateway,
        services=services,
        audit=audit,
        approvals=approvals,
        crm_http=crm_http,
        notifications_http=notif_http,
    )
