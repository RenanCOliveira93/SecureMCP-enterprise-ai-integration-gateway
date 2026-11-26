"""Access-token verification for the MCP resource server (ADR-0003).

Implements the MCP SDK ``TokenVerifier`` protocol: return an ``AccessToken`` for a valid token, ``None`` otherwise.
Checks: RS256 signature against the issuer's JWKS, ``alg`` pinned, ``iss``, ``aud`` (RFC 8707 resource binding),
``exp``/``nbf``/``iat`` with bounded clock skew, and the presence and shape of the custom claims we rely on.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import Any

import httpx
import jwt
from mcp.server.auth.provider import AccessToken

log = logging.getLogger(__name__)

_ALGORITHMS = ["RS256"]
_SUBJECT = re.compile(r"^usr_[a-z0-9_]{3,40}$")
_TENANT = re.compile(r"^tnt_[a-z0-9]{3,20}$")
_REQUIRED = ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"]


class JwksCache:
    """Caches signing keys by ``kid``; refetches on unknown ``kid`` at most every ``min_refresh_seconds``."""

    def __init__(
        self,
        jwks_url: str | None = None,
        *,
        static_jwks: dict[str, Any] | None = None,
        ttl_seconds: float = 300.0,
        min_refresh_seconds: float = 10.0,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        self.jwks_url = jwks_url
        self.ttl = ttl_seconds
        self.min_refresh = min_refresh_seconds
        self._keys: dict[str, Any] = {}
        self._fetched_at = 0.0
        self._lock = asyncio.Lock()
        self._http = http
        if static_jwks is not None:
            self._load(static_jwks)
            self._fetched_at = float("inf")

    def _load(self, jwks: dict[str, Any]) -> None:
        keys = {}
        for jwk in jwks.get("keys", []):
            if jwk.get("kty") == "RSA" and jwk.get("kid") and jwk.get("use", "sig") == "sig":
                keys[jwk["kid"]] = jwt.PyJWK(jwk, algorithm="RS256").key
        self._keys = keys

    async def _refresh(self) -> None:
        if not self.jwks_url:
            return
        client = self._http or httpx.AsyncClient(timeout=3.0)
        try:
            response = await client.get(self.jwks_url)
            response.raise_for_status()
            self._load(response.json())
            self._fetched_at = time.monotonic()
        finally:
            if self._http is None:
                await client.aclose()

    async def key_for(self, kid: str) -> Any | None:
        now = time.monotonic()
        if kid in self._keys and now - self._fetched_at < self.ttl:
            return self._keys[kid]
        async with self._lock:
            stale = now - self._fetched_at
            if (kid not in self._keys or stale >= self.ttl) and stale >= self.min_refresh:
                try:
                    await self._refresh()
                except (httpx.HTTPError, ValueError) as exc:
                    log.warning("JWKS refresh failed: %s", type(exc).__name__)
        return self._keys.get(kid)


class JwtTokenVerifier:
    def __init__(self, *, issuer: str, audience: str, jwks: JwksCache, leeway_seconds: int = 30) -> None:
        self.issuer = issuer
        self.audience = audience
        self.jwks = jwks
        self.leeway = leeway_seconds

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            return None
        if header.get("alg") not in _ALGORITHMS or not isinstance(header.get("kid"), str):
            return None
        key = await self.jwks.key_for(header["kid"])
        if key is None:
            return None
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=_ALGORITHMS,
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway,
                options={"require": _REQUIRED},
            )
        except jwt.PyJWTError as exc:
            log.info("token rejected: %s", type(exc).__name__)
            return None
        return self._to_access_token(token, claims)

    def _to_access_token(self, token: str, claims: dict[str, Any]) -> AccessToken | None:
        subject, tenant = claims.get("sub"), claims.get("tenant_id")
        roles, scope, client_id = claims.get("roles"), claims.get("scope", ""), claims.get("client_id")
        if not (isinstance(subject, str) and _SUBJECT.match(subject)):
            return None
        if not (isinstance(tenant, str) and _TENANT.match(tenant)):
            return None
        if not (isinstance(roles, list) and all(isinstance(r, str) for r in roles)):
            return None
        if not isinstance(scope, str) or not isinstance(client_id, str):
            return None
        aud = claims["aud"]
        resource = aud if isinstance(aud, str) else next((a for a in aud if a == self.audience), None)
        return AccessToken(
            token=token,
            client_id=client_id,
            scopes=scope.split(),
            expires_at=int(claims["exp"]),
            resource=resource,
            subject=subject,
            claims={"iss": claims["iss"], "tenant_id": tenant, "roles": roles, "jti": claims["jti"]},
        )
