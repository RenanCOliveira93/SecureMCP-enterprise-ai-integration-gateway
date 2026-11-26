"""The authenticated caller, derived exclusively from a verified access token."""

from __future__ import annotations

from dataclasses import dataclass, field

from mcp.server.auth.provider import AccessToken


@dataclass(frozen=True)
class Principal:
    subject: str
    tenant_id: str
    roles: frozenset[str]
    scopes: frozenset[str]
    client_id: str
    token_id: str | None = None
    issuer: str | None = None
    extra: dict[str, str] = field(default_factory=dict, compare=False, hash=False)


def principal_from_access_token(token: AccessToken) -> Principal:
    """Build a Principal from an AccessToken produced by ``JwtTokenVerifier``.

    The verifier already rejected tokens without these claims, so a KeyError here is a programming error.
    """
    claims = token.claims or {}
    return Principal(
        subject=str(token.subject),
        tenant_id=str(claims["tenant_id"]),
        roles=frozenset(claims.get("roles", [])),
        scopes=frozenset(token.scopes),
        client_id=token.client_id,
        token_id=claims.get("jti"),
        issuer=claims.get("iss"),
    )
