"""A small OAuth 2.1 authorization server for local development (ADR-0003).

Supported: RFC 8414 metadata, JWKS, authorization code grant with mandatory PKCE S256, RFC 8707 resource indicators,
RFC 9207 ``iss`` in the authorization response, pre-registered public clients, synthetic users.
Not supported on purpose: implicit/password grants, dynamic client registration, refresh tokens.
"""

from __future__ import annotations

import html
import logging
import secrets
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated
from urllib.parse import urlencode

import yaml
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from securemcp.auth_server.tokens import TokenIssuer, pkce_challenge, verify_password
from securemcp.security.policy import PolicyEngine

log = logging.getLogger(__name__)

CODE_TTL_SECONDS = 60


class UserRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str
    subject: str = Field(pattern=r"^usr_[a-z0-9_]{3,40}$")
    tenant_id: str = Field(pattern=r"^tnt_[a-z0-9]{3,20}$")
    roles: list[str]
    password_hash: str


class ClientRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")
    client_id: str
    name: str
    redirect_uris: list[str]
    allowed_scopes: list[str]


class Directory(BaseModel):
    model_config = ConfigDict(extra="forbid")
    users: list[UserRecord]
    clients: list[ClientRecord]

    @classmethod
    def from_file(cls, path: Path) -> Directory:
        return cls.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))

    def user(self, username: str) -> UserRecord | None:
        return next((u for u in self.users if u.username == username), None)

    def client(self, client_id: str) -> ClientRecord | None:
        return next((c for c in self.clients if c.client_id == client_id), None)


@dataclass
class PendingCode:
    client_id: str
    redirect_uri: str
    code_challenge: str
    user: UserRecord
    scopes: list[str]
    resource: str
    expires_at: float


def _oauth_error(error: str, description: str, status: int = 400) -> JSONResponse:
    return JSONResponse(
        {"error": error, "error_description": description}, status_code=status, headers={"Cache-Control": "no-store"}
    )


def _page(body: str, status: int = 200) -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><html><head><meta charset='utf-8'><title>SecureMCP sign-in</title>"
        f"<style>body{{font-family:system-ui;max-width:28rem;margin:4rem auto}}input{{display:block;width:100%;"
        f"margin:.4rem 0 1rem;padding:.4rem}}</style></head><body>{body}</body></html>",
        status_code=status,
        headers={
            "Cache-Control": "no-store",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
        },
    )


def create_auth_app(
    *, issuer: TokenIssuer, directory: Directory, policy: PolicyEngine, allowed_resources: list[str]
) -> FastAPI:
    app = FastAPI(title="SecureMCP local authorization server", docs_url=None, redoc_url=None)
    codes: dict[str, PendingCode] = {}
    base = issuer.issuer.rstrip("/")

    def granted_scopes(user: UserRecord, client: ClientRecord, requested: list[str]) -> list[str]:
        """requested ∩ what the client may ask for ∩ what the user's roles grant."""
        role_perms = policy.role_permissions(frozenset(user.roles))
        wanted = set(requested) if requested else set(client.allowed_scopes)
        return sorted(wanted & set(client.allowed_scopes) & role_perms)

    def validate_request(
        client_id: str,
        redirect_uri: str,
        response_type: str,
        code_challenge: str,
        code_challenge_method: str,
        resource: str,
    ) -> tuple[ClientRecord | None, str | None]:
        client = directory.client(client_id)
        if client is None:
            return None, "unknown client_id"
        if redirect_uri not in client.redirect_uris:  # exact match, never redirect to an unregistered URI
            return None, "redirect_uri is not registered for this client"
        if response_type != "code":
            return client, "response_type must be code"
        if code_challenge_method != "S256" or not (43 <= len(code_challenge) <= 128):
            return client, "PKCE with code_challenge_method=S256 is required"
        if resource not in allowed_resources:
            return client, "resource is not served by this authorization server"
        return client, None

    @app.get("/.well-known/oauth-authorization-server")
    async def metadata() -> dict:
        return {
            "issuer": issuer.issuer,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "jwks_uri": f"{base}/jwks.json",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": policy.doc.permissions,
            "authorization_response_iss_parameter_supported": True,
        }

    @app.get("/jwks.json")
    async def jwks() -> Response:
        return JSONResponse(issuer.jwks(), headers={"Cache-Control": "public, max-age=300"})

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    @app.get("/authorize")
    async def authorize_form(
        client_id: str = "",
        redirect_uri: str = "",
        response_type: str = "",
        code_challenge: str = "",
        code_challenge_method: str = "",
        resource: str = "",
        scope: str = "",
        state: str = "",
    ) -> Response:
        client, problem = validate_request(
            client_id, redirect_uri, response_type, code_challenge, code_challenge_method, resource
        )
        if problem:
            return _page(f"<h1>Invalid request</h1><p>{html.escape(problem)}</p>", 400)
        hidden = "".join(
            f"<input type='hidden' name='{k}' value='{html.escape(v, quote=True)}'>"
            for k, v in {
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": response_type,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "resource": resource,
                "scope": scope,
                "state": state,
            }.items()
        )
        return _page(
            f"<h1>Sign in</h1><p><b>{html.escape(client.name)}</b> asks to access "  # type: ignore[union-attr]
            f"<code>{html.escape(resource)}</code> with scopes <code>{html.escape(scope or 'default')}</code>.</p>"
            f"<form method='post' action='/authorize'>{hidden}<label>Username<input name='username'></label>"
            f"<label>Password<input name='password' type='password'></label><button>Allow</button></form>"
        )

    @app.post("/authorize")
    async def authorize_submit(
        client_id: Annotated[str, Form()] = "",
        redirect_uri: Annotated[str, Form()] = "",
        response_type: Annotated[str, Form()] = "",
        code_challenge: Annotated[str, Form()] = "",
        code_challenge_method: Annotated[str, Form()] = "",
        resource: Annotated[str, Form()] = "",
        username: Annotated[str, Form()] = "",
        password: Annotated[str, Form()] = "",
        scope: Annotated[str, Form()] = "",
        state: Annotated[str, Form()] = "",
    ) -> Response:
        # Every field defaults to "" so a missing value gets the same 400 page as a wrong one (never a redirect).
        client, problem = validate_request(
            client_id, redirect_uri, response_type, code_challenge, code_challenge_method, resource
        )
        if problem or client is None:
            return _page(f"<h1>Invalid request</h1><p>{html.escape(problem or '')}</p>", 400)
        user = directory.user(username)
        if user is None or not verify_password(password, user.password_hash):
            log.info("failed sign-in for client %s", client_id)
            return _page("<h1>Sign-in failed</h1><p>Invalid username or password.</p>", 401)
        scopes = granted_scopes(user, client, scope.split())
        if not scopes:
            params = {"error": "invalid_scope", "state": state, "iss": issuer.issuer}
            return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=302)
        code = secrets.token_urlsafe(32)
        codes[code] = PendingCode(
            client.client_id, redirect_uri, code_challenge, user, scopes, resource, time.time() + CODE_TTL_SECONDS
        )
        params = {"code": code, "state": state, "iss": issuer.issuer}
        return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=302)

    @app.post("/token")
    async def token(
        grant_type: Annotated[str, Form()] = "",
        code: Annotated[str, Form()] = "",
        redirect_uri: Annotated[str, Form()] = "",
        client_id: Annotated[str, Form()] = "",
        code_verifier: Annotated[str, Form()] = "",
        resource: Annotated[str, Form()] = "",
    ) -> Response:
        if grant_type != "authorization_code":
            return _oauth_error("unsupported_grant_type", "only authorization_code is supported")
        pending = codes.pop(code, None)  # single use, even when the rest of the request is wrong
        if pending is None or pending.expires_at < time.time():
            return _oauth_error("invalid_grant", "authorization code is invalid or expired")
        if pending.client_id != client_id or pending.redirect_uri != redirect_uri:
            return _oauth_error("invalid_grant", "client_id or redirect_uri does not match the authorization request")
        if not code_verifier or pkce_challenge(code_verifier) != pending.code_challenge:
            return _oauth_error("invalid_grant", "PKCE verification failed")
        if resource and resource != pending.resource:
            return _oauth_error("invalid_target", "resource does not match the authorization request")
        access_token = issuer.issue(
            subject=pending.user.subject,
            tenant_id=pending.user.tenant_id,
            roles=pending.user.roles,
            scopes=pending.scopes,
            client_id=pending.client_id,
            audience=pending.resource,
        )
        return JSONResponse(
            {
                "access_token": access_token,
                "token_type": "Bearer",
                "expires_in": issuer.ttl,
                "scope": " ".join(pending.scopes),
            },
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    return app
