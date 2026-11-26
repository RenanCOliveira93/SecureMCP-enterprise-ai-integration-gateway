"""Host-side OAuth 2.1 client: how an MCP host obtains a token for an MCP server.

1. Call the MCP server without a token → 401 with ``WWW-Authenticate: Bearer resource_metadata="…"``.
2. Read the Protected Resource Metadata (RFC 9728) → which authorization server protects it.
3. Read the authorization server metadata (RFC 8414) → endpoints, PKCE support.
4. Authorization code + PKCE S256 with ``resource=<MCP URL>`` (RFC 8707).
5. Exchange the code for an access token bound to the MCP server.

Step 4 normally happens in the user's browser. This demo host submits the sign-in form itself (the user typed the
password into the terminal), which keeps the protocol identical while staying scriptable.
"""

from __future__ import annotations

import base64
import hashlib
import re
import secrets
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse

import httpx


class OAuthError(RuntimeError):
    pass


@dataclass(frozen=True)
class TokenSet:
    access_token: str
    scope: str
    expires_at: float
    resource: str
    username: str
    client_id: str

    @property
    def expired(self) -> bool:
        return time.time() > self.expires_at - 30


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(64)[:96]
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


async def discover(mcp_url: str, http: httpx.AsyncClient) -> tuple[str, dict]:
    """Return (resource, authorization-server metadata) starting from the MCP URL only."""
    probe = await http.post(
        mcp_url,
        json={"jsonrpc": "2.0", "id": 0, "method": "ping"},
        headers={"Accept": "application/json, text/event-stream"},
    )
    if probe.status_code != 401:
        raise OAuthError(f"expected 401 from an unauthenticated probe, got {probe.status_code}")
    match = re.search(r'resource_metadata="([^"]+)"', probe.headers.get("www-authenticate", ""))
    if not match:
        raise OAuthError("server did not advertise resource_metadata in WWW-Authenticate")
    prm = (await http.get(match.group(1))).raise_for_status().json()
    issuer = prm["authorization_servers"][0].rstrip("/")
    metadata = (await http.get(f"{issuer}/.well-known/oauth-authorization-server")).raise_for_status().json()
    if "S256" not in metadata.get("code_challenge_methods_supported", []):
        raise OAuthError("authorization server does not support PKCE S256")
    return prm["resource"], metadata


async def login(
    *,
    mcp_url: str,
    username: str,
    password: str,
    client_id: str,
    redirect_uri: str,
    scopes: list[str] | None = None,
    http: httpx.AsyncClient | None = None,
) -> TokenSet:
    own = http is None
    http = http or httpx.AsyncClient(timeout=10.0)
    try:
        resource, metadata = await discover(mcp_url, http)
        verifier, challenge = _pkce_pair()
        state = secrets.token_urlsafe(16)
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": resource,
            "scope": " ".join(scopes or []),
            "state": state,
        }
        form = await http.get(metadata["authorization_endpoint"], params=params)
        if form.status_code != 200:
            raise OAuthError(f"authorization request rejected ({form.status_code})")
        submitted = await http.post(
            metadata["authorization_endpoint"],
            data={**params, "username": username, "password": password},
            follow_redirects=False,
        )
        if submitted.status_code != 302:
            status = submitted.status_code
            raise OAuthError("sign-in failed" if status == 401 else f"sign-in error {status}")
        location = urlparse(submitted.headers["location"])
        query = {k: v[0] for k, v in parse_qs(location.query).items()}
        if f"{location.scheme}://{location.netloc}{location.path}" != redirect_uri:
            raise OAuthError("redirect to an unexpected URI")
        if query.get("state") != state:
            raise OAuthError("state mismatch (possible CSRF)")
        if query.get("iss") != metadata["issuer"]:
            raise OAuthError("issuer mismatch in authorization response (RFC 9207)")
        if "error" in query:
            raise OAuthError(f"authorization denied: {query['error']}")
        token = await http.post(
            metadata["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": query["code"],
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": verifier,
                "resource": resource,
            },
        )
        if token.status_code != 200:
            raise OAuthError(f"token exchange failed: {token.json().get('error', token.status_code)}")
        body = token.json()
        return TokenSet(
            body["access_token"], body.get("scope", ""), time.time() + body["expires_in"], resource, username, client_id
        )
    finally:
        if own:
            await http.aclose()
