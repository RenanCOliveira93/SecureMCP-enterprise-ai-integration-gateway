"""Open an authenticated MCP client session over Streamable HTTP."""

from __future__ import annotations

import httpx2  # the HTTP client the MCP SDK transport is built on
from mcp import Client
from mcp.client.streamable_http import streamable_http_client


def mcp_client(url: str, access_token: str, *, timeout_seconds: float = 30.0) -> Client:
    """``async with mcp_client(url, token) as client:`` — the bearer token goes on every request (never in URLs)."""
    http = httpx2.AsyncClient(headers={"Authorization": f"Bearer {access_token}"}, timeout=timeout_seconds)
    return Client(streamable_http_client(url, http_client=http), client_info=None)
