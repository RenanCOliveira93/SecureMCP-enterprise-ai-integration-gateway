"""Plain HTTP routes on the same ASGI app: health probes and the out-of-band approval API (ADR-0007)."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from securemcp.errors import ErrorCode, GatewayError

if TYPE_CHECKING:
    from securemcp.mcp_server.server import SecureMCPServer

HTTP_STATUS = {
    ErrorCode.UNAUTHENTICATED: 401,
    ErrorCode.FORBIDDEN: 403,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.INVALID_ARGUMENT: 400,
    ErrorCode.UNKNOWN_OPERATION: 404,
    ErrorCode.CONFLICT: 409,
    ErrorCode.RATE_LIMITED: 429,
    ErrorCode.TIMEOUT: 504,
    ErrorCode.UPSTREAM_UNAVAILABLE: 503,
    ErrorCode.UPSTREAM_REJECTED: 502,
}


def _error(err: GatewayError, server: SecureMCPServer) -> JSONResponse:
    status = HTTP_STATUS.get(err.code, 500)
    headers = {}
    if status == 401:
        metadata = server.container.settings.public_url.replace("/mcp", "/.well-known/oauth-protected-resource/mcp")
        headers["WWW-Authenticate"] = f'Bearer error="invalid_token", resource_metadata="{metadata}"'
    if err.retry_after_seconds:
        headers["Retry-After"] = str(max(1, round(err.retry_after_seconds)))
    return JSONResponse(err.to_dict(err.request_id or "-"), status_code=status, headers=headers)


def register(server: SecureMCPServer) -> None:
    gw = server.gateway

    @server.custom_route("/healthz", methods=["GET"])
    async def healthz(_: Request) -> Response:
        return JSONResponse({"status": "ok"})

    @server.custom_route("/readyz", methods=["GET"])
    async def readyz(_: Request) -> Response:
        ok = await server.container.db.ping()
        return JSONResponse({"status": "ready" if ok else "unavailable"}, status_code=200 if ok else 503)

    @server.custom_route("/approvals", methods=["GET"])
    async def list_approvals(_: Request) -> Response:
        try:
            result = await gw.invoke("list_approvals", {})
        except GatewayError as err:
            return _error(err, server)
        return JSONResponse(result.model_dump(mode="json"))

    @server.custom_route("/approvals/{approval_id}/decision", methods=["POST"])
    async def decide(request: Request) -> Response:
        try:
            body: Any = json.loads(await request.body() or b"{}")
        except json.JSONDecodeError:
            body = None
        if not isinstance(body, dict):
            body = {"__invalid_body__": True}  # forces INVALID_ARGUMENT through the audited path
        args = {**body, "approval_id": request.path_params["approval_id"]}
        try:
            result = await gw.invoke("decide_approval", args)
        except GatewayError as err:
            return _error(err, server)
        return JSONResponse(result.model_dump(mode="json"))
