"""The protocol-independent security pipeline every operation goes through (ADR-0002).

identity → allowlist → rate limit → input validation → policy (RBAC ∩ scopes, approval rules)
→ idempotency → approval check → deadline → service → output validation + injection scan → audit
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from opentelemetry import trace
from pydantic import BaseModel, ValidationError

from securemcp.errors import ErrorCode, GatewayError, internal_error
from securemcp.gateway.approvals import ApprovalStore
from securemcp.gateway.audit import AuditRecord, AuditTrail
from securemcp.gateway.idempotency import ClaimOutcome, IdempotencyStore
from securemcp.schemas import UntrustedContent, WriteInput, WriteResult
from securemcp.security import injection
from securemcp.security.identity import Principal
from securemcp.security.policy import Effect, PolicyEngine
from securemcp.security.rate_limit import RateLimiter
from securemcp.security.sanitize import fingerprint
from securemcp.telemetry import current_trace_id, request_id_var

log = logging.getLogger(__name__)
tracer = trace.get_tracer("securemcp.gateway")

Handler = Callable[[Principal, Any], Awaitable[BaseModel]]
IdentityResolver = Callable[[], Awaitable[Principal | None]]

_DENIED = {
    ErrorCode.UNAUTHENTICATED,
    ErrorCode.FORBIDDEN,
    ErrorCode.UNKNOWN_OPERATION,
    ErrorCode.RATE_LIMITED,
    ErrorCode.APPROVAL_INVALID,
}
_FAILED = {ErrorCode.TIMEOUT, ErrorCode.UPSTREAM_UNAVAILABLE, ErrorCode.UPSTREAM_REJECTED, ErrorCode.INTERNAL}
_EXCLUDED_FROM_HASH = {"idempotency_key", "approval_id"}


@dataclass(frozen=True)
class OperationSpec:
    name: str
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    handler: Handler


def new_request_id() -> str:
    return f"req_{uuid.uuid4().hex[:16]}"


def _status_for(code: ErrorCode) -> str:
    if code in _DENIED:
        return "denied"
    if code in _FAILED:
        return "failed"
    return "rejected"


def _collect(data: Any, path: list[str]) -> list[str]:
    """Collect string values at a path like ``tickets[].description`` or ``ticket.subject``."""
    if not path:
        return [data] if isinstance(data, str) else []
    head, rest = path[0], path[1:]
    if head.endswith("[]"):
        items = data.get(head[:-2], []) if isinstance(data, dict) else []
        return [text for item in items for text in _collect(item, rest)]
    return _collect(data.get(head) if isinstance(data, dict) else None, rest)


class Gateway:
    def __init__(
        self,
        *,
        policy: PolicyEngine,
        rate_limiter: RateLimiter,
        idempotency: IdempotencyStore,
        approvals: ApprovalStore,
        audit: AuditTrail,
        identity: IdentityResolver,
    ) -> None:
        self.policy = policy
        self.rate_limiter = rate_limiter
        self.idempotency = idempotency
        self.approvals = approvals
        self.audit = audit
        self.identity = identity
        self.operations: dict[str, OperationSpec] = {}

    def register(
        self, name: str, input_model: type[BaseModel], output_model: type[BaseModel], handler: Handler
    ) -> None:
        op = self.policy.operation(name)
        if op is None:
            raise ValueError(f"operation {name!r} has no policy entry; refusing to register it")
        is_write_tool = op.class_ == "write" and op.kind == "tool"
        if is_write_tool and not (issubclass(input_model, WriteInput) and issubclass(output_model, WriteResult)):
            raise ValueError(f"write operation {name!r} must use WriteInput/WriteResult models")
        self.operations[name] = OperationSpec(name, input_model, output_model, handler)

    async def principal(self) -> Principal | None:
        return await self.identity()

    async def invoke(
        self,
        name: str,
        args: dict[str, Any],
        *,
        request_id: str | None = None,
        rejection: GatewayError | None = None,
    ) -> BaseModel:
        """Run ``name`` for the current caller. ``rejection`` lets the protocol layer report a call it already
        refused (e.g. SDK schema validation) so it is still authenticated, rate limited and audited."""
        request_id = request_id or new_request_id()
        token = request_id_var.set(request_id)
        started = time.monotonic()
        op_policy = self.policy.operation(name)
        record = AuditRecord(request_id=request_id, operation=name, kind=op_policy.kind if op_policy else "unknown")
        record.policy_version = self.policy.version
        with tracer.start_as_current_span("securemcp.operation") as span:
            span.set_attribute("securemcp.operation", name)
            span.set_attribute("securemcp.request_id", request_id)
            record.trace_id = current_trace_id()
            try:
                result = await self._run(name, args, record, rejection)
                return result
            except GatewayError as exc:
                record.status = _status_for(exc.code)
                record.error_code = exc.code.value
                exc.request_id = request_id
                raise
            except Exception as exc:
                log.exception("unexpected failure in %s", name)
                record.status = "failed"
                record.error_code = ErrorCode.INTERNAL.value
                err = internal_error()
                err.request_id = request_id
                raise err from exc
            finally:
                record.duration_ms = int((time.monotonic() - started) * 1000)
                span.set_attribute("securemcp.duration_ms", record.duration_ms)
                for key in ("tenant_id", "subject", "client_id", "status", "error_code", "policy_id", "risk"):
                    value = getattr(record, key)
                    if value is not None:
                        span.set_attribute(f"securemcp.{key}", value)
                if record.injection_signals:
                    span.set_attribute("securemcp.injection_signals", record.injection_signals)
                if record.error_code:
                    span.set_status(trace.Status(trace.StatusCode.ERROR, record.error_code))
                await self.audit.safe_append(record)
                log.info(
                    "op=%s status=%s code=%s policy=%s tenant=%s subject=%s client=%s %dms",
                    name,
                    record.status,
                    record.error_code,
                    record.policy_id,
                    record.tenant_id,
                    record.subject,
                    record.client_id,
                    record.duration_ms,
                )
                request_id_var.reset(token)

    async def _run(
        self, name: str, args: dict[str, Any], record: AuditRecord, rejection: GatewayError | None
    ) -> BaseModel:
        # 1. identity -------------------------------------------------------------------------------
        principal = await self.identity()
        if principal is None:
            raise GatewayError(ErrorCode.UNAUTHENTICATED, "authentication required")
        record.tenant_id = principal.tenant_id
        record.subject = principal.subject
        record.client_id = principal.client_id

        # 2. allowlist -------------------------------------------------------------------------------
        spec = self.operations.get(name)
        op_policy = self.policy.operation(name)
        if spec is None or op_policy is None:
            record.policy_id = "allowlist"
            raise GatewayError(ErrorCode.UNKNOWN_OPERATION, f"unknown operation {name!r}")
        record.risk = op_policy.risk

        # 3. rate limit (before any expensive work, and also for callers who will be denied) -------
        limit = self.rate_limiter.check(principal, op_policy.class_)
        if not limit.allowed:
            record.policy_id = f"rate_limit.{limit.bucket}"
            raise GatewayError(
                ErrorCode.RATE_LIMITED, "rate limit exceeded", retry_after_seconds=limit.retry_after_seconds
            )

        if rejection is not None:
            raise rejection

        # 4. input validation --------------------------------------------------------------------------
        try:
            data = spec.input_model.model_validate(args)
        except ValidationError as exc:
            fields = sorted({".".join(str(p) for p in err["loc"]) or "(root)" for err in exc.errors()})
            raise GatewayError(ErrorCode.INVALID_ARGUMENT, "arguments do not match the schema", fields=fields) from None
        canonical = data.model_dump(mode="json", exclude=_EXCLUDED_FROM_HASH)
        args_hash = fingerprint({"operation": name, "args": canonical})
        record.args_fingerprint = args_hash

        # 5. policy --------------------------------------------------------------------------------------
        decision = self.policy.evaluate(principal, name, data.model_dump(mode="python"))
        record.policy_id = decision.policy_id
        if decision.effect is Effect.DENY:
            raise GatewayError(ErrorCode.FORBIDDEN, f"not allowed: {decision.reason}")

        timeout = self.policy.timeout_for(name)
        if not isinstance(data, WriteInput):
            output = await self._execute(spec, principal, data, timeout)
            record.status = "ok"
            return self._finish(output, record)

        # 6. writes: idempotency + approvals ------------------------------------------------------------
        record.idempotency_key = data.idempotency_key
        record.approval_id = data.approval_id
        claim = await self.idempotency.claim(principal, name, data.idempotency_key, args_hash)
        output_model = spec.output_model
        if claim.outcome is ClaimOutcome.REPLAY:
            record.status = "replayed"
            return output_model.model_validate({**(claim.response or {}), "replayed": True})
        if claim.outcome is ClaimOutcome.APPROVAL_PENDING:
            if data.approval_id is None:
                record.status = "replayed"
                record.approval_id = claim.approval_id
                return output_model.model_validate({**(claim.response or {}), "replayed": True})
            await self.idempotency.resume(principal, claim.record_id)

        try:
            if decision.effect is Effect.APPROVAL_REQUIRED:
                if data.approval_id is None:
                    summary = {"operation": name, "args": canonical}
                    approval = await self.approvals.create(principal, name, args_hash, summary, decision)
                    pending = output_model(status="approval_required", approval=approval)
                    await self.idempotency.await_approval(
                        principal, claim.record_id, pending.model_dump(mode="json"), approval.approval_id
                    )
                    record.status = "approval_required"
                    record.approval_id = approval.approval_id
                    return pending
                await self.approvals.consume(principal, name, args_hash, data.approval_id)
            output = await self._execute(spec, principal, data, timeout)
        except Exception:
            if claim.outcome is ClaimOutcome.APPROVAL_PENDING and claim.approval_id and claim.response:
                # A bad or not-yet-approved approval_id must not lose the pending approval tied to this key.
                await self.idempotency.await_approval(principal, claim.record_id, claim.response, claim.approval_id)
            else:
                await self.idempotency.release(principal, claim.record_id)
            raise
        await self.idempotency.complete(principal, claim.record_id, output.model_dump(mode="json"))
        record.status = "ok"
        return self._finish(output, record)

    async def _execute(self, spec: OperationSpec, principal: Principal, data: BaseModel, timeout: float) -> BaseModel:
        try:
            async with asyncio.timeout(timeout):
                return await spec.handler(principal, data)
        except TimeoutError:
            raise GatewayError(ErrorCode.TIMEOUT, f"operation exceeded its {timeout:g}s deadline") from None

    def _finish(self, output: BaseModel, record: AuditRecord) -> BaseModel:
        output = type(output).model_validate(output.model_dump())  # output contract check
        if isinstance(output, UntrustedContent) and output.untrusted_fields:
            dumped = output.model_dump(mode="json")
            signals: set[str] = set()
            for path in output.untrusted_fields:
                for text in _collect(dumped, path.split(".")):
                    signals.update(injection.scan(text))
            if signals:
                output = output.model_copy(update={"injection_suspected": True, "injection_signals": sorted(signals)})
                record.injection_signals = sorted(signals)
        return output
