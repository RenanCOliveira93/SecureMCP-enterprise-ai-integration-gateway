"""Closed set of error codes returned to callers (see docs/tool-catalog.md#error-codes)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any


class ErrorCode(StrEnum):
    UNAUTHENTICATED = "UNAUTHENTICATED"
    INVALID_ARGUMENT = "INVALID_ARGUMENT"
    UNKNOWN_OPERATION = "UNKNOWN_OPERATION"
    FORBIDDEN = "FORBIDDEN"
    NOT_FOUND = "NOT_FOUND"
    CONFLICT = "CONFLICT"
    APPROVAL_INVALID = "APPROVAL_INVALID"
    IDEMPOTENCY_CONFLICT = "IDEMPOTENCY_CONFLICT"
    IDEMPOTENCY_IN_PROGRESS = "IDEMPOTENCY_IN_PROGRESS"
    RATE_LIMITED = "RATE_LIMITED"
    TIMEOUT = "TIMEOUT"
    UPSTREAM_UNAVAILABLE = "UPSTREAM_UNAVAILABLE"
    UPSTREAM_REJECTED = "UPSTREAM_REJECTED"
    INTERNAL = "INTERNAL"


RETRYABLE: frozenset[ErrorCode] = frozenset(
    {
        ErrorCode.IDEMPOTENCY_IN_PROGRESS,
        ErrorCode.RATE_LIMITED,
        ErrorCode.TIMEOUT,
        ErrorCode.UPSTREAM_UNAVAILABLE,
    }
)


class GatewayError(Exception):
    """An expected, caller-visible failure. The message must never contain secrets, PII or internals."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        *,
        fields: list[str] | None = None,
        retry_after_seconds: float | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.fields = fields or []
        self.retry_after_seconds = retry_after_seconds
        self.request_id: str | None = None  # set by the gateway pipeline

    @property
    def retryable(self) -> bool:
        return self.code in RETRYABLE

    def to_dict(self, request_id: str) -> dict[str, Any]:
        body: dict[str, Any] = {
            "code": self.code.value,
            "message": self.message,
            "retryable": self.retryable,
            "request_id": request_id,
        }
        if self.fields:
            body["fields"] = self.fields
        if self.retry_after_seconds is not None:
            body["retry_after_seconds"] = round(self.retry_after_seconds, 2)
        return {"error": body}


def not_found(kind: str) -> GatewayError:
    # Same message whether the object does not exist or belongs to another tenant: no existence oracle.
    return GatewayError(ErrorCode.NOT_FOUND, f"{kind} not found")


def internal_error() -> GatewayError:
    return GatewayError(ErrorCode.INTERNAL, "internal error; quote the request_id to support")
