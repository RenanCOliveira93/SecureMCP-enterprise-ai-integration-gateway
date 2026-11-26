"""Declarative, deny-by-default policy engine (ADR-0004).

The YAML file is parsed into strict Pydantic models: unknown keys, unknown permissions, unknown roles or unknown
condition operators make loading fail, so a typo can never silently widen access.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from securemcp.security.identity import Principal

Risk = Literal["low", "medium", "high"]
OperationKind = Literal["tool", "resource", "prompt", "http"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Condition(_Strict):
    id: str = Field(pattern=r"^[a-z0-9_]+$")
    field: str = Field(pattern=r"^[a-z_]+$")
    op: Literal["eq", "in", "gt", "gte", "count_gt"]
    value: Any
    reason: str

    def matches(self, args: dict[str, Any]) -> bool:
        actual = args.get(self.field)
        if actual is None:
            return False
        match self.op:
            case "eq":
                return bool(actual == self.value)
            case "in":
                return actual in self.value
            case "gt":
                return bool(actual > self.value)
            case "gte":
                return bool(actual >= self.value)
            case "count_gt":
                return len(actual) > self.value
        return False  # pragma: no cover - Literal exhausts the cases


class OperationPolicy(_Strict):
    kind: OperationKind
    permission: str
    risk: Risk
    class_: Literal["read", "write"] = Field(alias="class")
    idempotent: bool = False
    approval_when: list[Condition] = Field(default_factory=list)


class Bucket(_Strict):
    capacity: int = Field(gt=0)
    refill_per_second: float = Field(gt=0)


class RateLimits(_Strict):
    read: Bucket
    write: Bucket
    tenant: Bucket


class Timeouts(_Strict):
    read_seconds: float = Field(gt=0)
    write_seconds: float = Field(gt=0)


class ApprovalSettings(_Strict):
    ttl_seconds: int = Field(gt=0)
    four_eyes: bool
    decide_permission: str


class PolicyDocument(_Strict):
    version: str
    permissions: list[str]
    roles: dict[str, list[str]]
    rate_limits: RateLimits
    timeouts: Timeouts
    approvals: ApprovalSettings
    operations: dict[str, OperationPolicy]

    @model_validator(mode="after")
    def _references_are_known(self) -> PolicyDocument:
        known = set(self.permissions)
        for role, perms in self.roles.items():
            unknown = set(perms) - known
            if unknown:
                raise ValueError(f"role {role!r} references unknown permissions {sorted(unknown)}")
        for name, op in self.operations.items():
            if op.permission not in known:
                raise ValueError(f"operation {name!r} requires unknown permission {op.permission!r}")
            if op.class_ == "write" and op.kind == "tool" and not op.idempotent:
                raise ValueError(f"write tool {name!r} must be idempotent")
        if self.approvals.decide_permission not in known:
            raise ValueError("approvals.decide_permission is not a known permission")
        return self


class Effect(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    APPROVAL_REQUIRED = "approval_required"


@dataclass(frozen=True)
class Decision:
    effect: Effect
    policy_id: str
    reason: str
    risk: Risk | None


class PolicyEngine:
    def __init__(self, document: PolicyDocument) -> None:
        self.doc = document

    @classmethod
    def from_file(cls, path: Path) -> PolicyEngine:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        return cls(PolicyDocument.model_validate(raw))

    @property
    def version(self) -> str:
        return self.doc.version

    def operation(self, name: str) -> OperationPolicy | None:
        return self.doc.operations.get(name)

    def role_permissions(self, roles: frozenset[str] | set[str]) -> frozenset[str]:
        perms: set[str] = set()
        for role in roles:
            perms.update(self.doc.roles.get(role, []))  # unknown roles grant nothing
        return frozenset(perms)

    def effective_permissions(self, principal: Principal) -> frozenset[str]:
        """Role permissions ∩ delegated scopes."""
        return self.role_permissions(principal.roles) & principal.scopes

    def can(self, principal: Principal, operation: str) -> bool:
        op = self.operation(operation)
        return op is not None and op.permission in self.effective_permissions(principal)

    def evaluate(self, principal: Principal, operation: str, args: dict[str, Any]) -> Decision:
        op = self.operation(operation)
        if op is None:
            return Decision(Effect.DENY, "allowlist", f"operation {operation!r} is not allowed", None)
        if op.permission not in self.effective_permissions(principal):
            return Decision(Effect.DENY, f"rbac.{operation}", f"requires permission {op.permission}", op.risk)
        for condition in op.approval_when:
            if condition.matches(args):
                return Decision(
                    Effect.APPROVAL_REQUIRED, f"approval.{operation}.{condition.id}", condition.reason, op.risk
                )
        return Decision(Effect.ALLOW, f"rbac.{operation}", "permitted", op.risk)

    def timeout_for(self, operation: str) -> float:
        op = self.operation(operation)
        if op is not None and op.class_ == "write":
            return self.doc.timeouts.write_seconds
        return self.doc.timeouts.read_seconds
