"""Shared test helpers: synthetic principals that mirror config/auth-users.yaml."""

from __future__ import annotations

import json
from contextvars import ContextVar
from pathlib import Path
from typing import Any

import yaml

from securemcp.security.identity import Principal

ROOT = Path(__file__).resolve().parents[1]
POLICY = yaml.safe_load((ROOT / "config/policy.yaml").read_text())

USERS = {
    "ana": ("usr_aur_ana", "tnt_aurora", ["viewer"]),
    "bruno": ("usr_aur_bruno", "tnt_aurora", ["support_agent"]),
    "carla": ("usr_aur_carla", "tnt_aurora", ["operations_manager"]),
    "diego": ("usr_aur_diego", "tnt_aurora", ["tenant_admin"]),
    "eva": ("usr_bor_eva", "tnt_boreal", ["support_agent"]),
    "fabio": ("usr_bor_fabio", "tnt_boreal", ["operations_manager"]),
}

current_principal: ContextVar[Principal | None] = ContextVar("test_principal", default=None)


def principal(user: str, *, client: str = "securemcp-host", scopes: set[str] | None = None) -> Principal:
    subject, tenant, roles = USERS[user]
    granted = {perm for role in roles for perm in POLICY["roles"][role]}
    if client == "securemcp-host":
        granted.discard("approvals:decide")
    elif client == "securemcp-approvals":
        granted &= {"approvals:decide"}
    return Principal(
        subject=subject,
        tenant_id=tenant,
        roles=frozenset(roles),
        scopes=frozenset(scopes if scopes is not None else granted),
        client_id=client,
    )


class As:
    """``with As("bruno"):`` — run the block as that user (in-process identity resolver)."""

    def __init__(self, user: str | Principal, **kwargs: Any) -> None:
        self.p = user if isinstance(user, Principal) else principal(user, **kwargs)

    def __enter__(self) -> Principal:
        self._token = current_principal.set(self.p)
        return self.p

    def __exit__(self, *exc: object) -> None:
        current_principal.reset(self._token)


async def resolve_test_identity() -> Principal | None:
    return current_principal.get()


def error_of(result: Any) -> dict[str, Any]:
    assert result.is_error, f"expected an error result, got {result}"
    return json.loads(result.content[0].text)["error"]
