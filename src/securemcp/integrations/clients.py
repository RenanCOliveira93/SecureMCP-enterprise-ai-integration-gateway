"""CRM and notification API clients.

Confused-deputy rule: these clients authenticate with the *server's own* credential from the secret provider and
never receive or forward the caller's access token. Tenant and subject come from the verified principal.
"""

from __future__ import annotations

import hashlib
from typing import Any

from securemcp.integrations.http import ResilientHttp
from securemcp.security.identity import Principal
from securemcp.security.secrets import SecretProvider


class CrmClient:
    def __init__(self, http: ResilientHttp, secrets: SecretProvider) -> None:
        self.http = http
        self.secrets = secrets

    async def get_account(self, principal: Principal, client_id: str) -> dict[str, Any]:
        response = await self.http.request(
            "GET",
            f"/accounts/{client_id}",
            headers={
                "X-Api-Key": self.secrets.get("crm_api_key").get_secret_value(),
                "X-Tenant-Id": principal.tenant_id,
                "X-On-Behalf-Of": principal.subject,
            },
            retry_safe=True,
        )
        return dict(response.json())


class NotificationClient:
    def __init__(self, http: ResilientHttp, secrets: SecretProvider) -> None:
        self.http = http
        self.secrets = secrets

    @staticmethod
    def downstream_key(principal: Principal, idempotency_key: str) -> str:
        # Namespaced so two tenants using the same client key never collide downstream.
        return hashlib.sha256(f"{principal.tenant_id}:{principal.subject}:{idempotency_key}".encode()).hexdigest()

    async def send(self, principal: Principal, payload: dict[str, Any], idempotency_key: str) -> dict[str, Any]:
        response = await self.http.request(
            "POST",
            "/messages",
            headers={
                "X-Api-Key": self.secrets.get("notifications_api_key").get_secret_value(),
                "X-Tenant-Id": principal.tenant_id,
                "X-On-Behalf-Of": principal.subject,
                "Idempotency-Key": self.downstream_key(principal, idempotency_key),
            },
            json=payload,
            retry_safe=True,  # safe because the Idempotency-Key makes the POST idempotent downstream
        )
        return dict(response.json())
