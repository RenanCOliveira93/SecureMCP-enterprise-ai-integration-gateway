"""Secret access behind one interface (ADR-0015).

Secret names are lower_snake_case: ``auth_signing_key``, ``notifications_api_key``, ``crm_api_key``.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Protocol

from pydantic import SecretStr

from securemcp.config import Settings

log = logging.getLogger(__name__)

KNOWN_SECRETS = ("auth_signing_key", "notifications_api_key", "crm_api_key")


class SecretNotFound(LookupError):
    pass


class SecretProvider(Protocol):
    def get(self, name: str) -> SecretStr: ...


class EnvSecretProvider:
    """Reads ``SECUREMCP_SECRET_<NAME>``. Development convenience; values are visible to the process table."""

    def get(self, name: str) -> SecretStr:
        value = os.environ.get(f"SECUREMCP_SECRET_{name.upper()}")
        if value is None:
            raise SecretNotFound(name)
        return SecretStr(value)


class FileSecretProvider:
    """Reads one file per secret from a directory (Docker / Kubernetes secrets)."""

    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def get(self, name: str) -> SecretStr:
        if not name.replace("_", "").isalnum():
            raise SecretNotFound(name)  # never let a name walk out of the directory
        path = self.directory / name
        if not path.is_file():
            raise SecretNotFound(name)
        return SecretStr(path.read_text(encoding="utf-8").strip())


class DevFallbackSecretProvider:
    """Wraps a provider; outside ``prod`` a missing API key falls back to a fixed, obviously insecure value.

    The value is deterministic so that separate development processes (gateway and mock APIs) agree on it.
    ``auth_signing_key`` never falls back here: the authorization server generates an ephemeral key instead.
    """

    def __init__(self, inner: SecretProvider) -> None:
        self.inner = inner
        self._warned: set[str] = set()

    def get(self, name: str) -> SecretStr:
        try:
            return self.inner.get(name)
        except SecretNotFound:
            if name == "auth_signing_key":
                raise
            if name not in self._warned:
                log.warning("secret %s not configured; using the insecure development value", name)
                self._warned.add(name)
            return SecretStr(f"dev-insecure-{name.replace('_', '-')}")


def build_secret_provider(settings: Settings) -> SecretProvider:
    inner: SecretProvider = (
        FileSecretProvider(settings.secrets_dir) if settings.secrets_backend == "file" else EnvSecretProvider()
    )
    if settings.env == "prod":
        return inner
    return DevFallbackSecretProvider(inner)
