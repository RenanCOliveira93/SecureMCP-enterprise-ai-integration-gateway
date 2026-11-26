"""Redaction for logs/telemetry and masking for data returned to agents (PII minimisation)."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-._~+/]+=*"), "Bearer [REDACTED]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"), "[REDACTED_JWT]"),
    (re.compile(r"(?i)\b(api[_-]?key|secret|password|token)(\s*[=:]\s*)([^\s,;\"']+)"), r"\1\2[REDACTED]"),
    (re.compile(r"\bdev-insecure-[a-z-]+\b"), "[REDACTED]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[EMAIL]"),
    (re.compile(r"\+?\d{2}[\s-]?\d{2}[\s-]?\d{4,5}[\s-]?\d{4}\b"), "[PHONE]"),
]


def redact(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class RedactingFilter(logging.Filter):
    """Applied to every handler: rewrites the formatted message and drops raw args."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        record.msg = redact(message)
        record.args = None
        return True


def mask_email(email: str) -> str:
    local, _, domain = email.partition("@")
    if not domain:
        return "***"
    return f"{local[:1]}***@{domain}"


def mask_phone(phone: str) -> str:
    digits = re.sub(r"\D", "", phone)
    return f"***-{digits[-2:]}" if len(digits) >= 2 else "***"


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def fingerprint(data: Any) -> str:
    """SHA-256 of canonical JSON: correlates requests without storing their content."""
    return hashlib.sha256(canonical_json(data).encode()).hexdigest()
