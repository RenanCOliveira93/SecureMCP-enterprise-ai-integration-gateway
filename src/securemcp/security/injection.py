"""Heuristic detection of instruction-like text inside data (ADR-0012).

This is a *signal* for auditing and for hosts, not a control: the controls are intent binding, closed templates
and approvals. False negatives are expected; the scenario tests prove the controls hold anyway.
"""

from __future__ import annotations

import re

_SIGNALS: list[tuple[str, re.Pattern[str]]] = [
    ("override_instructions", re.compile(r"(?i)\b(ignore|disregard|forget)\b.{0,40}\b(instruction|prompt|rule)s?\b")),
    ("role_hijack", re.compile(r"(?i)\byou are now\b|\bact as\b.{0,30}\b(admin|system|developer)\b")),
    ("system_impersonation", re.compile(r"(?i)\b(system (note|message|prompt)|developer message)\b")),
    (
        "ai_addressed",
        re.compile(
            r"(?i)\b(ai|llm) (assistant|agent|model)s?\b.{0,40}\b(must|should|reading)\b"
            r"|\bnote (for|to) the (ai|assistant|agent)\b|\bai agents? reading\b"
        ),
    ),
    (
        "tool_invocation",
        re.compile(
            r"(?i)\b(call|invoke|run|execute)\b.{0,20}\b(send_notification|"
            r"schedule_maintenance|create_support_ticket|tool)\b"
        ),
    ),
    ("confirmation_bypass", re.compile(r"(?i)\b(do not|don't|without)\b.{0,20}\b(ask|confirm|approval|tell)\b")),
    ("hidden_markup", re.compile(r"(?is)<!--.{0,400}?-->|\[//\]: #")),
]


def scan(text: str) -> list[str]:
    """Return the names of the signals found in ``text`` (empty list when clean)."""
    return [name for name, pattern in _SIGNALS if pattern.search(text)]
