"""What the *user* asked for, extracted from the user's own words only.

The guard uses ``requested_writes`` to bind side effects to user intent: text that arrives later through tool results
(a ticket description, a manual) can never add a write to this set, which is what defeats indirect prompt injection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

WRITE_TOOLS = ("create_support_ticket", "schedule_maintenance", "send_notification")

_WRITE_PATTERNS = {
    "create_support_ticket": re.compile(r"\b(open|create|file|raise|log)\b[^.?!]*\bticket\b", re.I),
    "schedule_maintenance": re.compile(r"\b(schedule|book|plan)\b[^.?!]*\bmaintenance\b", re.I),
    "send_notification": re.compile(r"\b(notify|notification|inform|alert)\b", re.I),
}
_NEGATION = re.compile(r"\b(do not|don't|never|without)\b[^.?!]*\b(ticket|maintenance|notify|notification)\b", re.I)


def requested_writes(request: str) -> set[str]:
    if _NEGATION.search(request):
        stripped = _NEGATION.sub(" ", request)
        return {tool for tool, pattern in _WRITE_PATTERNS.items() if pattern.search(stripped)}
    return {tool for tool, pattern in _WRITE_PATTERNS.items() if pattern.search(request)}


@dataclass
class Entities:
    clients: list[str] = field(default_factory=list)
    cameras: list[str] = field(default_factory=list)
    tickets: list[str] = field(default_factory=list)
    maintenance: list[str] = field(default_factory=list)


def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def entities(text: str) -> Entities:
    return Entities(
        clients=_unique(re.findall(r"\bcli_[a-z0-9]{6}\b", text)),
        cameras=_unique(re.findall(r"\bcam_[a-z0-9]{6,10}\b", text)),
        tickets=_unique(re.findall(r"\btkt_[a-z0-9]{6,12}\b", text)),
        maintenance=_unique(re.findall(r"\bmnt_[a-z0-9]{6,12}\b", text)),
    )
