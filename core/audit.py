from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Mapping


@dataclass(frozen=True)
class AuditEvent:
    timestamp: datetime
    actor: str
    action: str
    details: str | None = None
    metadata: Mapping[str, str] | None = None

    def as_text(self) -> str:
        ts = self.timestamp.isoformat(timespec="seconds") + "Z"
        entry = f"[{ts}] {self.actor} - {self.action}"
        if self.details:
            entry += f" :: {self.details}"
        if self.metadata:
            kv = ", ".join(f"{k}={v}" for k, v in self.metadata.items())
            entry += f" ({kv})"
        return entry


class AuditTrail:
    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def record(
        self,
        actor: str,
        action: str,
        *,
        details: str | None = None,
        metadata: Mapping[str, str] | None = None,
    ) -> None:
        event = AuditEvent(
            timestamp=datetime.utcnow(),
            actor=actor,
            action=action,
            details=details,
            metadata=dict(metadata) if metadata else None,
        )
        self._events.append(event)

    def get_events(self) -> Iterable[AuditEvent]:
        return list(self._events)



