from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class TraceEntry:
    index: int
    event_id: str
    type: str
    pc: str | None
    thread_id: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "event_id": self.event_id,
            "type": self.type,
            "pc": self.pc,
            "thread_id": self.thread_id,
        }
