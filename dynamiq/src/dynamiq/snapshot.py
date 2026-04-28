from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Snapshot:
    snapshot_id: str
    name: str | None
    created_at: float
    pc: str | None
    thread_id: str | None
    event_id: str | None
    metadata: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "name": self.name,
            "created_at": self.created_at,
            "pc": self.pc,
            "thread_id": self.thread_id,
            "event_id": self.event_id,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class SnapshotDiff:
    left_id: str
    right_id: str
    changed_fields: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "left_id": self.left_id,
            "right_id": self.right_id,
            "changed_fields": dict(self.changed_fields),
        }
