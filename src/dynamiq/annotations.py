from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class Annotation:
    annotation_id: str
    address: str
    note: str
    tags: list[str] = field(default_factory=list)
    created_at: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "annotation_id": self.annotation_id,
            "address": self.address,
            "note": self.note,
            "tags": list(self.tags),
            "created_at": self.created_at,
        }
