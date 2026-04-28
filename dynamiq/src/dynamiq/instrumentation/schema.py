from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..events import Event, EventType, normalize_address


@dataclass(frozen=True, slots=True)
class AddressRange:
    start: str
    end: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "start", normalize_address(self.start))
        object.__setattr__(self, "end", normalize_address(self.end))
        if int(self.start, 16) > int(self.end, 16):
            raise ValueError("address range start must be <= end")

    def contains(self, address: str | None) -> bool:
        if address is None:
            return False
        value = int(normalize_address(address), 16)
        return int(self.start, 16) <= value <= int(self.end, 16)


def event_matches_filters(
    event: Event,
    event_types: set[EventType] | None = None,
    address_ranges: list[AddressRange] | None = None,
    thread_ids: set[str] | None = None,
) -> bool:
    if event_types and event.type not in event_types:
        return False
    if thread_ids and event.thread_id not in thread_ids:
        return False
    if address_ranges and not any(rng.contains(event.pc) for rng in address_ranges):
        return False
    return True


def trace_entry_from_event(index: int, event: Event | dict[str, Any]) -> dict[str, Any]:
    if isinstance(event, Event):
        payload = event.to_dict()
    else:
        payload = dict(event)
    return {
        "index": index,
        "event_id": payload["event_id"],
        "type": payload["type"],
        "pc": payload.get("pc"),
        "thread_id": payload.get("thread_id"),
    }
