from __future__ import annotations

import json
import socket
import threading
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from ..errors import EventValidationError
from ..events import Event, EventType, normalize_address
from .schema import AddressRange, event_matches_filters


@dataclass(slots=True)
class InstrumentationStats:
    events_received: int = 0
    events_dropped: int = 0
    malformed_events: int = 0
    sequence_gaps: int = 0

    def to_dict(self) -> dict[str, int]:
        return {
            "events_received": self.events_received,
            "events_dropped": self.events_dropped,
            "malformed_events": self.malformed_events,
            "sequence_gaps": self.sequence_gaps,
        }


class InstrumentationClient:
    def __init__(
        self,
        socket_path: str,
        max_events: int = 1024,
        max_line_bytes: int = 65536,
        timeout: float = 0.1,
        connector: Callable[[str, float], Any] | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.max_events = max_events
        self.max_line_bytes = max_line_bytes
        self.timeout = timeout
        self.connector = connector
        self.stats = InstrumentationStats()
        self._socket: socket.socket | None = None
        self._reader = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._cv = threading.Condition()
        self._events: deque[Event] = deque(maxlen=max_events)
        self._last_seq: int | None = None
        self._filters: set[EventType] = set()
        self._address_ranges: list[AddressRange] = []

    def connect(self) -> None:
        if self._socket is not None:
            return
        if self.connector is not None:
            sock = self.connector(self.socket_path, self.timeout)
        else:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect(self.socket_path)
        self._socket = sock
        self._reader = sock.makefile("r", encoding="utf-8")
        self._stop.clear()
        self._thread = threading.Thread(target=self._read_loop, name="instrumentation-client", daemon=True)
        self._thread.start()

    def configure_filters(
        self,
        event_types: list[str] | None = None,
        address_ranges: list[tuple[str, str]] | None = None,
    ) -> dict[str, Any]:
        if event_types is None:
            self._filters = set()
        else:
            self._filters = {EventType(item) for item in event_types}
        if address_ranges is None:
            self._address_ranges = []
        else:
            self._address_ranges = [AddressRange(start, end) for start, end in address_ranges]
        return {
            "event_types": sorted(item.value for item in self._filters),
            "address_ranges": [(item.start, item.end) for item in self._address_ranges],
        }

    def get_recent_events(
        self,
        limit: int = 100,
        event_types: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        requested_types = {EventType(item) for item in event_types} if event_types else None
        with self._cv:
            events = list(self._events)
        if requested_types is not None:
            events = [event for event in events if event.type in requested_types]
        return [event.to_dict() for event in events[-limit:]]

    def latest_seq(self) -> int | None:
        with self._cv:
            return self._last_seq

    def wait_for_event(
        self,
        event_types: list[str],
        timeout: float,
        min_seq_exclusive: int | None = None,
    ) -> dict[str, Any]:
        requested_types = {EventType(item) for item in event_types}

        def predicate() -> bool:
            return any(
                event.type in requested_types and (min_seq_exclusive is None or event.seq > min_seq_exclusive)
                for event in self._events
            )

        with self._cv:
            matched = self._cv.wait_for(predicate, timeout)
            if not matched:
                raise TimeoutError(f"timed out waiting for event types: {sorted(item.value for item in requested_types)}")
            for event in reversed(self._events):
                if event.type in requested_types and (min_seq_exclusive is None or event.seq > min_seq_exclusive):
                    return event.to_dict()
        raise TimeoutError("timed out waiting for instrumentation event")

    def wait_for_address(
        self,
        address: str,
        timeout: float,
        min_seq_exclusive: int | None = None,
    ) -> dict[str, Any]:
        normalized = normalize_address(address)

        def predicate() -> bool:
            return any(
                event.pc == normalized and (min_seq_exclusive is None or event.seq > min_seq_exclusive)
                for event in self._events
            )

        with self._cv:
            matched = self._cv.wait_for(predicate, timeout)
            if not matched:
                raise TimeoutError(f"timed out waiting for address: {normalized}")
            for event in reversed(self._events):
                if event.pc == normalized and (min_seq_exclusive is None or event.seq > min_seq_exclusive):
                    return event.to_dict()
        raise TimeoutError(f"timed out waiting for address: {normalized}")

    def close(self) -> None:
        self._stop.set()
        if self._reader is not None:
            self._reader.close()
            self._reader = None
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        if self._thread is not None:
            self._thread.join(timeout=1.0)
            self._thread = None

    def _read_loop(self) -> None:
        assert self._reader is not None
        while not self._stop.is_set():
            try:
                line = self._reader.readline()
            except OSError:
                break
            if not line:
                break
            if len(line.encode("utf-8")) > self.max_line_bytes:
                self.stats.events_dropped += 1
                continue
            try:
                event = Event.from_dict(json.loads(line))
            except (json.JSONDecodeError, EventValidationError, TypeError, ValueError):
                self.stats.malformed_events += 1
                continue
            if not event_matches_filters(
                event,
                event_types=self._filters or None,
                address_ranges=self._address_ranges or None,
            ):
                self.stats.events_dropped += 1
                continue
            self._append_event(event)

    def _append_event(self, event: Event) -> None:
        with self._cv:
            if self._last_seq is not None and event.seq != self._last_seq + 1:
                self.stats.sequence_gaps += 1
            self._last_seq = event.seq
            self._events.append(event)
            self.stats.events_received += 1
            self._cv.notify_all()
