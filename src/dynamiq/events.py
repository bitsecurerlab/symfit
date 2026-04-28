from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .errors import EventValidationError


class EventType(str, Enum):
    BACKEND_READY = "backend_ready"
    BASIC_BLOCK = "basic_block"
    BRANCH = "branch"
    CALL = "call"
    RETURN = "return"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    SYSCALL = "syscall"
    EXCEPTION = "exception"
    BREAKPOINT = "breakpoint"
    EXECUTION_PAUSED = "execution_paused"
    EXECUTION_RESUMED = "execution_resumed"
    SNAPSHOT_TAKEN = "snapshot_taken"


def normalize_address(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise EventValidationError("address must be a string")
    lowered = value.lower()
    if not lowered.startswith("0x"):
        raise EventValidationError(f"address must have 0x prefix: {value!r}")
    return lowered


def _bounded_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if len(payload) > 16:
        raise EventValidationError("payload contains too many keys")
    return payload


@dataclass(slots=True)
class Event:
    event_id: str
    seq: int
    type: EventType
    timestamp: float
    pc: str | None
    thread_id: str | None
    cpu_id: int | None
    payload: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.event_id:
            raise EventValidationError("event_id is required")
        if self.seq < 0:
            raise EventValidationError("seq must be non-negative")
        self.pc = normalize_address(self.pc)
        if self.thread_id is not None and not isinstance(self.thread_id, str):
            raise EventValidationError("thread_id must be a string or None")
        if self.cpu_id is not None and self.cpu_id < 0:
            raise EventValidationError("cpu_id must be non-negative or None")
        self.payload = _bounded_payload(dict(self.payload))
        self._validate_payload()

    def _validate_payload(self) -> None:
        validators = {
            EventType.BACKEND_READY: _validate_ready_payload,
            EventType.BASIC_BLOCK: _validate_basic_block_payload,
            EventType.BRANCH: _validate_branch_payload,
            EventType.CALL: _validate_call_payload,
            EventType.RETURN: _validate_return_payload,
            EventType.MEMORY_READ: _validate_memory_payload,
            EventType.MEMORY_WRITE: _validate_memory_payload,
            EventType.SYSCALL: _validate_syscall_payload,
            EventType.EXCEPTION: _validate_exception_payload,
            EventType.BREAKPOINT: _validate_breakpoint_payload,
            EventType.EXECUTION_PAUSED: _validate_reason_payload,
            EventType.EXECUTION_RESUMED: _validate_reason_payload,
            EventType.SNAPSHOT_TAKEN: _validate_snapshot_payload,
        }
        validators[self.type](self.payload)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Event":
        try:
            event_type = EventType(raw["type"])
        except KeyError as exc:
            raise EventValidationError("missing event type") from exc
        except ValueError as exc:
            raise EventValidationError(f"unknown event type: {raw.get('type')!r}") from exc
        return cls(
            event_id=str(raw["event_id"]),
            seq=int(raw["seq"]),
            type=event_type,
            timestamp=float(raw["timestamp"]),
            pc=raw.get("pc"),
            thread_id=raw.get("thread_id"),
            cpu_id=int(raw["cpu_id"]) if raw.get("cpu_id") is not None else None,
            payload=dict(raw.get("payload") or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "seq": self.seq,
            "type": self.type.value,
            "timestamp": self.timestamp,
            "pc": self.pc,
            "thread_id": self.thread_id,
            "cpu_id": self.cpu_id,
            "payload": dict(self.payload),
        }


@dataclass(slots=True)
class EventFilterConfig:
    event_types: set[EventType] = field(default_factory=set)
    address_ranges: list[tuple[str, str]] = field(default_factory=list)
    thread_ids: set[str] = field(default_factory=set)

    def normalized_ranges(self) -> list[tuple[str, str]]:
        ranges: list[tuple[str, str]] = []
        for start, end in self.address_ranges:
            ranges.append((normalize_address(start) or "", normalize_address(end) or ""))
        return ranges


def _require_keys(payload: dict[str, Any], keys: tuple[str, ...]) -> None:
    for key in keys:
        if key not in payload:
            raise EventValidationError(f"payload missing key: {key}")


def _validate_basic_block_payload(payload: dict[str, Any]) -> None:
    _require_keys(payload, ("start", "end", "instruction_count"))
    payload["start"] = normalize_address(payload["start"])
    payload["end"] = normalize_address(payload["end"])
    if int(payload["instruction_count"]) < 0:
        raise EventValidationError("instruction_count must be non-negative")


def _validate_branch_payload(payload: dict[str, Any]) -> None:
    _require_keys(payload, ("target", "taken"))
    payload["target"] = normalize_address(payload["target"])
    fallthrough = payload.get("fallthrough")
    if fallthrough is not None:
        payload["fallthrough"] = normalize_address(fallthrough)
    if not isinstance(payload["taken"], bool):
        raise EventValidationError("branch taken flag must be boolean")


def _validate_call_payload(payload: dict[str, Any]) -> None:
    _require_keys(payload, ("target", "kind"))
    payload["target"] = normalize_address(payload["target"])


def _validate_return_payload(payload: dict[str, Any]) -> None:
    _require_keys(payload, ("target",))
    payload["target"] = normalize_address(payload["target"])


def _validate_memory_payload(payload: dict[str, Any]) -> None:
    _require_keys(payload, ("address", "size"))
    payload["address"] = normalize_address(payload["address"])
    size = int(payload["size"])
    if size < 0 or size > 256:
        raise EventValidationError("memory event size must be between 0 and 256")
    value = payload.get("value")
    if value is not None and not isinstance(value, str):
        raise EventValidationError("memory event value must be a hex string")


def _validate_syscall_payload(payload: dict[str, Any]) -> None:
    _require_keys(payload, ("number", "phase"))
    int(payload["number"])
    if payload["phase"] not in {"enter", "exit"}:
        raise EventValidationError("syscall phase must be 'enter' or 'exit'")


def _validate_exception_payload(payload: dict[str, Any]) -> None:
    _require_keys(payload, ("vector",))
    int(payload["vector"])


def _validate_breakpoint_payload(payload: dict[str, Any]) -> None:
    _require_keys(payload, ("address", "breakpoint_id"))
    payload["address"] = normalize_address(payload["address"])


def _validate_reason_payload(payload: dict[str, Any]) -> None:
    _require_keys(payload, ("reason",))
    if not isinstance(payload["reason"], str):
        raise EventValidationError("reason must be a string")


def _validate_ready_payload(payload: dict[str, Any]) -> None:
    _require_keys(payload, ("status",))
    if not isinstance(payload["status"], str):
        raise EventValidationError("status must be a string")


def _validate_snapshot_payload(payload: dict[str, Any]) -> None:
    _require_keys(payload, ("snapshot_id",))
    if not isinstance(payload["snapshot_id"], str):
        raise EventValidationError("snapshot_id must be a string")
