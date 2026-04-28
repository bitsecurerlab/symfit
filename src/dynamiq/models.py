from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .errors import EventValidationError
from .events import normalize_address


@dataclass(slots=True)
class SymbolicByte:
    offset: int
    label: str
    symbolic: bool

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "SymbolicByte":
        offset = payload.get("offset")
        label = payload.get("label")
        symbolic = payload.get("symbolic")
        if not isinstance(offset, int):
            raise EventValidationError("symbolic byte offset must be an integer")
        if offset < 0:
            raise EventValidationError("symbolic byte offset must be >= 0")
        if not isinstance(label, str):
            raise EventValidationError("symbolic byte label must be a string")
        if not isinstance(symbolic, bool):
            raise EventValidationError("symbolic byte symbolic flag must be a boolean")
        return cls(offset=offset, label=label.lower() if label.startswith(("0x", "0X")) else label, symbolic=symbolic)

    def to_dict(self) -> dict[str, Any]:
        return {"offset": self.offset, "label": self.label, "symbolic": self.symbolic}


@dataclass(slots=True)
class RegisterSnapshot:
    registers: dict[str, str] = field(default_factory=dict)
    symbolic_registers: dict[str, dict[str, Any]] = field(default_factory=dict)

    @classmethod
    def from_rpc_result(cls, payload: dict[str, Any]) -> "RegisterSnapshot":
        raw_registers = payload.get("registers")
        if not isinstance(raw_registers, dict):
            raise EventValidationError("register RPC result must contain a registers object")
        raw_symbolic = payload.get("symbolic_registers", {})
        if raw_symbolic is None:
            raw_symbolic = {}
        if not isinstance(raw_symbolic, dict):
            raise EventValidationError("register RPC symbolic_registers must be an object when present")
        normalized: dict[str, str] = {}
        normalized_symbolic: dict[str, dict[str, Any]] = {}
        for name, value in raw_registers.items():
            if not isinstance(name, str) or not isinstance(value, str):
                raise EventValidationError("register names and values must be strings")
            normalized[name] = value.lower() if value.startswith(("0x", "0X")) else value
        for name, entry in raw_symbolic.items():
            if not isinstance(name, str) or not isinstance(entry, dict):
                raise EventValidationError("symbolic register entries must be keyed objects")
            label = entry.get("label")
            symbolic = entry.get("symbolic")
            if not isinstance(label, str):
                raise EventValidationError("symbolic register label must be a string")
            if not isinstance(symbolic, bool):
                raise EventValidationError("symbolic register symbolic flag must be a boolean")
            normalized_symbolic[name] = {
                "label": label.lower() if label.startswith(("0x", "0X")) else label,
                "symbolic": symbolic,
            }
        return cls(registers=normalized, symbolic_registers=normalized_symbolic)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"registers": dict(self.registers)}
        if self.symbolic_registers:
            payload["symbolic_registers"] = dict(self.symbolic_registers)
        return payload


@dataclass(slots=True)
class MemoryRegion:
    start: str
    end: str
    perm: str
    name: str | None = None
    path: str | None = None
    offset: str | None = None
    inode: int | None = None

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "MemoryRegion":
        perm = payload.get("perm")
        if not isinstance(perm, str):
            raise EventValidationError("memory map region perm must be a string")
        name = payload.get("name")
        if name is not None and not isinstance(name, str):
            raise EventValidationError("memory map region name must be a string or null")
        path = payload.get("path")
        if path is not None and not isinstance(path, str):
            raise EventValidationError("memory map region path must be a string or null")
        offset = payload.get("offset")
        if offset is not None and not isinstance(offset, str):
            raise EventValidationError("memory map region offset must be a string or null")
        inode = payload.get("inode")
        if inode is not None and not isinstance(inode, int):
            raise EventValidationError("memory map region inode must be an integer or null")
        return cls(
            start=normalize_address(payload.get("start")),
            end=normalize_address(payload.get("end")),
            perm=perm,
            name=name,
            path=path,
            offset=offset,
            inode=inode,
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "start": self.start,
            "end": self.end,
            "perm": self.perm,
            "name": self.name,
        }
        if self.path is not None:
            payload["path"] = self.path
        if self.offset is not None:
            payload["offset"] = self.offset
        if self.inode is not None:
            payload["inode"] = self.inode
        return payload


@dataclass(slots=True)
class MemoryMapSnapshot:
    regions: list[MemoryRegion] = field(default_factory=list)

    @classmethod
    def from_rpc_result(cls, payload: dict[str, Any]) -> "MemoryMapSnapshot":
        raw_regions = payload.get("regions")
        if not isinstance(raw_regions, list):
            raise EventValidationError("memory map RPC result must contain a regions list")
        return cls(regions=[MemoryRegion.from_dict(item) for item in raw_regions])

    def to_dict(self) -> dict[str, Any]:
        return {"regions": [item.to_dict() for item in self.regions]}


@dataclass(slots=True)
class MemoryReadResult:
    address: str
    size: int
    bytes: str
    symbolic_bytes: list[SymbolicByte] = field(default_factory=list)

    @classmethod
    def from_rpc_result(cls, payload: dict[str, Any]) -> "MemoryReadResult":
        address = normalize_address(payload.get("address"))
        size = payload.get("size")
        value = payload.get("bytes")
        raw_symbolic = payload.get("symbolic_bytes", [])
        if not isinstance(size, int):
            raise EventValidationError("memory read RPC result size must be an integer")
        if size < 0 or size > 256:
            raise EventValidationError("memory read RPC result size must be between 0 and 256")
        if not isinstance(value, str):
            raise EventValidationError("memory read RPC result bytes must be a hex string")
        if len(value) % 2 != 0:
            raise EventValidationError("memory read RPC result bytes must have even length")
        if raw_symbolic is None:
            raw_symbolic = []
        if not isinstance(raw_symbolic, list):
            raise EventValidationError("memory read RPC symbolic_bytes must be a list when present")
        return cls(
            address=address,
            size=size,
            bytes=value.lower(),
            symbolic_bytes=[SymbolicByte.from_dict(item) for item in raw_symbolic],
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "address": self.address,
            "size": self.size,
            "bytes": self.bytes,
        }
        if self.symbolic_bytes:
            payload["symbolic_bytes"] = [item.to_dict() for item in self.symbolic_bytes]
        return payload
