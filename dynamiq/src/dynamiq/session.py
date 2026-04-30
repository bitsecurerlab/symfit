from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

from .annotations import Annotation
from .backends.base import BackendAdapter
from .errors import InvalidStateError, SessionTimeoutError, UnsupportedOperationError
from .snapshot import Snapshot
from .state import ExecutionState


def _teardown_log(message: str) -> None:
    if not os.getenv("DYNAMIQ_DEBUG_TEARDOWN"):
        return
    try:
        with open("/tmp/dynamiq-teardown.log", "a", encoding="utf-8") as stream:
            stream.write(f"session pid={os.getpid()} {message}\n")
    except Exception:
        pass


@dataclass(slots=True)
class SessionConfig:
    backend_name: str = "qemu_user_instrumented"
    max_recent_events: int = 1024
    max_trace_entries: int = 4096
    max_memory_read: int = 256
    max_disassembly_instructions: int = 64


@dataclass(slots=True)
class AnalysisSession:
    backend: BackendAdapter
    config: SessionConfig = field(default_factory=SessionConfig)
    state: ExecutionState = field(default_factory=ExecutionState)
    snapshots: dict[str, Snapshot] = field(default_factory=dict)
    annotations: dict[str, list[Annotation]] = field(default_factory=dict)
    breakpoints: list[int] = field(default_factory=list)

    def start(
        self,
        target: str,
        args: list[str] | None = None,
        cwd: str | None = None,
        qemu_config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if self.state.session_status not in {"not_started", "closed"}:
            raise InvalidStateError("session already started")
        call_args = list(args or [])
        self.backend.start(target=target, args=call_args, cwd=cwd, qemu_config=qemu_config)
        self.state.session_status = "idle"
        self.state.backend = self.config.backend_name
        self.state.target = target
        self.state.args = call_args
        self.state.cwd = cwd
        self.state.trace_active = False
        self.state.trace_kind = None
        self.state.trace_file = None
        self.state.trace_event_types = []
        self.state.trace_address_ranges = []
        self.state.trace_start_head = 0
        self.state.capabilities = self.backend.capabilities()
        self._merge_state(self.backend.get_state())
        return self._response("start", {"target": target})


    def pause(self, timeout: float = 5.0) -> dict[str, Any]:
        if self.state.session_status in {"not_started", "closed"}:
            raise InvalidStateError("session is not started")
        if self.state.session_status in {"idle", "paused"}:
            self.state.session_status = "paused"
            return self._response("pause", {"status": "paused", "noop": True})
        return self._forward("pause", self.backend.pause(timeout))

    def resume(self, timeout: float = 5.0) -> dict[str, Any]:
        return self._forward("resume", self.backend.resume(timeout))

    def run_until_address(self, address: str, timeout: float = 5.0) -> dict[str, Any]:
        return self._forward("run_until_address", self.backend.run_until_address(address, timeout))

    def step(self, count: int = 1, timeout: float = 5.0) -> dict[str, Any]:
        return self._forward("step", self.backend.step(count, timeout))

    def advance_basic_blocks(self, count: int = 1, timeout: float = 5.0) -> dict[str, Any]:
        return self._forward("advance_basic_blocks", self.backend.advance_basic_blocks(count, timeout))

    def advance(self, mode: str, count: int | None = None, timeout: float = 5.0) -> dict[str, Any]:
        normalized_mode = str(mode).strip().lower()
        if normalized_mode not in {"continue", "insn", "bb", "return"}:
            raise InvalidStateError("advance mode must be one of: continue, insn, bb, return")
        if normalized_mode in {"insn", "bb"}:
            if count is None:
                count = 1
            if count < 1:
                raise InvalidStateError("advance count must be >= 1")
        elif count is not None:
            raise InvalidStateError("advance count is only valid for insn and bb modes")

        if normalized_mode == "continue":
            return self._advance_continue(timeout)
        if normalized_mode == "insn":
            return self._advance_counted(mode="insn", count=int(count), timeout=timeout)
        if normalized_mode == "bb":
            return self._advance_counted(mode="bb", count=int(count), timeout=timeout)
        return self._advance_return(timeout)


    def bp_add(self, address: str) -> dict[str, Any]:
        normalized = str(address).strip()
        if normalized == "":
            raise InvalidStateError("breakpoint address must be non-empty")
        value = self._parse_address(normalized)
        if value not in self.breakpoints:
            self.breakpoints.append(value)
        return self._response("bp_add", {"address": hex(value), "breakpoints": [hex(item) for item in self.breakpoints]})

    def bp_del(self, address: str) -> dict[str, Any]:
        normalized = str(address).strip()
        if normalized == "":
            raise InvalidStateError("breakpoint address must be non-empty")
        value = self._parse_address(normalized)
        if value in self.breakpoints:
            self.breakpoints.remove(value)
        return self._response("bp_del", {"address": hex(value), "breakpoints": [hex(item) for item in self.breakpoints]})

    def bp_clear(self) -> dict[str, Any]:
        self.breakpoints.clear()
        return self._response("bp_clear", {"breakpoints": []})

    def bp_list(self) -> dict[str, Any]:
        return self._response("bp_list", {"breakpoints": [hex(item) for item in self.breakpoints]})

    def bp_run(self, timeout: float = 5.0, max_steps: int = 10000) -> dict[str, Any]:
        if not self.breakpoints:
            raise InvalidStateError("no breakpoints configured")
        result = self.break_at_addresses([hex(item) for item in self.breakpoints], timeout=timeout, max_steps=max_steps)
        return self._response("bp_run", dict(result.get("result", {})))

    def break_at_addresses(
        self,
        addresses: list[str],
        timeout: float = 5.0,
        max_steps: int = 10000,
    ) -> dict[str, Any]:
        if not addresses:
            raise InvalidStateError("at least one address is required")
        if max_steps < 0:
            raise InvalidStateError("max_steps must be >= 0")
        targets = sorted({self._parse_address(item) for item in addresses})
        backend_break = getattr(self.backend, "break_at_addresses", None)
        if callable(backend_break):
            try:
                return self._forward(
                    "break_at_addresses",
                    backend_break(
                        [hex(item) for item in targets],
                        timeout=timeout,
                        max_steps=max_steps,
                    ),
                )
            except UnsupportedOperationError:
                pass

        current_pc = self._read_live_pc()
        steps = 0

        if current_pc is not None and current_pc in targets:
            # Continue semantics: do not immediately re-hit the current stop address.
            if max_steps == 0:
                raise InvalidStateError("max_steps exceeded before hitting any requested address")
            step_result = self.step(1, timeout=timeout)
            steps += 1
            current_pc = self._parse_optional_address(step_result.get("result", {}).get("pc"))
            if current_pc is None:
                current_pc = self._read_live_pc()

        while steps <= max_steps:
            if current_pc is not None and current_pc in targets:
                matched = hex(current_pc)
                return self._response(
                    "break_at_addresses",
                    {
                        "matched_address": matched,
                        "breakpoints": [hex(item) for item in targets],
                        "steps": steps,
                    },
                )
            if steps == max_steps:
                break
            step_result = self.step(1, timeout=timeout)
            steps += 1
            current_pc = self._parse_optional_address(step_result.get("result", {}).get("pc"))
            if current_pc is None:
                current_pc = self._read_live_pc()

        raise InvalidStateError("max_steps exceeded before hitting any requested address")

    def _advance_continue(self, timeout: float) -> dict[str, Any]:
        if self.breakpoints:
            result = self.bp_run(timeout=timeout)
            payload = dict(result.get("result", {}))
            payload.update({"mode": "continue", "completed": False, "stop_reason": "breakpoint"})
            return self._response("advance", payload)

        self._forward("advance", self.backend.resume(timeout))
        deadline = time.time() + timeout
        while time.time() < deadline:
            state_payload = self.backend.get_state()
            self._merge_state(state_payload)

            if self.state.session_status in {"paused", "idle", "exited", "closed"}:
                stop_reason = self._infer_stop_reason({}, self._read_live_pc(), completed=False)
                result = {
                    "mode": "continue",
                    "completed": False,
                    "stop_reason": stop_reason,
                }
                if stop_reason == "paused" and self.state.session_status in {"paused", "idle"}:
                    if self.state.pending_termination:
                        result["stop_reason"] = "termination_pending"
                        if isinstance(self.state.termination_kind, str):
                            result["termination_kind"] = self.state.termination_kind
                    else:
                        result["stop_reason"] = "io"
                        result["stdout_ready"] = False
                        result["stderr_ready"] = False
                if isinstance(self.state.pc, str):
                    result["pc"] = self.state.pc
                return self._response("advance", result)
            time.sleep(0.05)
        self._merge_state(self.backend.get_state())
        result = {
            "mode": "continue",
            "completed": False,
            "timed_out": True,
            "stop_reason": "running" if self.state.session_status == "running" else "unknown",
        }
        if isinstance(self.state.pc, str):
            result["pc"] = self.state.pc
        return self._response("advance", result)

    def _advance_counted(self, mode: str, count: int, timeout: float) -> dict[str, Any]:
        current_pc = self._read_live_pc()
        executed = 0
        last_payload: dict[str, Any] = {}
        if current_pc is not None and current_pc in self.breakpoints:
            first_payload = self._advance_one_unit(mode, timeout)
            executed += 1
            current_pc = self._payload_pc(first_payload)
            last_payload = first_payload
            if current_pc is not None and current_pc in self.breakpoints:
                payload = self._format_advance_result(
                    mode=mode,
                    requested_count=count,
                    actual_count=executed,
                    completed=False,
                    stop_reason="breakpoint",
                    payload=first_payload,
                )
                return self._response("advance", payload)
            if self._payload_terminal(first_payload):
                payload = self._format_advance_result(
                    mode=mode,
                    requested_count=count,
                    actual_count=executed,
                    completed=False,
                    stop_reason=self._infer_stop_reason(first_payload, current_pc, completed=False),
                    payload=first_payload,
                )
                return self._response("advance", payload)
        while executed < count:
            step_payload = self._advance_one_unit(mode, timeout)
            executed += 1
            current_pc = self._payload_pc(step_payload)
            last_payload = step_payload
            if current_pc is not None and current_pc in self.breakpoints:
                payload = self._format_advance_result(
                    mode=mode,
                    requested_count=count,
                    actual_count=executed,
                    completed=False,
                    stop_reason="breakpoint",
                    payload=step_payload,
                )
                return self._response("advance", payload)
            if self._payload_terminal(step_payload):
                payload = self._format_advance_result(
                    mode=mode,
                    requested_count=count,
                    actual_count=executed,
                    completed=False,
                    stop_reason=self._infer_stop_reason(step_payload, current_pc, completed=False),
                    payload=step_payload,
                )
                return self._response("advance", payload)
        payload = self._format_advance_result(
            mode=mode,
            requested_count=count,
            actual_count=executed,
            completed=True,
            stop_reason="target_reached",
            payload=last_payload,
        )
        return self._response("advance", payload)

    def _advance_return(self, timeout: float) -> dict[str, Any]:
        return_address = self._current_return_address()
        if return_address is None:
            raise InvalidStateError("unable to determine return address for current frame")
        result = self.break_at_addresses([hex(return_address)], timeout=timeout, max_steps=10000)
        payload = dict(result.get("result", {}))
        payload.update(
            {
                "mode": "return",
                "return_address": hex(return_address),
                "completed": payload.get("matched_address") == hex(return_address),
                "stop_reason": "target_reached" if payload.get("matched_address") == hex(return_address) else "breakpoint",
            }
        )
        return self._response("advance", payload)

    def _advance_one_unit(self, mode: str, timeout: float) -> dict[str, Any]:
        if mode == "insn":
            return self._forward("advance", self.backend.step(1, timeout)).get("result", {})
        if mode == "bb":
            return self._forward("advance", self.backend.advance_basic_blocks(1, timeout)).get("result", {})
        raise InvalidStateError(f"unsupported advance mode: {mode}")

    def _format_advance_result(
        self,
        *,
        mode: str,
        requested_count: int,
        actual_count: int,
        completed: bool,
        stop_reason: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        result = dict(payload)
        result["mode"] = mode
        result["completed"] = completed
        result["stop_reason"] = stop_reason
        result["requested_count"] = requested_count
        result["actual_count"] = actual_count
        return result

    def _payload_pc(self, payload: dict[str, Any]) -> int | None:
        if not isinstance(payload, dict):
            return self._read_live_pc()
        for key in ("matched_pc", "pc", "matched_address"):
            value = payload.get(key)
            parsed = self._parse_optional_address(value)
            if parsed is not None:
                return parsed
        return self._read_live_pc()

    def _payload_terminal(self, payload: dict[str, Any]) -> bool:
        status = payload.get("status") if isinstance(payload, dict) else None
        if status == "exited":
            return True
        return self.state.session_status == "exited"

    def _infer_stop_reason(self, payload: dict[str, Any], current_pc: int | None, completed: bool) -> str:
        if current_pc is not None and current_pc in self.breakpoints:
            return "breakpoint"
        if isinstance(payload, dict):
            for key in ("stop_reason", "reason"):
                value = payload.get(key)
                if isinstance(value, str) and value:
                    return value
            status = payload.get("status")
            if status == "exited":
                return "exited"
        if self.state.session_status == "exited":
            return "exited"
        if completed:
            return "target_reached"
        return "paused"

    def _stream_cursor(self, stream_name: str) -> int:
        backend_method = getattr(self.backend, f"read_{stream_name}", None)
        if not callable(backend_method):
            return 0
        try:
            payload = backend_method(cursor=0, max_chars=1 << 20)
        except Exception:
            return 0
        result = payload.get("result", {}) if isinstance(payload, dict) else {}
        cursor = result.get("cursor")
        return int(cursor) if isinstance(cursor, int) and cursor >= 0 else 0

    def _read_live_pc(self) -> int | None:
        live_pc: int | None = None
        try:
            registers = self.get_registers(["rip", "eip", "pc"])["result"].get("registers", {})
        except Exception:
            registers = {}
        for key in ("rip", "eip", "pc"):
            value = registers.get(key)
            parsed = self._parse_optional_address(value)
            if parsed is not None:
                live_pc = parsed
                break
        if live_pc is None:
            live_pc = self._parse_optional_address(self.state.pc)
        return live_pc

    def _current_pointer_size(self) -> int:
        regs64 = self.get_registers(["pc", "rip", "rbp", "rsp"]).get("result", {}).get("registers", {})
        regs32 = self.get_registers(["pc", "eip", "ebp", "esp"]).get("result", {}).get("registers", {})
        pc64 = self._parse_optional_address(regs64.get("pc") or regs64.get("rip"))
        pc32 = self._parse_optional_address(regs32.get("pc") or regs32.get("eip"))
        qemu_path = (self.state.launched_qemu_user_path or "").lower()
        if "aarch64" in qemu_path:
            return 8
        if "qemu-i386" in qemu_path:
            return 4
        if "qemu-x86_64" in qemu_path:
            return 8
        return 8 if pc64 is not None and (pc32 is None or pc64 > 0xFFFFFFFF) else 4

    def _current_return_address(self) -> int | None:
        qemu_path = (self.state.launched_qemu_user_path or "").lower()
        if "aarch64" in qemu_path:
            regs = self.get_registers(["x30"]).get("result", {}).get("registers", {})
            lr = self._parse_optional_address(regs.get("x30"))
            if lr is not None and lr != 0:
                return lr
        try:
            bt = self.backtrace(max_frames=2)
            frames = bt.get("result", {}).get("frames", [])
            if isinstance(frames, list) and len(frames) > 1:
                ret = self._parse_optional_address(frames[1].get("pc"))
                if ret is not None:
                    return ret
        except Exception:
            pass
        regs = self.get_registers(["x30", "rsp", "esp"]).get("result", {}).get("registers", {})
        lr = self._parse_optional_address(regs.get("x30"))
        if lr is not None and lr != 0:
            return lr
        sp = self._parse_optional_address(regs.get("rsp") or regs.get("esp"))
        if sp is None:
            return None
        pointer_size = self._current_pointer_size()
        return self._read_pointer(sp, pointer_size)

    def write_stdin(self, data: str | bytes, symbolic: bool = False) -> dict[str, Any]:
        return self._forward("write_stdin", self.backend.write_stdin(data, symbolic=symbolic))

    def read_stdout(self, cursor: int = 0, max_chars: int = 4096) -> dict[str, Any]:
        return self._forward("read_stdout", self.backend.read_stdout(cursor, max_chars))

    def read_stderr(self, cursor: int = 0, max_chars: int = 4096) -> dict[str, Any]:
        return self._forward("read_stderr", self.backend.read_stderr(cursor, max_chars))

    def symbols(self, max_count: int = 500, name_filter: str | None = None) -> dict[str, Any]:
        if max_count < 1:
            raise InvalidStateError("max_count must be >= 1")
        target = self.state.target
        if not isinstance(target, str) or target == "":
            raise InvalidStateError("session target is not available")
        elf_type = self._read_elf_type(target)
        load_base = 0
        if elf_type == "DYN":
            maps_result = self.list_memory_maps()["result"]
            regions = maps_result.get("maps", {}).get("regions", [])
            candidates = self._resolve_pie_bases(target=target, regions=regions)
            if not candidates:
                raise InvalidStateError("unable to resolve PIE load base from memory maps")
            load_base = min(candidates)
        symbols = self._read_elf_symbols(target, elf_type=elf_type, load_base=load_base, max_count=max_count, name_filter=name_filter)
        if len(symbols) < max_count:
            symbols.extend(
                self._read_plt_symbols(
                    target,
                    elf_type=elf_type,
                    load_base=load_base,
                    max_count=max_count - len(symbols),
                    name_filter=name_filter,
                    existing_names={str(item.get("name")) for item in symbols},
                )
            )
        return self._response(
            "symbols",
            {
                "target": target,
                "elf_type": elf_type,
                "load_base": hex(load_base),
                "symbols": symbols,
            },
        )

    def get_registers(self, names: list[str] | None = None) -> dict[str, Any]:
        return self._forward("get_registers", self.backend.get_registers(names))

    def backtrace(self, max_frames: int = 16) -> dict[str, Any]:
        if max_frames < 1:
            raise InvalidStateError("max_frames must be >= 1")
        regs64 = self.get_registers(["pc", "rip", "rbp", "rsp", "x29", "sp"]).get("result", {}).get("registers", {})
        regs32 = self.get_registers(["pc", "eip", "ebp", "esp"]).get("result", {}).get("registers", {})
        if not isinstance(regs64, dict) or not isinstance(regs32, dict):
            raise InvalidStateError("register read did not return a register map")

        pc64 = self._parse_optional_address(regs64.get("pc") or regs64.get("rip"))
        fp64 = self._parse_optional_address(regs64.get("rbp") or regs64.get("x29"))
        sp64 = self._parse_optional_address(regs64.get("rsp") or regs64.get("sp"))
        pc32 = self._parse_optional_address(regs32.get("pc") or regs32.get("eip"))
        fp32 = self._parse_optional_address(regs32.get("ebp"))
        sp32 = self._parse_optional_address(regs32.get("esp"))

        qemu_path = (self.state.launched_qemu_user_path or "").lower()
        if "aarch64" in qemu_path:
            prefer_64 = True
        elif "qemu-i386" in qemu_path:
            prefer_64 = False
        elif "qemu-x86_64" in qemu_path:
            prefer_64 = True
        else:
            prefer_64 = pc64 is not None and pc64 > 0xFFFFFFFF

        if prefer_64:
            pc = pc64 if pc64 is not None else pc32
            fp = fp64 if fp64 is not None else fp32
            sp = sp64 if sp64 is not None else sp32
            pointer_size = 8
        else:
            pc = pc32 if pc32 is not None else pc64
            fp = fp32 if fp32 is not None else fp64
            sp = sp32 if sp32 is not None else sp64
            pointer_size = 4

        if pc is None:
            pc = self._parse_optional_address(self.state.pc)
        if pc is None:
            raise InvalidStateError("unable to determine instruction pointer for backtrace")

        symbol_table = self._build_symbol_lookup()
        frames: list[dict[str, Any]] = []
        frames.append(self._format_bt_frame(index=0, pc=pc, sp=sp, fp=fp, symbol_table=symbol_table))

        reason: str | None = None
        current_fp = fp
        for index in range(1, max_frames):
            if current_fp is None or current_fp == 0:
                reason = "frame_pointer_unavailable"
                break
            next_fp = self._read_pointer(current_fp, pointer_size)
            ret_addr = self._read_pointer(current_fp + pointer_size, pointer_size)
            if ret_addr is None or ret_addr == 0:
                reason = "return_address_unavailable"
                break
            frame = self._format_bt_frame(index=index, pc=ret_addr, sp=None, fp=next_fp, symbol_table=symbol_table)
            frames.append(frame)
            if next_fp is None or next_fp <= current_fp:
                reason = "frame_chain_terminated"
                break
            current_fp = next_fp

        return self._response(
            "backtrace",
            {
                "frames": frames,
                "pointer_size": pointer_size,
                "reason": reason,
                "truncated": len(frames) >= max_frames,
            },
        )

    def read_memory(self, address: str, size: int) -> dict[str, Any]:
        if size > self.config.max_memory_read:
            raise InvalidStateError(f"memory read exceeds max of {self.config.max_memory_read} bytes")
        return self._forward("read_memory", self.backend.read_memory(address, size))

    def symbolize_memory(self, address: str, size: int, name: str | None = None) -> dict[str, Any]:
        if size > self.config.max_memory_read:
            raise InvalidStateError(f"memory symbolization exceeds max of {self.config.max_memory_read} bytes")
        backend_method = getattr(self.backend, "symbolize_memory", None)
        if not callable(backend_method):
            raise UnsupportedOperationError("backend does not support memory symbolization")
        return self._forward("symbolize_memory", backend_method(address=address, size=size, name=name))

    def symbolize_register(self, register: str, name: str | None = None) -> dict[str, Any]:
        backend_method = getattr(self.backend, "symbolize_register", None)
        if not callable(backend_method):
            raise UnsupportedOperationError("backend does not support register symbolization")
        return self._forward("symbolize_register", backend_method(register=register, name=name))

    def get_symbolic_expression(self, label: str) -> dict[str, Any]:
        backend_method = getattr(self.backend, "get_symbolic_expression", None)
        if not callable(backend_method):
            raise UnsupportedOperationError("backend does not support symbolic expression lookup")
        return self._forward("get_symbolic_expression", backend_method(label=label))

    def recent_path_constraints(self, limit: int = 16) -> dict[str, Any]:
        backend_method = getattr(self.backend, "recent_path_constraints", None)
        if not callable(backend_method):
            raise UnsupportedOperationError("backend does not support recent path-constraint lookup")
        return self._forward("recent_path_constraints", backend_method(limit=limit))

    def path_constraint_closure(self, label: str) -> dict[str, Any]:
        backend_method = getattr(self.backend, "path_constraint_closure", None)
        if not callable(backend_method):
            raise UnsupportedOperationError("backend does not support path-constraint closure lookup")
        return self._forward("path_constraint_closure", backend_method(label=label))

    def disassemble(self, address: str, count: int = 16) -> dict[str, Any]:
        if count > self.config.max_disassembly_instructions:
            raise InvalidStateError(
                f"disassembly request exceeds max of {self.config.max_disassembly_instructions} instructions"
            )
        return self._forward("disassemble", self.backend.disassemble(address, count))

    def list_memory_maps(self) -> dict[str, Any]:
        return self._forward("list_memory_maps", self.backend.list_memory_maps())

    def take_snapshot(self, name: str | None = None) -> dict[str, Any]:
        response = self._forward("take_snapshot", self.backend.take_snapshot(name))
        snapshot_result = response["result"]
        snapshot = Snapshot(
            snapshot_id=snapshot_result["snapshot_id"],
            name=snapshot_result.get("name"),
            created_at=float(snapshot_result["created_at"]),
            pc=snapshot_result.get("pc"),
            thread_id=snapshot_result.get("thread_id"),
            event_id=snapshot_result.get("event_id"),
            metadata=dict(snapshot_result.get("metadata") or {}),
        )
        self.snapshots[snapshot.snapshot_id] = snapshot
        self.state.last_snapshot_id = snapshot.snapshot_id
        return response

    def restore_snapshot(self, snapshot_id: str) -> dict[str, Any]:
        return self._forward("restore_snapshot", self.backend.restore_snapshot(snapshot_id))

    def diff_snapshots(self, left_id: str, right_id: str) -> dict[str, Any]:
        return self._forward("diff_snapshots", self.backend.diff_snapshots(left_id, right_id))

    def get_recent_events(
        self,
        limit: int = 100,
        event_types: list[str] | None = None,
    ) -> dict[str, Any]:
        return self._forward("get_recent_events", self.backend.get_recent_events(limit, event_types))

    def get_trace(self, limit: int = 100) -> dict[str, Any]:
        return self._forward("get_trace", self.backend.get_trace(limit))

    def trace_start(
        self,
        event_types: list[str] | None = None,
        address_ranges: list[tuple[str, str]] | None = None,
    ) -> dict[str, Any]:
        backend_trace_start = getattr(self.backend, "trace_start", None)
        if callable(backend_trace_start):
            response = self._forward(
                "trace_start",
                backend_trace_start(event_types=event_types, address_ranges=address_ranges),
            )
        else:
            response = self._forward(
                "trace_start",
                self.backend.configure_event_filters(event_types=event_types, address_ranges=address_ranges),
            )
        filters = response.get("result", {}).get("filters", {})
        trace_event_types = filters.get("event_types", []) if isinstance(filters, dict) else []
        trace_address_ranges = filters.get("address_ranges", []) if isinstance(filters, dict) else []
        result = response.get("result", {})
        self.state.trace_active = bool(result.get("trace_active", True))
        if isinstance(result.get("trace_kind"), str):
            self.state.trace_kind = result["trace_kind"]
        if isinstance(result.get("trace_file"), str):
            self.state.trace_file = result["trace_file"]
        self.state.trace_event_types = list(trace_event_types if isinstance(trace_event_types, list) else [])
        self.state.trace_address_ranges = list(trace_address_ranges if isinstance(trace_address_ranges, list) else [])
        self.state.trace_start_head = int(self.state.trace_head)
        return self._response(
            "trace_start",
            {
                "filters": filters,
                "trace_active": self.state.trace_active,
                "trace_kind": self.state.trace_kind,
                "trace_file": self.state.trace_file,
                "trace_start_head": self.state.trace_start_head,
            },
        )

    def trace_stop(self) -> dict[str, Any]:
        backend_trace_stop = getattr(self.backend, "trace_stop", None)
        if callable(backend_trace_stop):
            response = self._forward("trace_stop", backend_trace_stop())
            result = response.get("result", {})
            self.state.trace_active = bool(result.get("trace_active", False))
            if "trace_kind" in result:
                self.state.trace_kind = result.get("trace_kind")
            elif not self.state.trace_active:
                self.state.trace_kind = None
            if "trace_file" in result:
                self.state.trace_file = result.get("trace_file")
        else:
            self.state.trace_active = False
            self.state.trace_kind = None
        return self._response(
            "trace_stop",
            {
                "trace_active": self.state.trace_active,
                "trace_kind": self.state.trace_kind,
                "trace_file": self.state.trace_file,
                "trace_start_head": self.state.trace_start_head,
            },
        )

    def trace_status(self) -> dict[str, Any]:
        backend_trace_status = getattr(self.backend, "trace_status", None)
        if callable(backend_trace_status):
            response = self._forward("trace_status", backend_trace_status())
            result = response.get("result", {})
            if "trace_active" in result:
                self.state.trace_active = bool(result.get("trace_active"))
            if "trace_kind" in result:
                self.state.trace_kind = result.get("trace_kind")
            if "trace_file" in result:
                self.state.trace_file = result.get("trace_file")
        return self._response(
            "trace_status",
            {
                "trace_active": self.state.trace_active,
                "trace_kind": self.state.trace_kind,
                "trace_file": self.state.trace_file,
                "trace_event_types": list(self.state.trace_event_types),
                "trace_address_ranges": list(self.state.trace_address_ranges),
                "trace_start_head": self.state.trace_start_head,
                "trace_head": self.state.trace_head,
            },
        )

    def trace_get(self, limit: int = 100, since_start: bool = True) -> dict[str, Any]:
        effective_limit = self.config.max_trace_entries if since_start else limit
        trace_response = self._forward("get_trace", self.backend.get_trace(effective_limit))
        trace_items = trace_response.get("result", {}).get("trace", [])
        if not isinstance(trace_items, list):
            trace_items = []
        start_head = self.state.trace_start_head if since_start else 0
        if since_start:
            trace_items = [
                item for item in trace_items
                if isinstance(item, dict) and isinstance(item.get("index"), int) and int(item["index"]) >= start_head
            ]
        if limit > 0:
            trace_items = trace_items[-limit:]
        return self._response(
            "trace_get",
            {
                "trace": trace_items,
                "since_start": since_start,
                "trace_start_head": self.state.trace_start_head,
                "trace_head": self.state.trace_head,
            },
        )

    def annotate(
        self,
        address: str,
        note: str,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        annotation = Annotation(
            annotation_id=f"a-{sum(len(items) for items in self.annotations.values()) + 1}",
            address=address,
            note=note,
            tags=list(tags or []),
        )
        self.annotations.setdefault(address, []).append(annotation)
        return self._response("annotate", annotation.to_dict())

    def list_annotations(self, address: str | None = None) -> dict[str, Any]:
        if address is None:
            values = [item.to_dict() for items in self.annotations.values() for item in items]
        else:
            values = [item.to_dict() for item in self.annotations.get(address, [])]
        return self._response("list_annotations", {"annotations": values})

    def get_state(self) -> dict[str, Any]:
        self.state.capabilities = self.backend.capabilities()
        backend_state = self.backend.get_state()
        if isinstance(backend_state, dict) and isinstance(backend_state.get("state"), dict):
            self._merge_state(backend_state["state"])
        else:
            self._merge_state(backend_state)
        return self._response("get_state", self.state.to_dict())

    def capabilities(self) -> dict[str, Any]:
        self._merge_state(self.backend.get_state())
        return self._response("capabilities", {"capabilities": self.backend.capabilities()})

    def close(self) -> dict[str, Any]:
        _teardown_log("close start")
        self.backend.close()
        _teardown_log("close backend.close returned")
        self.state.session_status = "closed"
        self.state.trace_active = False
        self.state.trace_kind = None
        self.state.trace_file = None
        _teardown_log("close done")
        return self._response("close", {})

    def _forward(self, command: str, payload: dict[str, Any]) -> dict[str, Any]:
        self._merge_state(payload.get("state") or {})
        return self._response(command, payload.get("result") or {})

    def _merge_state(self, payload: dict[str, Any]) -> None:
        for key, value in payload.items():
            if hasattr(self.state, key):
                setattr(self.state, key, value)

    def _response(self, command: str, result: dict[str, Any]) -> dict[str, Any]:
        return {
            "ok": True,
            "command": command,
            "state": self.state.to_dict(),
            "result": result,
        }

    @staticmethod
    def _parse_address(address: str) -> int:
        try:
            return int(address, 0)
        except Exception as exc:  # noqa: BLE001
            raise InvalidStateError(f"invalid address: {address!r}") from exc

    @staticmethod
    def _parse_optional_address(value: Any) -> int | None:
        if not isinstance(value, str):
            return None
        try:
            return int(value, 0)
        except Exception:
            return None

    @staticmethod
    def _read_elf_type(target: str) -> str:
        result = subprocess.run(
            ["readelf", "-h", target],
            check=True,
            capture_output=True,
            text=True,
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if line.startswith("Type:"):
                if "DYN" in line:
                    return "DYN"
                if "EXEC" in line:
                    return "EXEC"
                break
        return "EXEC"

    @staticmethod
    def _read_elf_symbols(
        target: str,
        *,
        elf_type: str,
        load_base: int,
        max_count: int,
        name_filter: str | None,
    ) -> list[dict[str, Any]]:
        result = subprocess.run(
            ["readelf", "-Ws", target],
            check=True,
            capture_output=True,
            text=True,
        )
        items: list[dict[str, Any]] = []
        current_table: str | None = None
        needle = name_filter.lower() if isinstance(name_filter, str) and name_filter else None
        for raw in result.stdout.splitlines():
            line = raw.strip()
            if line.startswith("Symbol table '"):
                start = line.find("'") + 1
                end = line.find("'", start)
                current_table = line[start:end] if start > 0 and end > start else None
                continue
            if not line or line.startswith("Num:") or ":" not in line:
                continue
            parts = line.split(None, 7)
            if len(parts) < 8:
                continue
            value, size, sym_type, bind, vis, ndx, name = parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7]
            if needle and needle not in name.lower():
                continue
            if ndx == "UND":
                loaded_address = None
            else:
                try:
                    symbol_addr = int(value, 16)
                except ValueError:
                    continue
                loaded_address = symbol_addr if elf_type == "EXEC" else load_base + symbol_addr
            items.append(
                {
                    "name": name,
                    "table": current_table,
                    "value": f"0x{value.lower()}",
                    "loaded_address": None if loaded_address is None else hex(loaded_address),
                    "size": int(size) if size.isdigit() else 0,
                    "type": sym_type,
                    "bind": bind,
                    "visibility": vis,
                    "section": ndx,
                }
            )
            if len(items) >= max_count:
                break
        return items

    @staticmethod
    def _read_plt_symbols(
        target: str,
        *,
        elf_type: str,
        load_base: int,
        max_count: int,
        name_filter: str | None,
        existing_names: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        result = subprocess.run(
            ["objdump", "-d", "-j", ".plt", "-j", ".plt.sec", target],
            check=True,
            capture_output=True,
            text=True,
        )
        items: list[dict[str, Any]] = []
        seen = set(existing_names or ())
        needle = name_filter.lower() if isinstance(name_filter, str) and name_filter else None
        for raw in result.stdout.splitlines():
            line = raw.strip()
            if not line or "<" not in line or ">:" not in line:
                continue
            left, rest = line.split("<", 1)
            name = rest.split(">:", 1)[0].strip()
            if name in {".plt", ".plt.got", ".plt.sec"}:
                continue
            if needle and needle not in name.lower():
                continue
            if name in seen:
                continue
            try:
                symbol_addr = int(left, 16)
            except ValueError:
                continue
            loaded_address = symbol_addr if elf_type == "EXEC" else load_base + symbol_addr
            items.append(
                {
                    "name": name,
                    "table": ".plt",
                    "value": f"0x{symbol_addr:x}",
                    "loaded_address": hex(loaded_address),
                    "size": 0,
                    "type": "FUNC",
                    "bind": "GLOBAL",
                    "visibility": "DEFAULT",
                    "section": ".plt",
                }
            )
            seen.add(name)
            if len(items) >= max_count:
                break
        return items

    @staticmethod
    def _resolve_pie_bases(target: str, regions: Any) -> list[int]:
        if not isinstance(regions, list):
            return []
        target_real = os.path.realpath(target)
        target_name = os.path.basename(target_real)

        def parse_addr(value: Any) -> int | None:
            if isinstance(value, str):
                try:
                    return int(value, 16)
                except ValueError:
                    return None
            return None

        def parse_offset(value: Any) -> int | None:
            if isinstance(value, int):
                return value
            if isinstance(value, str):
                try:
                    return int(value, 16)
                except ValueError:
                    try:
                        return int(value, 10)
                    except ValueError:
                        return None
            return None

        def normalize_path(value: Any) -> str:
            if not isinstance(value, str):
                return ""
            text = value.strip()
            if text == "" or text.startswith("["):
                return ""
            return text

        exact_path_zero_offset: list[int] = []
        exact_path_any_offset: list[int] = []
        basename_zero_offset: list[int] = []
        basename_any_offset: list[int] = []
        legacy_contains: list[int] = []

        for region in regions:
            if not isinstance(region, dict):
                continue
            start = parse_addr(region.get("start"))
            if start is None:
                continue
            path = normalize_path(region.get("path"))
            if path == "":
                path = normalize_path(region.get("name"))
            if path == "":
                continue
            offset = parse_offset(region.get("offset"))

            path_real = os.path.realpath(path)
            is_exact_path = path_real == target_real
            is_basename = os.path.basename(path_real) == target_name
            is_legacy_contains = target_name in path
            is_offset_zero = offset == 0 if offset is not None else False

            if is_exact_path and is_offset_zero:
                exact_path_zero_offset.append(start)
            elif is_exact_path:
                exact_path_any_offset.append(start)
            elif is_basename and is_offset_zero:
                basename_zero_offset.append(start)
            elif is_basename:
                basename_any_offset.append(start)
            elif is_legacy_contains:
                legacy_contains.append(start)

        if exact_path_zero_offset:
            return exact_path_zero_offset
        if exact_path_any_offset:
            return exact_path_any_offset
        if basename_zero_offset:
            return basename_zero_offset
        if basename_any_offset:
            return basename_any_offset
        return legacy_contains

    def _read_pointer(self, address: int, pointer_size: int) -> int | None:
        try:
            payload = self.read_memory(hex(address), pointer_size)
        except Exception:
            return None
        result = payload.get("result", {})
        if not isinstance(result, dict):
            return None
        value_hex = result.get("bytes")
        if not isinstance(value_hex, str):
            return None
        try:
            raw = bytes.fromhex(value_hex)
        except ValueError:
            return None
        if len(raw) < pointer_size:
            return None
        return int.from_bytes(raw[:pointer_size], byteorder="little", signed=False)

    def _build_symbol_lookup(self) -> list[tuple[int, str]]:
        try:
            payload = self.symbols(max_count=4096)
        except Exception:
            return []
        raw_symbols = payload.get("result", {}).get("symbols", [])
        if not isinstance(raw_symbols, list):
            return []
        pairs: list[tuple[int, str]] = []
        for item in raw_symbols:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            loaded = item.get("loaded_address")
            if not isinstance(name, str) or not isinstance(loaded, str):
                continue
            addr = self._parse_optional_address(loaded)
            if addr is None:
                continue
            pairs.append((addr, name))
        pairs.sort(key=lambda entry: entry[0])
        return pairs

    def _format_bt_frame(
        self,
        *,
        index: int,
        pc: int,
        sp: int | None,
        fp: int | None,
        symbol_table: list[tuple[int, str]],
    ) -> dict[str, Any]:
        symbol_name, offset = self._lookup_symbol(pc, symbol_table)
        frame: dict[str, Any] = {
            "index": index,
            "pc": hex(pc),
            "symbol": symbol_name,
            "offset": offset,
        }
        if sp is not None:
            frame["sp"] = hex(sp)
        if fp is not None:
            frame["fp"] = hex(fp)
        return frame

    @staticmethod
    def _lookup_symbol(pc: int, symbol_table: list[tuple[int, str]]) -> tuple[str | None, int | None]:
        if not symbol_table:
            return (None, None)
        candidate_addr: int | None = None
        candidate_name: str | None = None
        for addr, name in symbol_table:
            if addr > pc:
                break
            candidate_addr = addr
            candidate_name = name
        if candidate_addr is None or candidate_name is None:
            return (None, None)
        return (candidate_name, pc - candidate_addr)
