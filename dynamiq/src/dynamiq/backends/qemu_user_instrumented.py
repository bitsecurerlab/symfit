from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from collections import deque
from pathlib import Path
from typing import Any

from ..errors import InvalidStateError, SessionTimeoutError, UnsupportedOperationError
from ..events import Event, EventType
from ..instrumentation import (
    AddressRange,
    InstrumentationClient,
    InstrumentationRpcClient,
    event_matches_filters,
    trace_entry_from_event,
)
from ..models import MemoryMapSnapshot, MemoryReadResult, RegisterSnapshot
from ..qemu_user import QemuUserLaunchConfig, QemuUserProcessRunner
from ..qmp import QmpClient, QmpController


def _teardown_log(message: str) -> None:
    if not os.getenv("DYNAMIQ_DEBUG_TEARDOWN"):
        return
    try:
        with open("/tmp/dynamiq-teardown.log", "a", encoding="utf-8") as stream:
            stream.write(f"backend pid={os.getpid()} {message}\n")
    except Exception:
        pass


def _debug_log(message: str) -> None:
    if not os.getenv("DYNAMIQ_DEBUG_MCP"):
        return
    try:
        with open("/tmp/dynamiq-mcp-debug.log", "a", encoding="utf-8") as stream:
            stream.write(f"backend pid={os.getpid()} {message}\n")
    except Exception:
        pass
from .base import BackendCapabilities


class QemuUserInstrumentedBackend:
    """Backend for an instrumented qemu-user target, with optional QMP support."""
    _RPC_PROTOCOL_VERSION = 1

    def __init__(
        self,
        qmp_client: QmpClient | None = None,
        instrumentation_client: InstrumentationClient | None = None,
        instrumentation_rpc_client: InstrumentationRpcClient | None = None,
        process_runner: QemuUserProcessRunner | None = None,
    ) -> None:
        self._capabilities = self._default_capabilities()
        self._qmp = qmp_client
        self._controller = QmpController(qmp_client) if qmp_client is not None else None
        self._instrumentation = instrumentation_client
        self._instrumentation_rpc = instrumentation_rpc_client
        self._process_runner = process_runner
        self._started = False
        self._state: dict[str, Any] = {
            "session_status": "not_started",
            "backend": "qemu_user_instrumented",
            "launched_qemu_user_path": None,
            "rpc_protocol_version": None,
            "rpc_capabilities": {},
            "registers": {},
            "symbolic_registers": {},
            "recent_symbolic_pcs": [],
            "trace_active": False,
            "trace_kind": None,
            "trace_file": None,
            "pending_termination": False,
            "termination_kind": None,
            "last_rpc_method": None,
            "last_rpc_timeout": None,
            "last_rpc_params": {},
            "last_rpc_status": None,
            "last_rpc_error": None,
            "rpc_history": [],
            "last_stop_transition": {},
            "recent_events": [],
            "ingestion_stats": {},
            "capabilities": self._capabilities.to_dict(),
        }
        self._trace: deque[dict[str, Any]] = deque(maxlen=4096)
        self._trace_event_ids: set[str] = set()
        self._snapshots: dict[str, dict[str, Any]] = {}
        self._auto_socket_root: Path | None = None
        self._trace_file_path: Path | None = None
        self._trace_file_offset: int = 0
        self._trace_raw_recent: deque[dict[str, Any]] = deque(maxlen=1024)
        self._trace_filter_types: set[EventType] = set()
        self._trace_filter_ranges: list[AddressRange] = []

    @staticmethod
    def _default_capabilities() -> BackendCapabilities:
        return BackendCapabilities(
            pause_resume=True,
            read_registers=True,
            read_memory=True,
            disassemble=True,
            list_memory_maps=True,
            take_snapshot=False,
            restore_snapshot=False,
            trace_basic_block=True,
            trace_branch=True,
            trace_memory=True,
            trace_syscall=True,
            run_until_address=True,
            single_step=True,
        )

    def start(
        self,
        target: str,
        args: list[str],
        cwd: str | None,
        qemu_config: dict[str, Any] | None = None,
    ) -> None:
        qemu_config = dict(qemu_config or {})
        _debug_log(f"start target={target!r} args={args!r} cwd={cwd!r} launch={bool(qemu_config.get('launch'))}")
        self._capabilities = self._default_capabilities()
        try:
            if qemu_config.get("launch"):
                qemu_config = self._ensure_launch_sockets(qemu_config)
            if qemu_config.get("launch"):
                if self._process_runner is None:
                    self._process_runner = QemuUserProcessRunner()
                launch_config = QemuUserLaunchConfig.from_target(
                    target=target,
                    args=args,
                    cwd=cwd,
                    qemu_config=qemu_config,
                )
                self._process_runner.start(launch_config)
            if self._qmp is None:
                socket_path = qemu_config.get("qmp_socket_path")
                if socket_path:
                    self._qmp = QmpClient(socket_path=socket_path, timeout=float(qemu_config.get("qmp_timeout", 2.0)))
                    self._controller = QmpController(self._qmp)
            if self._instrumentation is None:
                socket_path = qemu_config.get("instrumentation_socket_path")
                if socket_path:
                    self._instrumentation = InstrumentationClient(
                        socket_path=socket_path,
                        max_events=int(qemu_config.get("max_recent_events", 1024)),
                        timeout=float(qemu_config.get("instrumentation_timeout", 0.1)),
                    )
            if self._instrumentation_rpc is None:
                socket_path = qemu_config.get("instrumentation_rpc_socket_path")
                if socket_path:
                    self._instrumentation_rpc = InstrumentationRpcClient(
                        socket_path=socket_path,
                        timeout=float(qemu_config.get("instrumentation_rpc_timeout", 2.0)),
                    )
            trace_file_path = qemu_config.get("instrumentation_trace_file_path")
            self._trace_file_path = Path(trace_file_path) if isinstance(trace_file_path, str) and trace_file_path else None
            self._trace_file_offset = 0
            self._trace_raw_recent.clear()
            if self._instrumentation is None:
                trace_available = self._trace_file_path is not None or self._instrumentation_rpc is not None
                self._capabilities.trace_basic_block = trace_available
                self._capabilities.trace_branch = False
                self._capabilities.trace_memory = False
                self._capabilities.trace_syscall = False
                if self._instrumentation_rpc is None:
                    self._capabilities.run_until_address = False
                    self._capabilities.single_step = False
            overrides = dict(qemu_config.get("capabilities_override") or {})
            if qemu_config.get("launch"):
                if self._instrumentation is not None:
                    socket_path = getattr(self._instrumentation, "socket_path", None)
                    if socket_path:
                        self._wait_for_socket_path(
                            socket_path,
                            timeout=float(qemu_config.get("launch_connect_timeout", 5.0)),
                            socket_kind="instrumentation event",
                        )
                if self._instrumentation_rpc is not None:
                    socket_path = getattr(self._instrumentation_rpc, "socket_path", None)
                    if socket_path:
                        self._wait_for_socket_path(
                            socket_path,
                            timeout=float(qemu_config.get("launch_connect_timeout", 5.0)),
                            socket_kind="instrumentation rpc",
                        )
            try:
                if self._controller is not None:
                    self._controller.connect()
                if self._instrumentation is not None:
                    self._instrumentation.connect()
                if self._instrumentation_rpc is not None:
                    self._instrumentation_rpc.connect()
            except Exception as exc:
                process_summary = None
                if self._process_runner is not None:
                    process_summary = self._process_runner.exited_summary()
                if process_summary is not None:
                    raise InvalidStateError(f"{exc}; {process_summary}") from exc
                raise
            if self._instrumentation_rpc is not None:
                rpc_caps = self._rpc_request("capabilities")
                self._validate_rpc_capabilities(rpc_caps)
                self._apply_rpc_capabilities(rpc_caps)
                initial_status = self._rpc_request("query_status")
            else:
                initial_status = {}
            if overrides:
                for key, value in overrides.items():
                    if hasattr(self._capabilities, key):
                        setattr(self._capabilities, key, bool(value))
            launched_qemu_user_path = None
            if self._process_runner is not None and self._process_runner.config is not None:
                launched_qemu_user_path = self._process_runner.config.qemu_user_path
            self._state.update(
                {
                    "session_status": "idle",
                    "target": target,
                    "args": list(args),
                    "cwd": cwd,
                    "stop_reason": None,
                    "exit_code": None,
                    "exit_signal": None,
                    "pc": None,
                    "current_thread_id": None,
                    "registers": {},
                    "memory_maps": [],
                    "last_event_id": None,
                    "launched_qemu_user_path": launched_qemu_user_path,
                    "instrumentation_rpc_socket_path": qemu_config.get("instrumentation_rpc_socket_path"),
                    "rpc_protocol_version": self._RPC_PROTOCOL_VERSION if self._instrumentation_rpc is not None else None,
                    "rpc_capabilities": dict(rpc_caps.get("capabilities", {})) if self._instrumentation_rpc is not None else {},
                    "trace_active": bool(initial_status.get("trace_active", False)),
                    "trace_kind": initial_status.get("trace_kind") if isinstance(initial_status.get("trace_kind"), str) else None,
                    "trace_file": initial_status.get("trace_file") if isinstance(initial_status.get("trace_file"), str) else (str(self._trace_file_path) if self._trace_file_path is not None else None),
                    "recent_events": [],
                    "ingestion_stats": self._instrumentation.stats.to_dict() if self._instrumentation is not None else {},
                    "capabilities": self._capabilities.to_dict(),
                }
            )
            if isinstance(initial_status.get("status"), str):
                self._state["session_status"] = initial_status["status"]
            self._refresh_trace_from_file()
            self._started = True
            child_pid = None
            if self._process_runner is not None and getattr(self._process_runner, '_process', None) is not None:
                child_pid = getattr(self._process_runner._process, "pid", None)
            _debug_log(f"start complete status={self._state.get('session_status')} child_pid={child_pid} rpc_socket={self._state.get('instrumentation_rpc_socket_path')}")
        except Exception:
            try:
                self.close()
            except Exception:
                pass
            raise

    def resume(self, timeout: float) -> dict[str, Any]:
        self._require_started()
        _debug_log(f"resume timeout={timeout}")
        before_status = self._state.get("session_status")
        before_pc = self._state.get("pc")
        if self._instrumentation_rpc is not None:
            self._rpc_request("resume", timeout=timeout)
        elif self._controller is not None:
            self._controller.resume()
        else:
            raise UnsupportedOperationError("backend does not have a control channel configured")
        self._state["session_status"] = "running"
        self._record_stop_transition("resume", before_status, before_pc)
        return self._response({}, refresh_live_status=False)

    def pause(self, timeout: float) -> dict[str, Any]:
        self._require_started()
        if not self._capabilities.pause_resume:
            raise UnsupportedOperationError("backend does not support pause/resume control")
        before_status = self._state.get("session_status")
        before_pc = self._state.get("pc")
        if self._instrumentation_rpc is not None:
            self._rpc_request("pause", timeout=timeout)
        elif self._controller is not None:
            self._controller.pause()
        else:
            raise UnsupportedOperationError("backend does not have a control channel configured")
        self._state["session_status"] = "paused"
        self._record_stop_transition("pause", before_status, before_pc)
        return self._response({}, refresh_live_status=False)

    def run_until_address(self, address: str, timeout: float) -> dict[str, Any]:
        self._require_started()
        if not self._capabilities.run_until_address:
            raise UnsupportedOperationError("backend does not support run_until_address")
        before_status = self._state.get("session_status")
        before_pc = self._state.get("pc")
        current_pc = self._state.get("pc")
        if isinstance(current_pc, str) and current_pc.lower() == address.lower():
            self._state["session_status"] = "paused"
            self._state["pc"] = current_pc.lower()
            self._record_stop_transition("run_until_address(already_at_pc)", before_status, before_pc)
            return self._response(
                {"matched_address": current_pc.lower(), "status": "paused", "pc": current_pc.lower()},
                refresh_live_status=False,
            )
        result = self._rpc_request("resume_until_address", {"address": address}, timeout=timeout)
        status = result.get("status")
        if isinstance(status, str):
            self._state["session_status"] = status
        pc = result.get("pc")
        if isinstance(pc, str):
            self._state["pc"] = pc
        if result.get("matched") is True:
            matched_pc = result.get("matched_pc")
            if isinstance(matched_pc, str):
                result["matched_address"] = matched_pc
            else:
                result["matched_address"] = address
        self._record_stop_transition("run_until_address", before_status, before_pc)
        return self._response(result, refresh_live_status=False)

    def break_at_addresses(self, addresses: list[str], timeout: float, max_steps: int = 10000) -> dict[str, Any]:
        del max_steps
        self._require_started()
        if not addresses:
            raise InvalidStateError("at least one address is required")
        if self._instrumentation_rpc is None:
            raise UnsupportedOperationError("backend does not have an instrumentation RPC channel configured")
        normalized = [str(item).strip() for item in addresses if str(item).strip()]
        if not normalized:
            raise InvalidStateError("at least one address is required")
        if len(normalized) == 1:
            return self.run_until_address(normalized[0], timeout=timeout)
        before_status = self._state.get("session_status")
        before_pc = self._state.get("pc")
        try:
            result = self._rpc_request("resume_until_any_address", {"addresses": normalized}, timeout=timeout)
        except Exception as exc:
            if "unknown instrumentation RPC method" in str(exc):
                raise UnsupportedOperationError("backend RPC does not support resume_until_any_address") from exc
            raise
        status = result.get("status")
        if isinstance(status, str):
            self._state["session_status"] = status
        pc = result.get("pc")
        if isinstance(pc, str):
            self._state["pc"] = pc
        matched_pc = result.get("matched_pc")
        if isinstance(matched_pc, str):
            result["matched_address"] = matched_pc
        self._record_stop_transition("break_at_addresses", before_status, before_pc)
        return self._response(result, refresh_live_status=False)

    def set_breakpoints(self, addresses: list[str]) -> dict[str, Any]:
        self._require_started()
        if self._instrumentation_rpc is None:
            raise UnsupportedOperationError("backend does not have an instrumentation RPC channel configured")
        normalized = [str(item).strip() for item in addresses if str(item).strip()]
        try:
            result = self._rpc_request("set_breakpoints", {"addresses": normalized})
        except Exception as exc:
            if "unknown instrumentation RPC method" in str(exc):
                raise UnsupportedOperationError("backend RPC does not support set_breakpoints") from exc
            raise
        status = result.get("status")
        if isinstance(status, str):
            self._state["session_status"] = status
        return self._response(result, refresh_live_status=False)

    def step(self, count: int, timeout: float) -> dict[str, Any]:
        self._require_started()
        if not self._capabilities.single_step:
            raise UnsupportedOperationError("backend does not support single stepping")
        before_status = self._state.get("session_status")
        before_pc = self._state.get("pc")
        result = self._rpc_request("single_step", {"count": count}, timeout=timeout)
        status = result.get("status")
        if isinstance(status, str):
            self._state["session_status"] = status
        pc = result.get("pc")
        if isinstance(pc, str):
            self._state["pc"] = pc
        self._record_stop_transition("single_step", before_status, before_pc)
        return self._response(result, refresh_live_status=False)

    def advance_basic_blocks(self, count: int, timeout: float) -> dict[str, Any]:
        self._require_started()
        before_status = self._state.get("session_status")
        before_pc = self._state.get("pc")
        result = self._rpc_request("resume_until_basic_block", {"count": count}, timeout=timeout)
        status = result.get("status")
        if isinstance(status, str):
            self._state["session_status"] = status
        pc = result.get("pc")
        if isinstance(pc, str):
            self._state["pc"] = pc
        self._record_stop_transition("resume_until_basic_block", before_status, before_pc)
        return self._response(result, refresh_live_status=False)

    def write_stdin(self, data: str | bytes, symbolic: bool = False) -> dict[str, Any]:
        self._require_started()
        payload_size = len(data) if isinstance(data, bytes) else len(data.encode("utf-8", errors="replace"))
        _debug_log(f"write_stdin symbolic={symbolic} size={payload_size} session_status={self._state.get('session_status')}")
        if self._process_runner is None:
            raise UnsupportedOperationError("backend does not have a launched process")
        status = self._state.get("session_status")
        if status not in {"idle", "running", "paused"}:
            raise InvalidStateError("session is not active; start session before write_stdin")
        if isinstance(data, bytes):
            payload_size = len(data)
        else:
            payload_size = len(data.encode("utf-8", errors="replace"))
        if self._instrumentation_rpc is not None:
            queue_result = self._rpc_request(
                "queue_stdin_chunk",
                {"size": payload_size, "symbolic": symbolic},
            )
            pending = queue_result.get("pending_stdin_bytes")
            if isinstance(pending, int):
                self._state["pending_stdin_bytes"] = pending
            pending_symbolic = queue_result.get("pending_symbolic_stdin_bytes")
            if isinstance(pending_symbolic, int):
                self._state["pending_symbolic_stdin_bytes"] = pending_symbolic
        elif symbolic:
            raise UnsupportedOperationError("backend does not support symbolic stdin queueing")
        written = self._process_runner.write_stdin(data)
        return self._response({"written": written, "symbolic": symbolic})

    def close_stdin(self) -> dict[str, Any]:
        self._require_started()
        _debug_log(f"close_stdin session_status={self._state.get('session_status')}")
        if self._process_runner is None:
            raise UnsupportedOperationError("backend does not have a launched process")
        self._sync_process_state()
        status = self._state.get("session_status")
        if status not in {"idle", "running", "paused"}:
            raise InvalidStateError("session is not active; start session before close_stdin")
        result = self._process_runner.close_stdin()
        return self._response(result, refresh_live_status=False)

    def read_stdout(self, cursor: int = 0, max_chars: int = 4096) -> dict[str, Any]:
        self._require_started()
        if self._process_runner is None:
            raise UnsupportedOperationError("backend does not have a launched process")
        self._sync_process_state()
        return self._response(self._process_runner.read_stdout(cursor=cursor, max_chars=max_chars), refresh_live_status=False)

    def read_stderr(self, cursor: int = 0, max_chars: int = 4096) -> dict[str, Any]:
        self._require_started()
        if self._process_runner is None:
            raise UnsupportedOperationError("backend does not have a launched process")
        self._sync_process_state()
        return self._response(self._process_runner.read_stderr(cursor=cursor, max_chars=max_chars), refresh_live_status=False)

    def get_registers(self, names: list[str] | None = None) -> dict[str, Any]:
        self._require_started()
        snapshot = RegisterSnapshot.from_rpc_result(self._rpc_request("get_registers", {"names": list(names or [])}))
        self._state["registers"] = snapshot.registers
        self._state["symbolic_registers"] = snapshot.symbolic_registers
        pc = snapshot.registers.get("pc") or snapshot.registers.get("rip") or snapshot.registers.get("eip")
        if pc is not None:
            self._state["pc"] = pc
        return self._response(snapshot.to_dict())

    def read_memory(self, address: str, size: int) -> dict[str, Any]:
        self._require_started()
        result = MemoryReadResult.from_rpc_result(self._rpc_request("read_memory", {"address": address, "size": size}))
        return self._response(result.to_dict())

    def symbolize_memory(self, address: str, size: int, name: str | None = None) -> dict[str, Any]:
        self._require_started()
        params: dict[str, Any] = {"address": address, "size": size}
        if name:
            params["name"] = name
        return self._response(self._rpc_request("symbolize_memory", params))

    def symbolize_register(self, register: str, name: str | None = None) -> dict[str, Any]:
        self._require_started()
        params: dict[str, Any] = {"register": register}
        if name:
            params["name"] = name
        return self._response(self._rpc_request("symbolize_register", params))

    def get_symbolic_expression(self, label: str) -> dict[str, Any]:
        self._require_started()
        return self._response(self._rpc_request("get_symbolic_expression", {"label": label}))

    def recent_path_constraints(self, limit: int = 16) -> dict[str, Any]:
        self._require_started()
        result = self._rpc_request("get_recent_path_constraints", {"limit": limit})
        constraints = result.get("constraints")
        if isinstance(constraints, list):
            self._state["recent_symbolic_pcs"] = [
                {
                    "pc": item.get("pc"),
                    "label": item.get("label"),
                    "taken": item.get("taken"),
                    "op": item.get("op"),
                }
                for item in constraints
                if isinstance(item, dict)
                and isinstance(item.get("pc"), str)
                and isinstance(item.get("label"), str)
            ]
        else:
            self._state["recent_symbolic_pcs"] = []
        return self._response(result)

    def path_constraint_closure(self, label: str) -> dict[str, Any]:
        self._require_started()
        return self._response(self._rpc_request("get_path_constraints", {"label": label}))

    def disassemble(self, address: str, count: int) -> dict[str, Any]:
        self._require_started()
        if not self._capabilities.disassemble:
            raise UnsupportedOperationError("backend does not support disassembly")
        return self._response(self._rpc_request("disassemble", {"address": address, "count": count}))

    def list_memory_maps(self) -> dict[str, Any]:
        self._require_started()
        maps = MemoryMapSnapshot.from_rpc_result(self._rpc_request("list_memory_maps"))
        self._state["memory_maps"] = maps.to_dict()["regions"]
        return self._response({"maps": maps.to_dict()})

    def take_snapshot(self, name: str | None = None) -> dict[str, Any]:
        self._require_started()
        if not self._capabilities.take_snapshot:
            raise UnsupportedOperationError("backend does not support snapshots")
        if self._controller is None:
            raise UnsupportedOperationError("snapshot support requires a backend control channel")
        snapshot_id = name or f"s-{len(self._snapshots) + 1}"
        self._controller.save_snapshot(snapshot_id)
        snapshot = {
            "snapshot_id": snapshot_id,
            "name": name,
            "created_at": time.time(),
            "pc": self._state.get("pc"),
            "thread_id": self._state.get("current_thread_id"),
            "event_id": self._state.get("last_event_id"),
            "metadata": {"reason": "manual"},
        }
        self._snapshots[snapshot_id] = snapshot
        self._state["last_snapshot_id"] = snapshot_id
        return self._response(snapshot)

    def restore_snapshot(self, snapshot_id: str) -> dict[str, Any]:
        self._require_started()
        if not self._capabilities.restore_snapshot:
            raise UnsupportedOperationError("backend does not support snapshot restore")
        if self._controller is None:
            raise UnsupportedOperationError("snapshot restore requires a backend control channel")
        self._controller.load_snapshot(snapshot_id)
        snapshot = self._snapshots.get(snapshot_id, {"snapshot_id": snapshot_id})
        self._state["last_snapshot_id"] = snapshot_id
        return self._response(snapshot)

    def diff_snapshots(self, left_id: str, right_id: str) -> dict[str, Any]:
        left = self._snapshots.get(left_id)
        right = self._snapshots.get(right_id)
        if left is None or right is None:
            raise ValueError("snapshot id not found")
        changed: dict[str, Any] = {}
        for key in {"pc", "thread_id", "event_id"}:
            if left.get(key) != right.get(key):
                changed[key] = {"left": left.get(key), "right": right.get(key)}
        return self._response({"left_id": left_id, "right_id": right_id, "changed_fields": changed})

    def get_recent_events(
        self,
        limit: int = 100,
        event_types: list[str] | None = None,
    ) -> dict[str, Any]:
        self._require_started()
        if self._instrumentation is not None:
            events = self._instrumentation.get_recent_events(limit=limit, event_types=event_types)
            self._state["recent_events"] = events
            self._state["ingestion_stats"] = self._instrumentation.stats.to_dict()
            return self._response({"events": events})
        if self._trace_file_path is None:
            raise UnsupportedOperationError("backend does not have an instrumentation event channel configured")
        self._refresh_trace_from_file()
        events = list(self._trace_raw_recent)
        if event_types:
            requested = {EventType(item) for item in event_types}
            events = [event for event in events if EventType(event["type"]) in requested]
        events = events[-limit:]
        self._state["recent_events"] = events
        self._state["ingestion_stats"] = {
            "events_received": len(self._trace),
            "events_dropped": 0,
            "malformed_events": 0,
            "sequence_gaps": 0,
            "source": "trace_file",
            "trace_file_path": str(self._trace_file_path),
        }
        return self._response({"events": events})

    def get_trace(self, limit: int) -> dict[str, Any]:
        self._require_started()
        self._refresh_trace_from_file()
        trace = list(self._trace)[-limit:]
        return self._response({"trace": trace})

    def trace_start(
        self,
        event_types: list[str] | None = None,
        address_ranges: list[tuple[str, str]] | None = None,
    ) -> dict[str, Any]:
        self._require_started()
        normalized_types = [str(item).strip() for item in (event_types or []) if str(item).strip()]
        if address_ranges:
            raise UnsupportedOperationError("trace address range filters are not supported by the SymFit RPC backend")
        unsupported = [item for item in normalized_types if item != "basic_block"]
        if unsupported:
            raise UnsupportedOperationError(
                f"unsupported trace event types for SymFit RPC backend: {', '.join(sorted(set(unsupported)))}"
            )
        if self._instrumentation is None and self._instrumentation_rpc is not None:
            result = self._rpc_request("start_trace", {"basic_block": True})
            self._apply_trace_status(result)
            filters = {"event_types": ["basic_block"], "address_ranges": []}
            return self._response({"filters": filters, **result})
        return self.configure_event_filters(event_types=event_types, address_ranges=address_ranges)

    def trace_stop(self) -> dict[str, Any]:
        self._require_started()
        if self._instrumentation is None and self._instrumentation_rpc is not None:
            result = self._rpc_request("stop_trace")
            self._apply_trace_status(result)
            return self._response(result)
        self._state["trace_active"] = False
        self._state["trace_kind"] = None
        return self._response(
            {
                "trace_active": False,
                "trace_kind": None,
                "trace_file": str(self._trace_file_path) if self._trace_file_path is not None else None,
            }
        )

    def trace_status(self) -> dict[str, Any]:
        self._require_started()
        if self._instrumentation is None and self._instrumentation_rpc is not None:
            result = self._rpc_request("query_status")
            self._apply_trace_status(result)
            return self._response(
                {
                    "trace_active": bool(self._state.get("trace_active")),
                    "trace_kind": self._state.get("trace_kind"),
                    "trace_file": self._state.get("trace_file"),
                }
            )
        return self._response(
            {
                "trace_active": bool(self._state.get("trace_active")),
                "trace_kind": self._state.get("trace_kind"),
                "trace_file": str(self._trace_file_path) if self._trace_file_path is not None else None,
            }
        )

    def configure_event_filters(
        self,
        event_types: list[str] | None = None,
        address_ranges: list[tuple[str, str]] | None = None,
    ) -> dict[str, Any]:
        self._require_started()
        if self._instrumentation is not None:
            config = self._instrumentation.configure_filters(event_types, address_ranges)
        elif self._trace_file_path is not None:
            self._trace_filter_types = {EventType(item) for item in event_types} if event_types else set()
            self._trace_filter_ranges = [AddressRange(start, end) for start, end in (address_ranges or [])]
            config = {
                "event_types": sorted(item.value for item in self._trace_filter_types),
                "address_ranges": [(item.start, item.end) for item in self._trace_filter_ranges],
            }
        else:
            raise UnsupportedOperationError("backend does not have an instrumentation event channel configured")
        return self._response({"filters": config})

    def get_state(self) -> dict[str, Any]:
        self._refresh_live_status()
        if self._instrumentation is not None:
            self._refresh_recent_events()
        else:
            self._refresh_trace_from_file()
        return dict(self._state)

    def capabilities(self) -> dict[str, bool]:
        return self._capabilities.to_dict()

    def close(self) -> None:
        _teardown_log(f"close start process_runner={self._process_runner is not None} instrumentation={self._instrumentation is not None} rpc={self._instrumentation_rpc is not None} qmp={self._controller is not None}")
        cleanup_actions = [
            self._process_runner.close if self._process_runner is not None else None,
            self._instrumentation.close if self._instrumentation is not None else None,
            self._instrumentation_rpc.close if self._instrumentation_rpc is not None else None,
            self._controller.close if self._controller is not None else None,
        ]
        for action in cleanup_actions:
            if action is None:
                continue
            try:
                _teardown_log(f"calling cleanup action {getattr(action, '__qualname__', repr(action))}")
                action()
                _teardown_log(f"cleanup action returned {getattr(action, '__qualname__', repr(action))}")
            except Exception as exc:
                _teardown_log(f"cleanup action raised {exc!r}")
        if self._auto_socket_root is not None:
            shutil.rmtree(self._auto_socket_root, ignore_errors=True)
            self._auto_socket_root = None
        self._instrumentation = None
        self._instrumentation_rpc = None
        self._qmp = None
        self._controller = None
        self._process_runner = None
        self._capabilities = self._default_capabilities()
        self._started = False
        self._state["session_status"] = "closed"
        self._state["pending_termination"] = False
        self._state["termination_kind"] = None
        self._state["launched_qemu_user_path"] = None
        self._state["instrumentation_rpc_socket_path"] = None
        self._state["rpc_protocol_version"] = None
        self._state["rpc_capabilities"] = {}
        self._state["registers"] = {}
        self._state["symbolic_registers"] = {}
        self._state["recent_symbolic_pcs"] = []
        self._state["last_rpc_method"] = None
        self._state["last_rpc_timeout"] = None
        self._state["last_rpc_params"] = {}
        self._state["last_rpc_status"] = None
        self._state["last_rpc_error"] = None
        self._state["rpc_history"] = []
        self._state["last_stop_transition"] = {}
        self._state["stop_reason"] = None
        self._state["exit_code"] = None
        self._state["exit_signal"] = None
        self._state["pc"] = None
        self._state["current_thread_id"] = None
        self._state["registers"] = {}
        self._state["memory_maps"] = []
        self._state["last_event_id"] = None
        self._state["capabilities"] = self._capabilities.to_dict()
        self._trace_file_path = None
        _teardown_log("close done")
        self._trace_file_offset = 0
        self._trace_raw_recent.clear()
        self._trace_filter_types = set()
        self._trace_filter_ranges = []
        self._trace.clear()
        self._trace_event_ids.clear()
        self._state["trace_active"] = False
        self._state["trace_kind"] = None
        self._state["trace_file"] = None

    def _response(self, result: dict[str, Any], refresh_live_status: bool = True) -> dict[str, Any]:
        if refresh_live_status:
            self._refresh_live_status()
        if self._instrumentation is not None:
            self._refresh_recent_events()
        else:
            self._refresh_trace_from_file()
        return {"state": dict(self._state), "result": result}

    def _refresh_live_status(self) -> None:
        self._sync_process_state()
        if self._state.get("session_status") == "exited":
            return
        if self._instrumentation_rpc is not None and self._started:
            try:
                status = self._instrumentation_rpc.request("query_status")
            except SessionTimeoutError as exc:
                self._state["last_rpc_error"] = str(exc)
                if self._state.get("session_status") not in {"exited", "closed"}:
                    self._state["session_status"] = "running"
                return
            except Exception as exc:
                process_summary = None
                if self._process_runner is not None:
                    process_summary = self._process_runner.exited_summary()
                if process_summary is not None:
                    raise InvalidStateError(f"failed to query instrumentation RPC status; {process_summary}") from exc
                raise InvalidStateError("failed to query instrumentation RPC status") from exc
            if not isinstance(status, dict) or "status" not in status:
                raise InvalidStateError("instrumentation RPC status response missing status")
            self._state["session_status"] = status["status"]
            _debug_log(f"live_status rpc status={status.get('status')} pending_termination={status.get('pending_termination')} termination_kind={status.get('termination_kind')} pc={status.get('pc')}")
            self._apply_runtime_status(status)
            self._apply_trace_status(status)
            return
        if self._controller is not None and self._started:
            try:
                status = self._controller.query_status()
            except Exception as exc:
                process_summary = None
                if self._process_runner is not None:
                    process_summary = self._process_runner.exited_summary()
                if process_summary is not None:
                    raise InvalidStateError(f"failed to query backend control status; {process_summary}") from exc
                raise InvalidStateError("failed to query backend control status") from exc
            if not isinstance(status, dict) or "status" not in status:
                raise InvalidStateError("backend control status response missing status")
            self._state["session_status"] = status["status"]
            _debug_log(f"live_status controller status={status.get('status')}")
            return
        if self._started:
            _debug_log("live_status missing live channel")
            raise InvalidStateError("backend has no live status channel configured")
        self._sync_process_state()

    def _record_trace(self, event: dict[str, Any]) -> None:
        event_id = event.get("event_id")
        if not isinstance(event_id, str) or event_id in self._trace_event_ids:
            return
        self._trace_event_ids.add(event_id)
        entry = trace_entry_from_event(len(self._trace), event)
        self._trace.append(entry)
        self._state["trace_head"] = len(self._trace)

    def _refresh_recent_events(self) -> None:
        if self._instrumentation is None:
            return
        self._state["recent_events"] = self._instrumentation.get_recent_events(limit=10)
        self._state["ingestion_stats"] = self._instrumentation.stats.to_dict()

    def _refresh_trace_from_file(self) -> None:
        if self._trace_file_path is None:
            return
        path = self._trace_file_path
        if not path.exists():
            return
        malformed_events = 0
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            stream.seek(self._trace_file_offset)
            while True:
                line = stream.readline()
                if not line:
                    break
                self._trace_file_offset = stream.tell()
                payload = line.strip()
                if payload == "":
                    continue
                try:
                    event = Event.from_dict(json.loads(payload))
                except Exception:
                    malformed_events += 1
                    continue
                if not event_matches_filters(
                    event,
                    event_types=self._trace_filter_types or None,
                    address_ranges=self._trace_filter_ranges or None,
                ):
                    continue
                event_dict = event.to_dict()
                self._trace_raw_recent.append(event_dict)
                self._record_trace(event_dict)
        if malformed_events:
            current = dict(self._state.get("ingestion_stats") or {})
            current["malformed_events"] = int(current.get("malformed_events", 0)) + malformed_events
            current["source"] = "trace_file"
            current["trace_file_path"] = str(path)
            self._state["ingestion_stats"] = current
        self._state["recent_events"] = list(self._trace_raw_recent)[-10:]

    def _require_started(self) -> None:
        if not self._started:
            raise InvalidStateError("backend has not been started")

    def _require_rpc(self) -> InstrumentationRpcClient:
        if self._instrumentation_rpc is None:
            raise UnsupportedOperationError("backend does not have an instrumentation RPC channel configured")
        return self._instrumentation_rpc

    def _rpc_request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        rpc = self._require_rpc()
        request_params = dict(params or {})
        history_entry: dict[str, Any] = {
            "ts": time.time(),
            "method": method,
            "params": request_params,
            "timeout": timeout,
            "ok": False,
        }
        self._state["last_rpc_method"] = method
        self._state["last_rpc_timeout"] = timeout
        self._state["last_rpc_params"] = request_params
        self._state["last_rpc_error"] = None
        try:
            result = rpc.request(method, params, timeout=timeout)
            self._apply_trace_status(result)
            self._apply_runtime_status(result)
            history_entry["ok"] = True
            status = result.get("status")
            if isinstance(status, str):
                self._state["last_rpc_status"] = status
                history_entry["status"] = status
            if "pc" in result:
                history_entry["pc"] = result.get("pc")
            self._append_rpc_history(history_entry)
            return result
        except SessionTimeoutError as exc:
            message = str(exc)
            self._state["last_rpc_error"] = message
            if method in {
                "resume",
                "resume_until_address",
                "resume_until_any_address",
                "resume_until_basic_block",
                "single_step",
            }:
                self._state["session_status"] = "running"
                self._state["last_rpc_status"] = "timeout"
                history_entry["status"] = "timeout"
            history_entry["error"] = message
            self._append_rpc_history(history_entry)
            process_summary = None
            if self._process_runner is not None:
                process_summary = self._process_runner.exited_summary()
            if process_summary is not None:
                raise InvalidStateError(f"{exc}; {process_summary}") from exc
            raise
        except Exception as exc:
            message = str(exc)
            self._state["last_rpc_error"] = message
            history_entry["error"] = message
            self._append_rpc_history(history_entry)
            process_summary = None
            if self._process_runner is not None:
                process_summary = self._process_runner.exited_summary()
            if process_summary is not None:
                raise InvalidStateError(f"{exc}; {process_summary}") from exc
            raise

    def _validate_rpc_capabilities(self, rpc_caps: dict[str, Any]) -> None:
        version = rpc_caps.get("protocol_version")
        if not isinstance(version, int):
            raise InvalidStateError("instrumentation RPC capabilities missing integer protocol_version")
        if version != self._RPC_PROTOCOL_VERSION:
            raise InvalidStateError(
                f"incompatible instrumentation RPC protocol version: got {version}, "
                f"expected {self._RPC_PROTOCOL_VERSION}"
            )

    def _apply_rpc_capabilities(self, rpc_caps: dict[str, Any]) -> None:
        caps = rpc_caps.get("capabilities")
        if not isinstance(caps, dict):
            return
        for name in self._capabilities.to_dict().keys():
            if name in caps and isinstance(caps[name], bool):
                setattr(self._capabilities, name, caps[name])

    def _raise_launch_socket_timeout(self, socket_path: str, timeout: float, socket_kind: str) -> None:
        message = (
            f"start timed out waiting for {socket_kind} socket after {timeout:.1f}s: {socket_path}"
        )
        process_summary = None
        if self._process_runner is not None:
            process_summary = self._process_runner.exited_summary()
        if process_summary is not None:
            raise SessionTimeoutError(f"{message}; {process_summary}")
        raise SessionTimeoutError(message)

    def _wait_for_socket_path(self, socket_path: str, timeout: float, socket_kind: str = "instrumentation") -> None:
        deadline = time.time() + timeout
        path = Path(socket_path)
        while time.time() < deadline:
            if path.exists():
                return
            time.sleep(0.05)
        self._raise_launch_socket_timeout(socket_path, timeout, socket_kind)

    def _sync_process_state(self) -> None:
        if self._process_runner is None:
            return
        _debug_log(f"sync_process_state before status={self._state.get('session_status')} process_runner_present={self._process_runner is not None}")
        process = self._process_runner.process
        if process is None:
            return
        returncode = process.poll()
        if returncode is None:
            return
        before_status = self._state.get("session_status")
        before_pc = self._state.get("pc")
        self._state["session_status"] = "exited"
        _debug_log(f"sync_process_state marked exited returncode={returncode}")
        self._state["pending_termination"] = False
        if returncode < 0:
            self._state["exit_signal"] = f"SIG{-returncode}"
            self._state["exit_code"] = None
            self._state["stop_reason"] = "signaled"
        else:
            self._state["exit_code"] = int(returncode)
            self._state["exit_signal"] = None
            self._state["stop_reason"] = "exited"
        self._record_stop_transition("process_exit", before_status, before_pc)

    def _apply_runtime_status(self, payload: dict[str, Any]) -> None:
        if not isinstance(payload, dict):
            return
        if "pending_termination" in payload:
            self._state["pending_termination"] = bool(payload.get("pending_termination"))
        if "termination_kind" in payload:
            termination_kind = payload.get("termination_kind")
            self._state["termination_kind"] = termination_kind if isinstance(termination_kind, str) else None
    def _apply_trace_status(self, payload: dict[str, Any]) -> None:
        if not isinstance(payload, dict):
            return
        if "trace_active" in payload:
            self._state["trace_active"] = bool(payload.get("trace_active"))
        if "trace_kind" in payload:
            trace_kind = payload.get("trace_kind")
            self._state["trace_kind"] = trace_kind if isinstance(trace_kind, str) else None
        elif payload.get("trace_active") is False:
            self._state["trace_kind"] = None
        if "trace_file" in payload:
            trace_file = payload.get("trace_file")
            if isinstance(trace_file, str) and trace_file:
                self._state["trace_file"] = trace_file
                self._trace_file_path = Path(trace_file)
            else:
                self._state["trace_file"] = None
                self._trace_file_path = None
                self._trace_file_offset = 0

    def _ensure_launch_sockets(self, qemu_config: dict[str, Any]) -> dict[str, Any]:
        need_event = False
        need_rpc = not bool(qemu_config.get("instrumentation_rpc_socket_path"))
        need_trace_file = False
        if not need_event and not need_rpc and not need_trace_file:
            return qemu_config

        if need_event and self._instrumentation is not None:
            socket_path = getattr(self._instrumentation, "socket_path", None)
            if isinstance(socket_path, str) and socket_path:
                qemu_config["instrumentation_socket_path"] = socket_path
                need_event = False
        if need_rpc and self._instrumentation_rpc is not None:
            socket_path = getattr(self._instrumentation_rpc, "socket_path", None)
            if isinstance(socket_path, str) and socket_path:
                qemu_config["instrumentation_rpc_socket_path"] = socket_path
                need_rpc = False
        if not need_event and not need_rpc and not need_trace_file:
            return qemu_config

        root = Path(tempfile.mkdtemp(prefix="ia-qemu-"))
        self._auto_socket_root = root
        if need_event:
            qemu_config["instrumentation_socket_path"] = str(root / "events.sock")
        if need_rpc:
            qemu_config["instrumentation_rpc_socket_path"] = str(root / "rpc.sock")
        return qemu_config

    def _append_rpc_history(self, entry: dict[str, Any]) -> None:
        history = self._state.get("rpc_history")
        if not isinstance(history, list):
            history = []
        history.append(entry)
        if len(history) > 64:
            del history[:-64]
        self._state["rpc_history"] = history

    def _record_stop_transition(self, reason: str, before_status: Any, before_pc: Any) -> None:
        self._state["last_stop_transition"] = {
            "ts": time.time(),
            "reason": reason,
            "before_status": before_status,
            "after_status": self._state.get("session_status"),
            "before_pc": before_pc,
            "after_pc": self._state.get("pc"),
            "exit_code": self._state.get("exit_code"),
            "exit_signal": self._state.get("exit_signal"),
        }
