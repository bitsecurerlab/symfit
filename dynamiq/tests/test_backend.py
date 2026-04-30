from __future__ import annotations

from pathlib import Path

import pytest

from dynamiq.backends.qemu_user_instrumented import QemuUserInstrumentedBackend
from dynamiq.errors import InvalidStateError, SessionTimeoutError, UnsupportedOperationError


class FakeQmpClient:
    def __init__(self) -> None:
        self.commands: list[tuple[str, dict | None]] = []

    def connect(self) -> dict:
        return {"QMP": {}}

    def execute(self, command: str, arguments: dict | None = None) -> dict:
        self.commands.append((command, arguments))
        if command == "human-monitor-command":
            return {"command-line": arguments["command-line"]}
        return {}

    def close(self) -> None:
        return None


class FakeQmpClientWithStatus(FakeQmpClient):
    def execute(self, command: str, arguments: dict | None = None) -> dict:
        self.commands.append((command, arguments))
        if command == "query-status":
            return {"status": "paused"}
        return super().execute(command, arguments)


class FakeInstrumentationClient:
    def __init__(self) -> None:
        self.stats = type("Stats", (), {"to_dict": lambda self: {"events_received": 1}})()
        self.connected = False
        self._pause_requested = False
        self._latest_seq = 0

    def connect(self) -> None:
        self.connected = True

    def latest_seq(self) -> int | None:
        return self._latest_seq

    def wait_for_event(self, event_types: list[str], timeout: float, min_seq_exclusive: int | None = None) -> dict:
        assert timeout == 1.0
        if event_types == ["execution_paused"]:
            assert self._pause_requested is True
            assert min_seq_exclusive == 1
            self._pause_requested = False
            self._latest_seq = 99
            return {
                "event_id": "e-pause",
                "seq": 99,
                "type": "execution_paused",
                "timestamp": 1.1,
                "pc": "0x401000",
                "thread_id": "1",
                "cpu_id": 0,
                "payload": {"reason": "user"},
            }
        assert event_types == ["branch"]
        assert min_seq_exclusive == 0
        self._latest_seq = 1
        return {
            "event_id": "e-1",
            "seq": 1,
            "type": "branch",
            "timestamp": 1.0,
            "pc": "0x401000",
            "thread_id": "1",
            "cpu_id": 0,
            "payload": {"target": "0x401010", "taken": True},
        }

    def wait_for_address(self, address: str, timeout: float, min_seq_exclusive: int | None = None) -> dict:
        assert timeout == 1.0
        assert min_seq_exclusive == 0
        self._latest_seq = 2
        return {
            "event_id": "e-2",
            "seq": 2,
            "type": "basic_block",
            "timestamp": 2.0,
            "pc": address,
            "thread_id": "1",
            "cpu_id": 0,
            "payload": {"start": address, "end": address, "instruction_count": 1},
        }

    def get_recent_events(self, limit: int = 100, event_types: list[str] | None = None) -> list[dict]:
        del limit, event_types
        return [
            {
                "event_id": "e-1",
                "seq": 1,
                "type": "branch",
                "timestamp": 1.0,
                "pc": "0x401000",
                "thread_id": "1",
                "cpu_id": 0,
                "payload": {"target": "0x401010", "taken": True},
            }
        ]

    def configure_filters(self, event_types=None, address_ranges=None) -> dict:
        return {"event_types": event_types or [], "address_ranges": address_ranges or []}

    def close(self) -> None:
        return None


class RaisingClose:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True
        raise RuntimeError("close failed")


class FakeInstrumentationRpcClient:
    def __init__(self, instrumentation_client: FakeInstrumentationClient | None = None) -> None:
        self.connected = False
        self.requests: list[tuple[str, dict]] = []
        self.request_timeouts: list[tuple[str, float | None]] = []
        self.instrumentation_client = instrumentation_client
        self.trace_active = False
        self.trace_file: str | None = None

    def connect(self) -> None:
        self.connected = True

    def request(self, method: str, params: dict | None = None, timeout: float | None = None) -> dict:
        params = dict(params or {})
        self.request_timeouts.append((method, timeout))
        if method not in {"capabilities", "query_status"}:
            self.requests.append((method, params))
        if method == "capabilities":
            return {
                "protocol_version": 1,
                "capabilities": {
                    "pause_resume": True,
                    "read_registers": True,
                    "read_memory": True,
                    "disassemble": True,
                    "list_memory_maps": True,
                    "take_snapshot": False,
                    "restore_snapshot": False,
                    "trace_basic_block": True,
                    "trace_branch": False,
                    "trace_memory": False,
                    "trace_syscall": False,
                "run_until_address": True,
                    "single_step": True,
                },
            }
        if method == "resume":
            return {}
        if method == "pause":
            if self.instrumentation_client is not None:
                self.instrumentation_client._pause_requested = True
            return {}
        if method == "resume_until_basic_block":
            return {"status": "paused", "blocks_executed": params["count"], "pc": "0x401010"}
        if method == "resume_until_address":
            return {"status": "paused", "pc": params["address"], "matched": True, "matched_pc": params["address"]}
        if method == "resume_until_any_address":
            matched = params["addresses"][0]
            return {"status": "paused", "pc": matched, "matched_pc": matched, "matched": True}
        if method == "set_breakpoints":
            return {"status": "running", "armed": bool(params["addresses"]), "breakpoints": list(params["addresses"])}
        if method == "single_step":
            return {"status": "paused", "count": params["count"], "executed": params["count"], "pc": "0x401004"}
        if method == "query_status":
            result = {"status": "paused", "trace_active": self.trace_active}
            if self.trace_file:
                result["trace_file"] = self.trace_file
            if self.trace_active:
                result["trace_kind"] = "basic_block"
            return result
        if method == "get_registers":
            return {
                "registers": {"rax": "0x1", "rbx": "0x2", "rip": "0x401000"},
                "symbolic_registers": {
                    "rax": {"symbolic": False, "label": "0x0"},
                    "rbx": {"symbolic": True, "label": "0x20"},
                    "rip": {"symbolic": False, "label": "0x0"},
                },
            }
        if method == "read_memory":
            return {
                "address": params["address"],
                "size": params["size"],
                "bytes": "0102",
                "symbolic_bytes": [
                    {"offset": 0, "symbolic": False, "label": "0x0"},
                    {"offset": 1, "symbolic": True, "label": "0x44"},
                ],
            }
        if method == "symbolize_memory":
            return {
                "address": params["address"],
                "size": params["size"],
                "bytes": [{"offset": 0, "symbolic": True, "label": "0x51"}],
            }
        if method == "symbolize_register":
            return {
                "register": params["register"],
                "value": "0x1",
                "symbolic": True,
                "label": "0x52",
            }
        if method == "get_symbolic_expression":
            return {
                "label": params["label"],
                "expression": "Xor:i64(0x22:i64, Add:i64(0x11:i64, input(0):i8))",
                "op": "Xor",
                "size": 64,
                "left_label": 0,
                "right_label": 2,
                "op1": 34,
                "op2": 0,
            }
        if method == "get_recent_path_constraints":
            return {
                "constraints": [
                    {
                        "label": "0x12",
                        "pc": "0x401020",
                        "taken": True,
                        "expression": "ICmp[eq]:bool(input(0):i8, 0x42:i8)",
                        "op": "ICmp",
                        "size": 1,
                    },
                    {
                        "label": "0x6",
                        "pc": "0x401010",
                        "taken": True,
                        "expression": "ICmp[eq]:bool(input(0):i8, 0x41:i8)",
                        "op": "ICmp",
                        "size": 1,
                    },
                ],
                "count": 2,
                "truncated": False,
            }
        if method == "get_path_constraints":
            return {
                "root": {
                    "label": params["label"],
                    "expression": "ICmp[eq]:bool(input(0):i8, 0x42:i8)",
                    "op": "ICmp",
                    "size": 1,
                    "taken": True,
                },
                "constraints": [
                    {
                        "label": "0x6",
                        "expression": "ICmp[eq]:bool(input(0):i8, 0x41:i8)",
                        "op": "ICmp",
                        "size": 1,
                        "taken": True,
                    }
                ],
                "count": 1,
            }
        if method == "disassemble":
            return {
                "instructions": [
                    {
                        "address": params["address"],
                        "size": 3,
                        "bytes": "4889e5",
                        "text": "mov rbp, rsp",
                    },
                    {
                        "address": "0x401003",
                        "size": 1,
                        "bytes": "90",
                        "text": "nop",
                    },
                ]
            }
        if method == "list_memory_maps":
            return {"regions": [{"start": "0x400000", "end": "0x401000", "perm": "r-x"}]}
        if method == "queue_stdin_chunk":
            size = int(params["size"])
            symbolic = bool(params.get("symbolic", False))
            return {
                "size": size,
                "symbolic": symbolic,
                "stream_offset": "0x0",
                "pending_stdin_bytes": size,
                "pending_symbolic_stdin_bytes": size if symbolic else 0,
            }
        if method == "start_trace":
            if not self.trace_file:
                self.trace_file = "/tmp/fake-trace.ndjson"
            self.trace_active = True
            return {"trace_active": True, "trace_kind": "basic_block", "trace_file": self.trace_file}
        if method == "stop_trace":
            self.trace_active = False
            return {"trace_active": False, "trace_file": self.trace_file}
        raise AssertionError(f"unexpected method: {method}")

    def close(self) -> None:
        return None


class FakeProcessRunner:
    def __init__(self) -> None:
        self.started = False
        self.closed = False
        self.config = None
        self.summary: str | None = None
        self._process = None
        self.stdin_writes: list[str] = []
        self.stdin_closed = False

    def start(self, config) -> object:
        self.started = True
        self.config = config
        return object()

    def close(self) -> None:
        self.closed = True

    def exited_summary(self) -> str | None:
        return self.summary

    @property
    def process(self):
        return self._process

    def write_stdin(self, data: str) -> int:
        self.stdin_writes.append(data)
        return len(data)

    def close_stdin(self) -> dict:
        already_closed = self.stdin_closed
        self.stdin_closed = True
        return {"closed": True, "already_closed": already_closed}

    def read_stdout(self, cursor: int = 0, max_chars: int = 4096) -> dict:
        del max_chars
        return {"data": "", "cursor": cursor, "eof": False}

    def read_stderr(self, cursor: int = 0, max_chars: int = 4096) -> dict:
        del max_chars
        return {"data": "", "cursor": cursor, "eof": False}


class ExitedProcess:
    def __init__(self, returncode: int) -> None:
        self._returncode = returncode

    def poll(self) -> int:
        return self._returncode


class TimeoutInstrumentationRpcClient(FakeInstrumentationRpcClient):
    def __init__(self, instrumentation_client: FakeInstrumentationClient | None = None) -> None:
        super().__init__(instrumentation_client=instrumentation_client)
        self.timeout_methods: set[str] = set()

    def request(self, method: str, params: dict | None = None, timeout: float | None = None) -> dict:
        if method in self.timeout_methods:
            self.request_timeouts.append((method, timeout))
            if method not in {"capabilities", "query_status"}:
                self.requests.append((method, dict(params or {})))
            raise SessionTimeoutError("timed out waiting for instrumentation RPC response")
        return super().request(method, params, timeout)


class FailingInstrumentationRpcClient(FakeInstrumentationRpcClient):
    def request(self, method: str, params: dict | None = None, timeout: float | None = None) -> dict:
        del timeout
        self.requests.append((method, dict(params or {})))
        raise RuntimeError("instrumentation RPC connection closed")


class BadProtocolInstrumentationRpcClient(FakeInstrumentationRpcClient):
    def request(self, method: str, params: dict | None = None, timeout: float | None = None) -> dict:
        del timeout
        if method == "capabilities":
            return {"protocol_version": 99}
        return super().request(method, params)


def test_backend_start_allows_rpc_only_mode() -> None:
    rpc = FakeInstrumentationRpcClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
    )

    backend.start(
        "target.bin",
        [],
        None,
        {
            "capabilities_override": {
                "pause_resume": False,
                "list_memory_maps": False,
                "run_until_address": False,
            }
        },
    )

    state = backend.get_state()
    registers = backend.get_registers(["rip", "rax"])

    assert state["session_status"] == "paused"
    assert state["capabilities"]["trace_branch"] is False
    assert state["capabilities"]["pause_resume"] is False
    assert state["rpc_protocol_version"] == 1
    assert state["rpc_capabilities"]["read_memory"] is True
    assert registers["result"]["registers"]["rip"] == "0x401000"


def test_backend_start_syncs_initial_rpc_status() -> None:
    rpc = FakeInstrumentationRpcClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
    )

    backend.start("target.bin", [], None, {})

    state = backend.get_state()
    assert state["session_status"] == "paused"


def test_backend_start_clears_stale_exit_and_pc_state() -> None:
    rpc = FakeInstrumentationRpcClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
    )
    backend._state["session_status"] = "exited"
    backend._state["exit_code"] = 0
    backend._state["exit_signal"] = "SIG11"
    backend._state["stop_reason"] = "signaled"
    backend._state["pc"] = "0x4081b9e0"
    backend._state["registers"] = {"eip": "0x4081b9e0"}
    backend._state["memory_maps"] = [{"start": "0x1", "end": "0x2", "perm": "r--", "name": None}]

    backend.start("target.bin", [], None, {})

    state = backend.get_state()
    assert state["session_status"] == "paused"
    assert state["exit_code"] is None
    assert state["exit_signal"] is None
    assert state["stop_reason"] is None
    assert state["pc"] is None
    assert state["registers"] == {}
    assert state["memory_maps"] == []


def test_backend_start_rejects_incompatible_rpc_protocol_version() -> None:
    rpc = BadProtocolInstrumentationRpcClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
    )

    with pytest.raises(InvalidStateError, match="incompatible instrumentation RPC protocol version"):
        backend.start("target.bin", [], None, {})


def test_backend_advance_basic_blocks_uses_rpc_method() -> None:
    rpc = FakeInstrumentationRpcClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {"capabilities_override": {"run_until_address": True}})

    result = backend.advance_basic_blocks(1, timeout=1.0)

    assert rpc.requests[-1] == ("resume_until_basic_block", {"count": 1})
    assert rpc.request_timeouts[-1] == ("resume_until_basic_block", 1.0)
    assert result["result"]["blocks_executed"] == 1
    assert result["state"]["pc"] == "0x401010"


def test_backend_run_until_address_uses_rpc_in_rpc_only_mode() -> None:
    rpc = FakeInstrumentationRpcClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {"capabilities_override": {"run_until_address": True}})

    result = backend.run_until_address("0x401000", timeout=1.0)

    assert rpc.requests[-1] == ("resume_until_address", {"address": "0x401000"})
    assert rpc.request_timeouts[-1] == ("resume_until_address", 1.0)
    assert result["result"]["matched_address"] == "0x401000"
    assert result["state"]["pc"] == "0x401000"
    assert result["state"]["last_rpc_method"] == "resume_until_address"
    assert result["state"]["last_rpc_timeout"] == 1.0
    assert result["state"]["last_stop_transition"]["reason"] == "run_until_address"


def test_backend_run_until_address_does_not_invent_match_on_exit() -> None:
    class ExitBeforeAddressRpc(FakeInstrumentationRpcClient):
        def request(self, method: str, params: dict | None = None, timeout: float | None = None) -> dict:
            if method == "resume_until_address":
                self.requests.append((method, dict(params or {})))
                self.request_timeouts.append((method, timeout))
                return {"status": "exited", "matched": False, "pc": "0x400800", "matched_pc": "0x0"}
            return super().request(method, params, timeout)

    rpc = ExitBeforeAddressRpc()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {"capabilities_override": {"run_until_address": True}})

    result = backend.run_until_address("0x401000", timeout=1.0)

    assert result["result"]["matched"] is False
    assert "matched_address" not in result["result"]
    assert result["state"]["session_status"] == "exited"
    assert result["state"]["pc"] == "0x400800"


def test_backend_run_until_address_returns_immediately_when_already_at_address() -> None:
    rpc = FakeInstrumentationRpcClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {"capabilities_override": {"run_until_address": True}})
    backend.get_registers(["rip"])

    result = backend.run_until_address("0x401000", timeout=1.0)

    assert rpc.requests == [("get_registers", {"names": ["rip"]})]
    assert result["result"]["matched_address"] == "0x401000"
    assert result["state"]["pc"] == "0x401000"


def test_backend_break_at_addresses_uses_rpc_method() -> None:
    rpc = FakeInstrumentationRpcClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {"capabilities_override": {"run_until_address": True}})

    result = backend.break_at_addresses(["0x401000", "0x401010"], timeout=1.0, max_steps=10)

    assert rpc.requests[-1] == ("resume_until_any_address", {"addresses": ["0x401000", "0x401010"]})
    assert result["result"]["matched_address"] == "0x401000"
    assert result["state"]["pc"] == "0x401000"
    assert result["state"]["last_stop_transition"]["reason"] == "break_at_addresses"


def test_backend_set_breakpoints_arms_rpc_without_pausing() -> None:
    rpc = FakeInstrumentationRpcClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {"capabilities_override": {"run_until_address": True}})
    backend._state["session_status"] = "running"

    result = backend.set_breakpoints(["0x401000"])

    assert rpc.requests[-1] == ("set_breakpoints", {"addresses": ["0x401000"]})
    assert result["result"]["armed"] is True
    assert result["state"]["session_status"] == "running"


def test_backend_disassemble_uses_rpc_in_rpc_only_mode() -> None:
    rpc = FakeInstrumentationRpcClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {"capabilities_override": {"disassemble": True}})

    result = backend.disassemble("0x401000", 2)

    assert rpc.requests[-1] == ("disassemble", {"address": "0x401000", "count": 2})
    assert result["result"]["instructions"][0]["address"] == "0x401000"
    assert result["result"]["instructions"][1]["text"] == "nop"


def test_backend_step_uses_rpc_in_rpc_only_mode() -> None:
    rpc = FakeInstrumentationRpcClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {"capabilities_override": {"single_step": True}})

    result = backend.step(2, timeout=1.0)

    assert rpc.requests[-1] == ("single_step", {"count": 2})
    assert rpc.request_timeouts[-1] == ("single_step", 1.0)
    assert result["result"]["executed"] == 2
    assert result["state"]["pc"] == "0x401004"
    assert result["state"]["last_rpc_method"] == "single_step"
    assert result["state"]["last_stop_transition"]["reason"] == "single_step"


def test_backend_rpc_failure_includes_process_exit_summary() -> None:
    rpc = FailingInstrumentationRpcClient()
    process_runner = FakeProcessRunner()
    process_runner.summary = "qemu-user exited with code 139; stderr: ia-rpc: matched stop address"
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
        process_runner=process_runner,
    )
    with pytest.raises(InvalidStateError, match="qemu-user exited with code 139"):
        backend.start("target.bin", [], None, {"capabilities_override": {"run_until_address": True}})


def test_backend_get_recent_events_returns_event_shape_not_trace_shape() -> None:
    instrumentation = FakeInstrumentationClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClient(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=FakeInstrumentationRpcClient(instrumentation),
    )
    backend.start("target.bin", [], None, {})
    result = backend.get_recent_events()

    assert result["result"]["events"][0]["event_id"] == "e-1"
    assert "payload" in result["result"]["events"][0]
    assert "index" not in result["result"]["events"][0]


def test_backend_trace_returns_trace_shape() -> None:
    instrumentation = FakeInstrumentationClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClient(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=FakeInstrumentationRpcClient(instrumentation),
    )
    backend.start("target.bin", [], None, {})
    backend._record_trace(
        {
            "event_id": "e-1",
            "type": "branch",
            "pc": "0x401000",
            "thread_id": "1",
            "payload": {"target": "0x401010", "taken": True},
        }
    )

    result = backend.get_trace(limit=10)

    assert result["result"]["trace"][0]["event_id"] == "e-1"
    assert result["result"]["trace"][0]["index"] == 0
    assert "payload" not in result["result"]["trace"][0]


def test_backend_take_snapshot_records_snapshot_id() -> None:
    instrumentation = FakeInstrumentationClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClient(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=FakeInstrumentationRpcClient(instrumentation),
    )
    backend.start("target.bin", [], None, {})

    with pytest.raises(Exception):
        backend.take_snapshot("snap-1")


def test_backend_trace_start_uses_rpc_method() -> None:
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=FakeInstrumentationRpcClient(None),
    )
    backend.start("target.bin", [], None, {})

    result = backend.trace_start(event_types=["basic_block"], address_ranges=None)

    assert result["result"]["filters"]["event_types"] == ["basic_block"]
    assert result["result"]["trace_active"] is True
    assert result["result"]["trace_kind"] == "basic_block"
    assert result["result"]["trace_file"] == "/tmp/fake-trace.ndjson"


def test_backend_trace_status_uses_rpc_query_status() -> None:
    rpc = FakeInstrumentationRpcClient(None)
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {})
    backend.trace_start(event_types=["basic_block"], address_ranges=None)

    result = backend.trace_status()

    assert result["result"]["trace_active"] is True
    assert result["result"]["trace_kind"] == "basic_block"
    assert result["result"]["trace_file"] == "/tmp/fake-trace.ndjson"


def test_backend_trace_stop_uses_rpc_method() -> None:
    rpc = FakeInstrumentationRpcClient(None)
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {})
    backend.trace_start(event_types=["basic_block"], address_ranges=None)

    result = backend.trace_stop()

    assert result["result"]["trace_active"] is False
    assert result["result"]["trace_file"] == "/tmp/fake-trace.ndjson"


def test_backend_trace_start_rejects_unsupported_filters() -> None:
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=FakeInstrumentationRpcClient(None),
    )
    backend.start("target.bin", [], None, {})

    with pytest.raises(UnsupportedOperationError, match="unsupported trace event types"):
        backend.trace_start(event_types=["branch"], address_ranges=None)


def test_backend_get_state_queries_qmp_status() -> None:
    instrumentation = FakeInstrumentationClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClientWithStatus(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=FakeInstrumentationRpcClient(instrumentation),
    )
    backend.start("target.bin", [], None, {})

    state = backend.get_state()

    assert state["session_status"] == "paused"


def test_backend_get_state_returns_cached_running_state_after_rpc_timeout() -> None:
    rpc = TimeoutInstrumentationRpcClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
        process_runner=FakeProcessRunner(),
    )
    backend.start("target.bin", [], None, {})

    rpc.timeout_methods.add("resume_until_basic_block")
    with pytest.raises(SessionTimeoutError):
        backend.advance_basic_blocks(count=1, timeout=0.25)
    assert backend._state["session_status"] == "running"

    rpc.timeout_methods.add("query_status")
    state = backend.get_state()

    assert state["session_status"] == "running"
    assert "timed out waiting" in state["last_rpc_error"]


def test_backend_stdout_does_not_query_rpc_after_running_timeout() -> None:
    rpc = TimeoutInstrumentationRpcClient()
    process_runner = FakeProcessRunner()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
        process_runner=process_runner,
    )
    backend.start("target.bin", [], None, {})
    rpc.timeout_methods.update({"resume_until_basic_block", "query_status"})

    with pytest.raises(SessionTimeoutError):
        backend.advance_basic_blocks(count=1, timeout=0.25)
    result = backend.read_stdout(cursor=0, max_chars=500)

    assert result["state"]["session_status"] == "running"
    assert result["result"] == {"data": "", "cursor": 0, "eof": False}
    assert rpc.request_timeouts[-1][0] == "resume_until_basic_block"


def test_backend_resume_uses_rpc_control_when_available() -> None:
    instrumentation = FakeInstrumentationClient()
    rpc = FakeInstrumentationRpcClient(instrumentation)
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {})

    result = backend.resume(timeout=1.0)

    assert result["state"]["session_status"] == "running"
    assert rpc.requests[0] == ("resume", {})


def test_backend_pause_uses_rpc_control_when_available() -> None:
    instrumentation = FakeInstrumentationClient()
    rpc = FakeInstrumentationRpcClient(instrumentation)
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {})
    backend.resume(timeout=1.0)

    result = backend.pause(timeout=1.0)

    assert result["state"]["session_status"] == "paused"
    assert ("pause", {}) in rpc.requests


def test_backend_start_can_launch_qemu_user_process() -> None:
    runner = FakeProcessRunner()
    instrumentation = FakeInstrumentationClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=FakeInstrumentationRpcClient(instrumentation),
        process_runner=runner,
    )

    backend.start(
        "target.bin",
        ["arg1"],
        "/tmp/work",
        {
            "launch": True,
            "qemu_user_path": "/usr/bin/qemu-x86_64",
            "instrumentation_socket_path": "/tmp/events.sock",
            "instrumentation_rpc_socket_path": "/tmp/rpc.sock",
        },
    )

    assert runner.started is True
    assert runner.config.target == "target.bin"
    assert runner.config.args == ["arg1"]
    assert runner.config.cwd == "/tmp/work"
    assert backend.get_state()["launched_qemu_user_path"] == "/usr/bin/qemu-x86_64"


def test_backend_start_launch_auto_configures_rpc_socket_path() -> None:
    runner = FakeProcessRunner()
    instrumentation = FakeInstrumentationClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=FakeInstrumentationRpcClient(instrumentation),
        process_runner=runner,
    )

    backend.start(
        "target.bin",
        [],
        None,
        {
            "launch": True,
            "qemu_user_path": "/usr/bin/qemu-x86_64",
            "instrumentation_socket_path": "/tmp/events.sock",
        },
    )

    rpc_socket = runner.config.instrumentation_rpc_socket
    assert isinstance(rpc_socket, str) and rpc_socket.endswith("/rpc.sock")
    assert Path(rpc_socket).parent.exists()
    assert backend.get_state()["instrumentation_rpc_socket_path"] == rpc_socket

    backend.close()
    assert not Path(rpc_socket).parent.exists()


def test_backend_start_launch_auto_configures_rpc_path_only() -> None:
    runner = FakeProcessRunner()
    instrumentation = FakeInstrumentationClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=FakeInstrumentationRpcClient(instrumentation),
        process_runner=runner,
    )

    backend.start(
        "target.bin",
        [],
        None,
        {
            "launch": True,
            "qemu_user_path": "/usr/bin/qemu-x86_64",
        },
    )

    rpc_socket = runner.config.instrumentation_rpc_socket
    assert isinstance(rpc_socket, str) and rpc_socket.endswith("/rpc.sock")
    assert Path(rpc_socket).parent.exists()
    assert runner.config.instrumentation_trace_file is None

    backend.close()
    assert not Path(rpc_socket).parent.exists()


def test_backend_close_still_reaps_process_runner_when_other_cleanup_fails(tmp_path: Path) -> None:
    runner = FakeProcessRunner()
    instrumentation = RaisingClose()
    instrumentation_rpc = RaisingClose()
    qmp = RaisingClose()
    backend = QemuUserInstrumentedBackend(
        qmp_client=qmp,
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=instrumentation_rpc,
        process_runner=runner,
    )
    auto_socket_root = tmp_path / "rpc-root"
    auto_socket_root.mkdir()

    backend._auto_socket_root = auto_socket_root
    backend._started = True
    backend._state["session_status"] = "paused"

    backend.close()

    assert runner.closed is True
    assert instrumentation.closed is True
    assert instrumentation_rpc.closed is True
    assert qmp.closed is True
    assert not auto_socket_root.exists()
    assert backend.get_state()["session_status"] == "closed"


def test_backend_start_cleans_up_partial_launch_on_socket_timeout(monkeypatch) -> None:  # noqa: ANN001
    runner = FakeProcessRunner()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=None,
        process_runner=runner,
    )

    def _raise_timeout(socket_path: str, timeout: float, socket_kind: str = "instrumentation") -> None:
        del socket_path, timeout, socket_kind
        raise SessionTimeoutError("start timed out waiting for instrumentation rpc socket after 5.0s")

    monkeypatch.setattr(
        QemuUserInstrumentedBackend,
        "_wait_for_socket_path",
        staticmethod(_raise_timeout),
    )

    with pytest.raises(SessionTimeoutError, match="start timed out waiting for instrumentation rpc socket"):
        backend.start(
            "target.bin",
            [],
            None,
            {
                "launch": True,
                "qemu_user_path": "/usr/bin/qemu-x86_64",
            },
        )

    assert runner.started is True
    assert runner.closed is True
    state = backend.get_state()
    assert state["session_status"] == "closed"
    assert state["instrumentation_rpc_socket_path"] is None
    assert backend._instrumentation is None
    assert backend._instrumentation_rpc is None


def test_backend_start_fails_when_event_socket_missing(monkeypatch) -> None:  # noqa: ANN001
    runner = FakeProcessRunner()
    instrumentation = FakeInstrumentationClient()
    rpc = FakeInstrumentationRpcClient(instrumentation)
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=rpc,
        process_runner=runner,
    )

    def _wait_selective(socket_path: str, timeout: float, socket_kind: str = "instrumentation") -> None:
        del timeout
        if socket_path.endswith("events.sock"):
            raise SessionTimeoutError(f"start timed out waiting for {socket_kind} socket after 5.0s: {socket_path}")
        return None

    monkeypatch.setattr(
        QemuUserInstrumentedBackend,
        "_wait_for_socket_path",
        staticmethod(_wait_selective),
    )
    monkeypatch.setattr(instrumentation, "socket_path", "/tmp/ia/events.sock", raising=False)
    monkeypatch.setattr(rpc, "socket_path", "/tmp/ia/rpc.sock", raising=False)

    with pytest.raises(SessionTimeoutError, match="instrumentation event socket"):
        backend.start(
            "target.bin",
            [],
            None,
            {
                "launch": True,
                "qemu_user_path": "/usr/bin/qemu-x86_64",
                "instrumentation_socket_path": "/tmp/ia/events.sock",
                "instrumentation_rpc_socket_path": "/tmp/ia/rpc.sock",
            },
        )

    state = backend.get_state()
    assert state["session_status"] == "closed"
    assert runner.closed is True


def test_backend_start_timeout_includes_qemu_exit_summary() -> None:
    runner = FakeProcessRunner()
    runner.summary = "qemu-user exited with code 1; stderr: bind rpc socket failed"
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=FakeInstrumentationRpcClient(),
        process_runner=runner,
    )

    with pytest.raises(
        SessionTimeoutError,
        match=r"start timed out waiting for instrumentation rpc socket after 0.2s: /tmp/ia/rpc\.sock; qemu-user exited with code 1; stderr: bind rpc socket failed",
    ):
        backend._raise_launch_socket_timeout("/tmp/ia/rpc.sock", 0.2, "instrumentation rpc")


def test_backend_trace_file_mode_reads_events(tmp_path: Path) -> None:
    trace_file = tmp_path / "trace.ndjson"
    trace_file.write_text(
        "\n".join(
            [
                '{"event_id":"e-1","seq":1,"type":"branch","timestamp":1.0,"pc":"0x401000","thread_id":"1","cpu_id":0,"payload":{"target":"0x401010","taken":true}}',
                '{"event_id":"e-2","seq":2,"type":"basic_block","timestamp":1.1,"pc":"0x401010","thread_id":"1","cpu_id":0,"payload":{"start":"0x401010","end":"0x401012","instruction_count":1}}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=FakeInstrumentationRpcClient(None),
        process_runner=None,
    )

    backend.start(
        "target.bin",
        [],
        None,
        {
            "instrumentation_rpc_socket_path": "/tmp/rpc.sock",
            "instrumentation_trace_file_path": str(trace_file),
        },
    )
    backend.configure_event_filters(event_types=["branch"], address_ranges=None)
    trace = backend.get_trace(limit=10)
    events = backend.get_recent_events(limit=10, event_types=["branch"])

    assert trace["result"]["trace"] == [
        {"index": 0, "event_id": "e-1", "type": "branch", "pc": "0x401000", "thread_id": "1"},
        {"index": 1, "event_id": "e-2", "type": "basic_block", "pc": "0x401010", "thread_id": "1"},
    ]
    assert len(events["result"]["events"]) == 1
    assert events["result"]["events"][0]["event_id"] == "e-1"
    assert events["state"]["ingestion_stats"]["source"] == "trace_file"


def test_backend_get_state_reports_process_exit_code() -> None:
    runner = FakeProcessRunner()
    runner._process = ExitedProcess(139)
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=FakeInstrumentationClient(),
        instrumentation_rpc_client=FakeInstrumentationRpcClient(),
        process_runner=runner,
    )
    backend.start("target.bin", [], None, {"launch": True, "qemu_user_path": "/usr/bin/qemu-x86_64"})

    state = backend.get_state()

    assert state["session_status"] == "exited"
    assert state["exit_code"] == 139
    assert state["stop_reason"] == "exited"


def test_backend_write_stdin_allows_paused_session_state() -> None:
    runner = FakeProcessRunner()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=FakeInstrumentationClient(),
        instrumentation_rpc_client=FakeInstrumentationRpcClient(),
        process_runner=runner,
    )
    backend.start("target.bin", [], None, {"launch": True, "qemu_user_path": "/usr/bin/qemu-x86_64"})
    backend._state["session_status"] = "paused"
    result = backend.write_stdin("1\n")
    assert result["result"]["written"] == 2
    assert runner.stdin_writes == ["1\n"]


def test_backend_write_stdin_allows_idle_session_state() -> None:
    runner = FakeProcessRunner()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=FakeInstrumentationClient(),
        instrumentation_rpc_client=FakeInstrumentationRpcClient(),
        process_runner=runner,
    )
    backend.start("target.bin", [], None, {"launch": True, "qemu_user_path": "/usr/bin/qemu-x86_64"})
    backend._state["session_status"] = "idle"
    result = backend.write_stdin("1\n")
    assert result["result"]["written"] == 2
    assert runner.stdin_writes == ["1\n"]

def test_backend_write_stdin_symbolic_queues_chunk_before_write() -> None:
    runner = FakeProcessRunner()
    rpc = FakeInstrumentationRpcClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=FakeInstrumentationClient(),
        instrumentation_rpc_client=rpc,
        process_runner=runner,
    )
    backend.start("target.bin", [], None, {"launch": True, "qemu_user_path": "/usr/bin/qemu-x86_64"})
    backend._state["session_status"] = "paused"

    result = backend.write_stdin("abc", symbolic=True)

    assert result["result"]["written"] == 3
    assert result["result"]["symbolic"] is True
    assert rpc.requests[-1] == ("queue_stdin_chunk", {"size": 3, "symbolic": True})
    assert runner.stdin_writes == ["abc"]


def test_backend_write_stdin_mixed_chunks_preserve_queue_order() -> None:
    runner = FakeProcessRunner()
    rpc = FakeInstrumentationRpcClient()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=FakeInstrumentationClient(),
        instrumentation_rpc_client=rpc,
        process_runner=runner,
    )
    backend.start("target.bin", [], None, {"launch": True, "qemu_user_path": "/usr/bin/qemu-x86_64"})
    backend._state["session_status"] = "paused"

    backend.write_stdin("ab", symbolic=False)
    backend.write_stdin("cde", symbolic=True)

    assert rpc.requests[-2:] == [
        ("queue_stdin_chunk", {"size": 2, "symbolic": False}),
        ("queue_stdin_chunk", {"size": 3, "symbolic": True}),
    ]
    assert runner.stdin_writes == ["ab", "cde"]


def test_backend_close_stdin_signals_eof_without_rpc() -> None:
    rpc = FakeInstrumentationRpcClient()
    runner = FakeProcessRunner()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=None,
        instrumentation_rpc_client=rpc,
        process_runner=runner,
    )
    backend.start("target.bin", [], None, {})

    result = backend.close_stdin()

    assert result["result"]["closed"] is True
    assert result["result"]["already_closed"] is False
    assert runner.stdin_closed is True
    assert rpc.requests == []


def test_backend_write_stdin_symbolic_requires_rpc_channel() -> None:
    runner = FakeProcessRunner()
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=FakeInstrumentationClient(),
        instrumentation_rpc_client=None,
        process_runner=runner,
    )
    backend.start("target.bin", [], None, {})
    backend._state["session_status"] = "paused"

    with pytest.raises(UnsupportedOperationError, match="symbolic stdin queueing"):
        backend.write_stdin("abc", symbolic=True)


def test_backend_get_registers_uses_rpc_channel() -> None:
    instrumentation = FakeInstrumentationClient()
    rpc = FakeInstrumentationRpcClient(instrumentation)
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClient(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {})

    result = backend.get_registers(["rax"])

    assert result["result"]["registers"] == {"rax": "0x1", "rbx": "0x2", "rip": "0x401000"}
    assert rpc.requests[0] == ("get_registers", {"names": ["rax"]})
    assert result["state"]["registers"]["rip"] == "0x401000"
    assert result["state"]["pc"] == "0x401000"


def test_backend_get_symbolic_expression_uses_rpc_channel() -> None:
    instrumentation = FakeInstrumentationClient()
    rpc = FakeInstrumentationRpcClient(instrumentation)
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClient(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {})

    result = backend.get_symbolic_expression("0x3")

    assert result["result"]["label"] == "0x3"
    assert result["result"]["op"] == "Xor"
    assert "Add:i64" in result["result"]["expression"]
    assert rpc.requests[0] == ("get_symbolic_expression", {"label": "0x3"})


def test_backend_recent_path_constraints_uses_rpc_channel() -> None:
    instrumentation = FakeInstrumentationClient()
    rpc = FakeInstrumentationRpcClient(instrumentation)
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClient(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {})

    result = backend.recent_path_constraints(limit=4)

    assert result["result"]["count"] == 2
    assert result["result"]["constraints"][0]["label"] == "0x12"
    assert result["result"]["constraints"][0]["taken"] is True
    assert rpc.requests[0] == ("get_recent_path_constraints", {"limit": 4})


def test_backend_state_surfaces_symbolic_registers_and_recent_symbolic_pcs() -> None:
    instrumentation = FakeInstrumentationClient()
    rpc = FakeInstrumentationRpcClient(instrumentation)
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClient(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {})

    backend.get_registers(["rax", "rbx", "rip"])
    backend.recent_path_constraints(limit=4)

    state = backend.get_state()

    assert state["symbolic_registers"]["rbx"] == {"symbolic": True, "label": "0x20"}
    assert state["recent_symbolic_pcs"] == [
        {"pc": "0x401020", "label": "0x12", "taken": True, "op": "ICmp"},
        {"pc": "0x401010", "label": "0x6", "taken": True, "op": "ICmp"},
    ]


def test_backend_path_constraint_closure_uses_rpc_channel() -> None:
    instrumentation = FakeInstrumentationClient()
    rpc = FakeInstrumentationRpcClient(instrumentation)
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClient(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {})

    result = backend.path_constraint_closure("0x12")

    assert result["result"]["root"]["label"] == "0x12"
    assert result["result"]["root"]["taken"] is True
    assert result["result"]["constraints"][0]["label"] == "0x6"
    assert result["result"]["constraints"][0]["taken"] is True
    assert rpc.requests[0] == ("get_path_constraints", {"label": "0x12"})


def test_backend_read_memory_uses_rpc_channel() -> None:
    instrumentation = FakeInstrumentationClient()
    rpc = FakeInstrumentationRpcClient(instrumentation)
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClient(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {})

    result = backend.read_memory("0x401000", 2)

    assert result["result"] == {
        "address": "0x401000",
        "size": 2,
        "bytes": "0102",
        "symbolic_bytes": [
            {"offset": 0, "label": "0x0", "symbolic": False},
            {"offset": 1, "label": "0x44", "symbolic": True},
        ],
    }
    assert rpc.requests[0] == ("read_memory", {"address": "0x401000", "size": 2})


def test_backend_list_memory_maps_uses_rpc_channel() -> None:
    instrumentation = FakeInstrumentationClient()
    rpc = FakeInstrumentationRpcClient(instrumentation)
    backend = QemuUserInstrumentedBackend(
        qmp_client=FakeQmpClient(),
        instrumentation_client=instrumentation,
        instrumentation_rpc_client=rpc,
    )
    backend.start("target.bin", [], None, {})

    result = backend.list_memory_maps()

    assert result["result"]["maps"] == {"regions": [{"start": "0x400000", "end": "0x401000", "perm": "r-x", "name": None}]}
    assert rpc.requests[0] == ("list_memory_maps", {})
    assert result["state"]["memory_maps"] == [{"start": "0x400000", "end": "0x401000", "perm": "r-x", "name": None}]
