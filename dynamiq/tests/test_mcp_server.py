from __future__ import annotations

import atexit
import ctypes
import json
import signal

from dynamiq.errors import InvalidStateError, SessionTimeoutError
from dynamiq.mcp_server import InteractiveAnalysisMcpServer, _arm_parent_death_signal, _install_shutdown_hooks


class FakeSession:
    def __init__(self) -> None:
        self.started = False
        self.last_target = None
        self.last_args = None
        self.last_cwd = None
        self.last_qemu_config = None
        self.close_calls = 0
        self.stdin_written = b""
        self.stdin_closed = False
        self.stdout_cursors: list[int] = []
        self.stderr_cursors: list[int] = []

    def start(self, target, args=None, cwd=None, qemu_config=None):  # noqa: ANN001
        if self.started:
            raise InvalidStateError("session already started")
        self.started = True
        self.last_target = target
        self.last_args = args
        self.last_cwd = cwd
        self.last_qemu_config = qemu_config
        return {"ok": True, "command": "start", "result": {"target": target}}

    def close(self):
        self.started = False
        self.close_calls += 1
        return {"ok": True, "command": "close", "result": {}}

    def capabilities(self):
        return {"ok": True, "command": "capabilities", "result": {"capabilities": {"read_memory": True}}}

    def get_state(self):
        return {"ok": True, "command": "get_state", "result": {"session_status": "paused"}}

    def symbols(self, max_count=500, name_filter=None, module_filter=None, include_modules=False):  # noqa: ANN001
        return {
            "ok": True,
            "command": "symbols",
            "result": {
                "target": "/tmp/a.out",
                "elf_type": "EXEC",
                "load_base": "0x0",
                "symbols": [{"name": "main", "loaded_address": "0x401000"}],
                "max_count": max_count,
                "name_filter": name_filter,
                "module_filter": module_filter,
                "include_modules": include_modules,
            },
        }

    def resume(self, timeout=5.0):  # noqa: ANN001
        return {"ok": True, "command": "resume", "result": {"timeout": timeout}}

    def pause(self, timeout=5.0):  # noqa: ANN001
        return {"ok": True, "command": "pause", "result": {"timeout": timeout}}

    def advance(self, mode, count=None, timeout=5.0):  # noqa: ANN001
        result = {"mode": mode, "timeout": timeout, "completed": mode != "continue", "stop_reason": "target_reached"}
        if count is not None:
            result["requested_count"] = count
            result["actual_count"] = count
        return {"ok": True, "command": "advance", "result": result}

    def get_registers(self, names=None):  # noqa: ANN001
        return {
            "ok": True,
            "command": "get_registers",
            "result": {
                "registers": {"rip": "0x401000"},
                "symbolic_registers": {"rip": {"symbolic": False, "label": "0x0"}},
            },
        }

    def backtrace(self, max_frames=16):  # noqa: ANN001
        return {
            "ok": True,
            "command": "backtrace",
            "result": {"frames": [{"index": 0, "pc": "0x401000", "symbol": "main", "offset": 0}], "max_frames": max_frames},
        }

    def disassemble(self, address, count=16):  # noqa: ANN001
        return {"ok": True, "command": "disassemble", "result": {"instructions": [{"address": address, "size": count}]}}

    def read_memory(self, address, size):  # noqa: ANN001
        return {
            "ok": True,
            "command": "read_memory",
            "result": {
                "address": address,
                "size": size,
                "bytes": "00",
                "symbolic_bytes": [{"offset": 0, "label": "0x0", "symbolic": False}],
            },
        }

    def symbolize_memory(self, address, size, name=None):  # noqa: ANN001
        return {
            "ok": True,
            "command": "symbolize_memory",
            "result": {"address": address, "size": size, "name": name, "bytes": [{"offset": 0, "label": "0x41", "symbolic": True}]},
        }

    def symbolize_register(self, register, name=None):  # noqa: ANN001
        return {
            "ok": True,
            "command": "symbolize_register",
            "result": {"register": register, "name": name, "label": "0x42", "symbolic": True},
        }

    def get_symbolic_expression(self, label):  # noqa: ANN001
        return {
            "ok": True,
            "command": "get_symbolic_expression",
            "result": {
                "label": label,
                "expression": "Xor:i64(0x22:i64, Add:i64(0x11:i64, input(0):i8))",
                "op": "Xor",
                "size": 64,
            },
        }

    def recent_path_constraints(self, limit=16):  # noqa: ANN001
        return {
            "ok": True,
            "command": "recent_path_constraints",
            "result": {
                "constraints": [
                    {
                        "label": "0x12",
                        "pc": "0x401050",
                        "taken": True,
                        "expression": "ICmp:eq(input(0), 0x41)",
                        "op": "ICmp",
                    }
                ],
                "count": 1,
                "truncated": False,
            },
        }

    def path_constraint_closure(self, label):  # noqa: ANN001
        return {
            "ok": True,
            "command": "path_constraint_closure",
            "result": {
                "root": {"label": label, "expression": "ICmp:eq(input(0), 0x41)", "op": "ICmp", "taken": True},
                "constraints": [{"label": "0x6", "expression": "ICmp:ult(input(0), 0x80)", "op": "ICmp", "taken": True}],
                "count": 1,
            },
        }

    def list_memory_maps(self):
        return {"ok": True, "command": "list_memory_maps", "result": {"maps": {"regions": []}}}

    def run_until_address(self, address, timeout=5.0):  # noqa: ANN001
        return {"ok": True, "command": "run_until_address", "result": {"matched_address": address, "timeout": timeout}}

    def step(self, count=1, timeout=5.0):  # noqa: ANN001
        return {"ok": True, "command": "step", "result": {"count": count, "timeout": timeout}}

    def advance_basic_blocks(self, count=1, timeout=5.0):  # noqa: ANN001
        return {"ok": True, "command": "advance_basic_blocks", "result": {"count": count, "timeout": timeout}}

    def write_stdin(self, data, symbolic=False):  # noqa: ANN001
        if isinstance(data, str):
            payload = data.encode("utf-8")
        else:
            payload = data
        self.stdin_written += payload
        return {"ok": True, "command": "write_stdin", "result": {"written": len(payload), "symbolic": symbolic}}

    def close_stdin(self):
        already_closed = self.stdin_closed
        self.stdin_closed = True
        return {"ok": True, "command": "close_stdin", "result": {"closed": True, "already_closed": already_closed}}

    def read_stdout(self, cursor=0, max_chars=4096):  # noqa: ANN001
        self.stdout_cursors.append(cursor)
        return {"ok": True, "command": "read_stdout", "result": {"data": "abc", "cursor": cursor + 3, "eof": False, "max_chars": max_chars}}

    def read_stderr(self, cursor=0, max_chars=4096):  # noqa: ANN001
        self.stderr_cursors.append(cursor)
        return {"ok": True, "command": "read_stderr", "result": {"data": "", "cursor": cursor, "eof": False, "max_chars": max_chars}}

    def bp_add(self, address):  # noqa: ANN001
        return {"ok": True, "command": "bp_add", "result": {"address": address, "breakpoints": [address]}}

    def bp_del(self, address):  # noqa: ANN001
        return {"ok": True, "command": "bp_del", "result": {"address": address, "breakpoints": []}}

    def bp_list(self):
        return {"ok": True, "command": "bp_list", "result": {"breakpoints": []}}

    def bp_clear(self):
        return {"ok": True, "command": "bp_clear", "result": {"breakpoints": []}}

    def bp_run(self, timeout=5.0, max_steps=10000):  # noqa: ANN001
        del max_steps
        return {
            "ok": True,
            "command": "bp_run",
            "result": {"matched_address": "0x401000", "selected_address": "0x401000", "steps": 0, "timeout": timeout},
        }

    def trace_start(self, event_types=None, address_ranges=None):  # noqa: ANN001
        return {
            "ok": True,
            "command": "trace_start",
            "result": {
                "filters": {
                    "event_types": list(event_types or []),
                    "address_ranges": list(address_ranges or []),
                },
                "trace_active": True,
                "trace_start_head": 0,
            },
        }

    def trace_stop(self):
        return {"ok": True, "command": "trace_stop", "result": {"trace_active": False, "trace_start_head": 0}}

    def trace_status(self):
        return {
            "ok": True,
            "command": "trace_status",
            "result": {"trace_active": True, "trace_event_types": ["branch"], "trace_address_ranges": [], "trace_start_head": 0, "trace_head": 3},
        }

    def trace_get(self, limit=100, since_start=True):  # noqa: ANN001
        return {
            "ok": True,
            "command": "trace_get",
            "result": {"trace": [{"index": 0, "event_id": "e-1", "type": "branch"}], "limit": limit, "since_start": since_start},
        }

def _server() -> InteractiveAnalysisMcpServer:
    return InteractiveAnalysisMcpServer(session_factory=FakeSession)


def test_mcp_initialize() -> None:
    server = _server()
    response = server.handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert response is not None
    assert response["result"]["serverInfo"]["name"] == "dynamiq"
    assert "tools" in response["result"]["capabilities"]


def test_mcp_tools_list_contains_short_names() -> None:
    server = _server()
    response = server.handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    assert response is not None
    names = {item["name"] for item in response["result"]["tools"]}
    assert "start" in names
    assert "advance" in names
    assert "syms" in names
    assert "pause" in names
    assert "send_bytes" in names
    assert "send_line" in names
    assert "close_stdin" in names
    assert "stdout" in names
    assert "bp_add" in names
    assert "trace_start" in names
    assert "trace_stop" in names
    assert "trace_status" in names
    assert "trace_get" in names
    assert "symbolize_mem" in names
    assert "symbolize_reg" in names
    assert "expr" in names
    assert "recent_path_constraints" in names
    assert "path_constraint_closure" in names
    assert "bt" in names
    assert "bp_list" in names
    assert "stdin" not in names
    assert "stdin_file" not in names
    assert "until" not in names
    assert "bp_run" not in names


def test_mcp_tool_schemas_do_not_use_top_level_combinators() -> None:
    server = _server()
    response = server.handle_request({"jsonrpc": "2.0", "id": 21, "method": "tools/list", "params": {}})
    assert response is not None

    forbidden = {"oneOf", "allOf", "anyOf"}
    offenders = [
        tool["name"]
        for tool in response["result"]["tools"]
        if forbidden.intersection(tool["inputSchema"].keys())
    ]
    assert offenders == []


def test_mcp_inspection_tools_document_terminal_pause_reads() -> None:
    server = _server()
    response = server.handle_request({"jsonrpc": "2.0", "id": 22, "method": "tools/list", "params": {}})
    assert response is not None

    tools = {tool["name"]: tool for tool in response["result"]["tools"]}
    for name in ["state", "advance", "regs", "bt", "disasm", "mem"]:
        description = tools[name]["description"]
        assert "pending_termination=true" in description or "termination_pending" in description
    assert "do not skip memory reads" in tools["mem"]["description"]


def test_mcp_tool_call_start() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "start",
                "arguments": {"target": "/tmp/a.out", "args": ["x"]},
            },
        }
    )
    assert response is not None
    result = response["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["result"]["target"] == "/tmp/a.out"


def test_mcp_tool_call_symbolize_memory() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {
                "name": "symbolize_mem",
                "arguments": {"address": "0x401000", "size": 4, "name": "buf"},
            },
        }
    )
    assert response is not None
    result = response["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["result"]["address"] == "0x401000"


def test_mcp_tool_call_expr() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 32,
            "method": "tools/call",
            "params": {
                "name": "expr",
                "arguments": {"label": "0x3"},
            },
        }
    )
    assert response is not None
    result = response["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["result"]["label"] == "0x3"
    assert "Add:i64" in result["structuredContent"]["result"]["expression"]


def test_mcp_tool_call_recent_path_constraints() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 33,
            "method": "tools/call",
            "params": {
                "name": "recent_path_constraints",
                "arguments": {"limit": 4},
            },
        }
    )
    assert response is not None
    result = response["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["command"] == "recent_path_constraints"
    assert result["structuredContent"]["result"]["constraints"][0]["label"] == "0x12"


def test_mcp_tool_call_path_constraint_closure() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 34,
            "method": "tools/call",
            "params": {
                "name": "path_constraint_closure",
                "arguments": {"label": "0x12"},
            },
        }
    )
    assert response is not None
    result = response["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["command"] == "path_constraint_closure"
    assert result["structuredContent"]["result"]["root"]["taken"] is True
    assert result["structuredContent"]["result"]["constraints"][0]["taken"] is True
    assert result["structuredContent"]["result"]["root"]["label"] == "0x12"


def test_mcp_tool_call_symbolize_register() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 32,
            "method": "tools/call",
            "params": {
                "name": "symbolize_reg",
                "arguments": {"register": "rax", "name": "acc"},
            },
        }
    )
    assert response is not None
    result = response["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["result"]["register"] == "rax"


def test_mcp_tool_call_start_rejects_empty_target() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 300,
            "method": "tools/call",
            "params": {
                "name": "start",
                "arguments": {"target": "   "},
            },
        }
    )
    assert response is not None
    assert response["result"]["isError"] is True
    text = response["result"]["content"][0]["text"]
    assert "non-empty" in text


def test_mcp_tool_call_start_rejects_malformed_placeholder_target() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 302,
            "method": "tools/call",
            "params": {
                "name": "start",
                "arguments": {"target": ","},
            },
        }
    )
    assert response is not None
    assert response["result"]["isError"] is True
    text = response["result"]["content"][0]["text"]
    assert "target appears malformed" in text


def test_mcp_tool_call_start_rejects_invalid_args_type() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 301,
            "method": "tools/call",
            "params": {"name": "start", "arguments": {"target": "/tmp/a.out", "args": "oops"}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is True
    text = response["result"]["content"][0]["text"]
    assert "args must be an array of strings" in text


def test_mcp_tool_call_start_defaults_launch_true() -> None:
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {
                "name": "start",
                "arguments": {"target": "/tmp/a.out"},
            },
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert fake.last_qemu_config == {"launch": True}


def test_mcp_tool_call_start_accepts_qemu_launch_config() -> None:
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 32,
            "method": "tools/call",
            "params": {
                "name": "start",
                "arguments": {
                    "target": "/tmp/android_root/lib64/toybox",
                    "args": ["echo", "test"],
                    "cwd": "/tmp/android_root",
                    "qemu_user_path": "/opt/symfit/symfit-aarch64",
                    "qemu_args": ["-L", "."],
                    "env": {
                        "QEMU_LD_PREFIX": ".",
                        "LD_LIBRARY_PATH": "./lib64",
                    },
                },
            },
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert fake.last_target == "/tmp/android_root/lib64/toybox"
    assert fake.last_args == ["echo", "test"]
    assert fake.last_cwd == "/tmp/android_root"
    assert fake.last_qemu_config == {
        "launch": True,
        "qemu_user_path": "/opt/symfit/symfit-aarch64",
        "qemu_args": ["-L", "."],
        "env": {
            "QEMU_LD_PREFIX": ".",
            "LD_LIBRARY_PATH": "./lib64",
        },
    }


def test_mcp_tool_call_start_uses_server_locked_qemu_path(monkeypatch) -> None:  # noqa: ANN001
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    monkeypatch.setenv("DYNAMIQ_MCP_QEMU_USER_PATH", "/opt/symfit/symfit-x86_64")

    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 33,
            "method": "tools/call",
            "params": {
                "name": "start",
                "arguments": {"target": "/tmp/a.out"},
            },
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert fake.last_qemu_config == {"launch": True, "qemu_user_path": "/opt/symfit/symfit-x86_64"}


def test_mcp_tool_call_start_auto_restarts_existing_session() -> None:
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    first = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 41,
            "method": "tools/call",
            "params": {"name": "start", "arguments": {"target": "/tmp/a.out"}},
        }
    )
    assert first is not None and first["result"]["isError"] is False
    second = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {"name": "start", "arguments": {"target": "/tmp/b.out"}},
        }
    )
    assert second is not None
    assert second["result"]["isError"] is False
    assert fake.close_calls == 1


def test_mcp_tool_call_bt() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {
                "name": "bt",
                "arguments": {"max_frames": 8},
            },
        }
    )
    assert response is not None
    result = response["result"]
    assert result["isError"] is False
    payload = result["structuredContent"]
    assert payload["command"] == "backtrace"
    assert payload["result"]["frames"][0]["symbol"] == "main"


def test_mcp_server_shutdown_closes_active_session() -> None:
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 51,
            "method": "tools/call",
            "params": {"name": "start", "arguments": {"target": "/tmp/a.out"}},
        }
    )
    server.shutdown()
    assert fake.close_calls == 1


def test_arm_parent_death_signal_uses_prctl_on_linux(monkeypatch) -> None:
    calls: list[tuple[int, int, int, int, int]] = []

    class FakeLibC:
        def __init__(self) -> None:
            self.prctl = self._prctl

        @staticmethod
        def _prctl(arg0: int, arg1: int, arg2: int, arg3: int, arg4: int) -> int:
            calls.append((arg0, arg1, arg2, arg3, arg4))
            return 0

    monkeypatch.setattr("dynamiq.mcp_server.sys.platform", "linux")
    monkeypatch.setattr(ctypes, "CDLL", lambda _: FakeLibC())

    _arm_parent_death_signal()

    assert calls == [(1, signal.SIGTERM, 0, 0, 0)]


def test_install_shutdown_hooks_registers_atexit_and_signal_handlers(monkeypatch) -> None:
    server = InteractiveAnalysisMcpServer(session_factory=FakeSession)
    registered = {"atexit": None, "signals": []}

    monkeypatch.setattr(atexit, "register", lambda fn: registered.__setitem__("atexit", fn))
    monkeypatch.setattr(signal, "signal", lambda signum, handler: registered["signals"].append((signum, handler)))

    _install_shutdown_hooks(server)

    assert registered["atexit"] == server.shutdown
    assert [signum for signum, _handler in registered["signals"]] == [signal.SIGINT, signal.SIGTERM]


def test_mcp_tool_call_unknown_tool_returns_error() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "nope", "arguments": {}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is True


def test_mcp_tool_call_send_bytes() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 55,
            "method": "tools/call",
            "params": {"name": "send_bytes", "arguments": {"data": "abc"}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert response["result"]["structuredContent"]["result"]["written"] == 3


def test_mcp_tool_call_send_bytes_symbolic() -> None:
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 551,
            "method": "tools/call",
            "params": {"name": "send_bytes", "arguments": {"data": "abc", "symbolic": True}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert response["result"]["structuredContent"]["result"]["symbolic"] is True


def test_mcp_tool_call_send_line_appends_newline() -> None:
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 56,
            "method": "tools/call",
            "params": {"name": "send_line", "arguments": {"line": "hello"}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert fake.stdin_written == b"hello\n"


def test_mcp_tool_call_send_line_without_line_sends_newline_only() -> None:
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 57,
            "method": "tools/call",
            "params": {"name": "send_line", "arguments": {}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert fake.stdin_written == b"\n"


def test_mcp_tool_call_send_file(tmp_path) -> None:  # noqa: ANN001
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    payload = tmp_path / "payload.bin"
    payload.write_bytes(b"A\n\x80\xffB")

    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 575,
            "method": "tools/call",
            "params": {
                "name": "send_file",
                "arguments": {"path": str(payload), "append_newline": True},
            },
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert fake.stdin_written == b"A\n\x80\xffB\n"
    assert response["result"]["structuredContent"]["written"] == 6


def test_mcp_tool_call_close_stdin() -> None:
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 576,
            "method": "tools/call",
            "params": {"name": "close_stdin", "arguments": {}},
        }
    )

    assert response is not None
    assert response["result"]["isError"] is False
    assert fake.stdin_closed is True
    assert response["result"]["structuredContent"]["command"] == "close_stdin"
    assert response["result"]["structuredContent"]["result"]["closed"] is True


def test_mcp_tool_call_send_bytes_data_hex() -> None:
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 576,
            "method": "tools/call",
            "params": {"name": "send_bytes", "arguments": {"data_hex": "040000000680ffffffffffff"}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert fake.stdin_written == bytes.fromhex("040000000680ffffffffffff")
    assert response["result"]["structuredContent"]["result"]["written"] == 12


def test_mcp_tool_call_advance_rejects_nonpositive_timeout() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 577,
            "method": "tools/call",
            "params": {"name": "advance", "arguments": {"mode": "continue", "timeout": 0}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is True
    text = response["result"]["content"][0]["text"]
    assert "timeout must be > 0" in text


def test_mcp_tool_call_regs_rejects_non_string_names() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 578,
            "method": "tools/call",
            "params": {"name": "regs", "arguments": {"names": ["rip", 1]}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is True
    text = response["result"]["content"][0]["text"]
    assert "names must be an array of strings" in text


def test_mcp_tool_call_mem_rejects_negative_size() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 579,
            "method": "tools/call",
            "params": {"name": "mem", "arguments": {"address": "0x401000", "size": -1}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is True
    text = response["result"]["content"][0]["text"]
    assert "size must be >= 0" in text


def test_mcp_stdout_uses_internal_cursor_progression() -> None:
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    first = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 58,
            "method": "tools/call",
            "params": {"name": "stdout", "arguments": {"max_chars": 16}},
        }
    )
    second = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 59,
            "method": "tools/call",
            "params": {"name": "stdout", "arguments": {"max_chars": 16}},
        }
    )
    assert first is not None and second is not None
    assert fake.stdout_cursors == [0, 3]


def test_mcp_stdout_rejects_negative_wait_ms() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 580,
            "method": "tools/call",
            "params": {"name": "stdout", "arguments": {"wait_ms": -1}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is True
    text = response["result"]["content"][0]["text"]
    assert "wait_ms must be >= 0" in text


def test_mcp_tool_call_advance_continue() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {"name": "advance", "arguments": {"mode": "continue", "timeout": 1.5}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert response["result"]["structuredContent"]["command"] == "advance"
    assert response["result"]["structuredContent"]["result"]["mode"] == "continue"


def test_mcp_advance_caps_long_timeout_for_polling() -> None:
    fake = FakeSession()
    server = InteractiveAnalysisMcpServer(session_factory=lambda: fake)
    server._max_advance_timeout = 2.5

    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 72,
            "method": "tools/call",
            "params": {"name": "advance", "arguments": {"mode": "continue", "timeout": 120}},
        }
    )

    assert response is not None
    assert response["result"]["isError"] is False
    result = response["result"]["structuredContent"]["result"]
    assert result["timeout"] == 2.5
    assert result["requested_timeout"] == 120
    assert result["effective_timeout"] == 2.5
    assert result["timeout_capped"] is True


def test_mcp_tool_call_advance_insn() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 601,
            "method": "tools/call",
            "params": {"name": "advance", "arguments": {"mode": "insn", "count": 3, "timeout": 1.5}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    payload = response["result"]["structuredContent"]
    assert payload["command"] == "advance"
    assert payload["result"]["mode"] == "insn"
    assert payload["result"]["requested_count"] == 3


def test_mcp_tool_call_advance_return() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 6011,
            "method": "tools/call",
            "params": {"name": "advance", "arguments": {"mode": "return", "timeout": 1.5}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    payload = response["result"]["structuredContent"]
    assert payload["command"] == "advance"
    assert payload["result"]["mode"] == "return"


def test_mcp_tool_call_advance_rejects_count_for_continue() -> None:
    class InvalidCountSession(FakeSession):
        def advance(self, mode, count=None, timeout=5.0):  # noqa: ANN001
            del timeout
            if mode == "continue" and count is not None:
                raise InvalidStateError("advance count is only valid for insn and bb modes")
            return super().advance(mode=mode, count=count, timeout=5.0)

    server = InteractiveAnalysisMcpServer(session_factory=InvalidCountSession)
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 6012,
            "method": "tools/call",
            "params": {"name": "advance", "arguments": {"mode": "continue", "count": 1, "timeout": 1.5}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is True
    text = response["result"]["content"][0]["text"]
    assert "only valid for insn and bb modes" in text


def test_mcp_tool_call_advance_timeout_is_non_fatal() -> None:
    class TimeoutSession(FakeSession):
        def advance(self, mode, count=None, timeout=5.0):  # noqa: ANN001
            del mode, count
            raise SessionTimeoutError(f"timed out waiting for advance condition ({timeout}s)")

    server = InteractiveAnalysisMcpServer(session_factory=TimeoutSession)
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 602,
            "method": "tools/call",
            "params": {"name": "advance", "arguments": {"mode": "continue", "timeout": 2.0}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    text_payload = json.loads(response["result"]["content"][0]["text"])
    assert text_payload["command"] == "advance"
    assert text_payload["ok"] is False
    assert text_payload["result"]["timed_out"] is True
    payload = response["result"]["structuredContent"]
    assert payload["command"] == "advance"
    assert payload["result"]["timed_out"] is True
    assert payload["result"]["timeout"] == 2.0


def test_mcp_tool_call_trace_start_with_filters() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 610,
            "method": "tools/call",
            "params": {
                "name": "trace_start",
                "arguments": {
                    "event_types": ["branch", "basic_block"],
                    "address_ranges": [{"start": "0x401000", "end": "0x401100"}],
                },
            },
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    payload = response["result"]["structuredContent"]
    assert payload["command"] == "trace_start"
    assert payload["result"]["filters"]["event_types"] == ["branch", "basic_block"]
    assert payload["result"]["filters"]["address_ranges"] == [("0x401000", "0x401100")]


def test_mcp_tool_call_trace_status_and_get() -> None:
    server = _server()
    status_response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 611,
            "method": "tools/call",
            "params": {"name": "trace_status", "arguments": {}},
        }
    )
    get_response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 612,
            "method": "tools/call",
            "params": {"name": "trace_get", "arguments": {"limit": 20, "since_start": False}},
        }
    )
    stop_response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 613,
            "method": "tools/call",
            "params": {"name": "trace_stop", "arguments": {}},
        }
    )
    assert status_response is not None and get_response is not None and stop_response is not None
    assert status_response["result"]["structuredContent"]["command"] == "trace_status"
    assert get_response["result"]["structuredContent"]["command"] == "trace_get"
    assert get_response["result"]["structuredContent"]["result"]["since_start"] is False
    assert stop_response["result"]["structuredContent"]["command"] == "trace_stop"


def test_mcp_trace_start_rejects_malformed_address_ranges() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 614,
            "method": "tools/call",
            "params": {
                "name": "trace_start",
                "arguments": {"address_ranges": [{"start": "0x401000"}]},
            },
        }
    )
    assert response is not None
    assert response["result"]["isError"] is True
    text = response["result"]["content"][0]["text"]
    assert "address_ranges[0].end must be a non-empty string" in text


def test_mcp_tool_call_pause_timeout_is_non_fatal() -> None:
    class TimeoutSession(FakeSession):
        def pause(self, timeout=5.0):  # noqa: ANN001
            raise SessionTimeoutError(f"timed out waiting for pause acknowledgement ({timeout}s)")

    server = InteractiveAnalysisMcpServer(session_factory=TimeoutSession)
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 603,
            "method": "tools/call",
            "params": {"name": "pause", "arguments": {"timeout": 2.0}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    text_payload = json.loads(response["result"]["content"][0]["text"])
    assert text_payload["command"] == "pause"
    assert text_payload["ok"] is False
    assert text_payload["result"]["timed_out"] is True
    payload = response["result"]["structuredContent"]
    assert payload["command"] == "pause"
    assert payload["result"]["timed_out"] is True
    assert payload["result"]["timeout"] == 2.0


def test_mcp_tool_call_bp_add() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 81,
            "method": "tools/call",
            "params": {"name": "bp_add", "arguments": {"address": "0x401000"}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert response["result"]["structuredContent"]["result"]["address"] == "0x401000"


def test_mcp_tool_call_syms() -> None:
    server = _server()
    response = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 91,
            "method": "tools/call",
            "params": {"name": "syms", "arguments": {"max_count": 10, "name_filter": "main"}},
        }
    )
    assert response is not None
    assert response["result"]["isError"] is False
    assert response["result"]["structuredContent"]["result"]["symbols"][0]["name"] == "main"


def test_mcp_state_and_streams_include_json_text_for_text_only_clients() -> None:
    server = _server()
    state = server.handle_request(
        {"jsonrpc": "2.0", "id": 901, "method": "tools/call", "params": {"name": "state", "arguments": {}}}
    )
    stdout = server.handle_request(
        {"jsonrpc": "2.0", "id": 902, "method": "tools/call", "params": {"name": "stdout", "arguments": {}}}
    )
    assert state is not None and stdout is not None
    state_text = state["result"]["content"][0]["text"]
    stdout_text = stdout["result"]["content"][0]["text"]
    state_payload = json.loads(state_text)
    stdout_payload = json.loads(stdout_text)
    assert state_payload["command"] == "get_state"
    assert state_payload["result"]["session_status"] == "paused"
    assert stdout_payload["command"] == "read_stdout"
    assert stdout_payload["result"]["data"] == "abc"


def test_mcp_syms_includes_json_text_for_text_only_clients() -> None:
    server = _server()
    syms = server.handle_request(
        {"jsonrpc": "2.0", "id": 903, "method": "tools/call", "params": {"name": "syms", "arguments": {}}}
    )
    assert syms is not None
    syms_text = syms["result"]["content"][0]["text"]
    syms_payload = json.loads(syms_text)
    assert syms_payload["command"] == "symbols"
    assert syms_payload["result"]["symbols"][0]["loaded_address"] == "0x401000"


def test_mcp_bp_add_includes_json_text_for_text_only_clients() -> None:
    server = _server()
    result = server.handle_request(
        {
            "jsonrpc": "2.0",
            "id": 904,
            "method": "tools/call",
            "params": {"name": "bp_add", "arguments": {"address": "0x401000"}},
        }
    )
    assert result is not None
    text_payload = json.loads(result["result"]["content"][0]["text"])
    assert text_payload["command"] == "bp_add"
    assert text_payload["ok"] is True
    assert text_payload["result"]["address"] == "0x401000"
