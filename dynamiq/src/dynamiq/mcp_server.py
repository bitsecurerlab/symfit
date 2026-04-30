from __future__ import annotations

import argparse
import atexit
import ctypes
import json
import os
import signal
import sys
import time
from pathlib import Path
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .backends.qemu_user_instrumented import QemuUserInstrumentedBackend
from .errors import InvalidStateError, SessionTimeoutError
from .session import AnalysisSession


JSON = dict[str, Any]

MCP_PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "dynamiq"
SERVER_VERSION = "0.1.0"
MCP_LOCKED_QEMU_PATH_ENV = "DYNAMIQ_MCP_QEMU_USER_PATH"


def _teardown_log(message: str) -> None:
    if not os.getenv("DYNAMIQ_DEBUG_TEARDOWN"):
        return
    try:
        with open("/tmp/dynamiq-teardown.log", "a", encoding="utf-8") as stream:
            stream.write(f"mcp_server pid={os.getpid()} {message}\n")
    except Exception:
        pass


def _debug_log(message: str) -> None:
    if not os.getenv("DYNAMIQ_DEBUG_MCP"):
        return
    try:
        with open("/tmp/dynamiq-mcp-debug.log", "a", encoding="utf-8") as stream:
            stream.write(f"mcp_server pid={os.getpid()} {message}\n")
    except Exception:
        pass
_PR_SET_PDEATHSIG = 1


@dataclass(slots=True)
class ToolSpec:
    name: str
    description: str
    input_schema: JSON

    def to_mcp(self) -> JSON:
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


class InteractiveAnalysisMcpServer:
    def __init__(self, session_factory: Callable[[], AnalysisSession] | None = None) -> None:
        self._session_factory = session_factory or (lambda: AnalysisSession(backend=QemuUserInstrumentedBackend()))
        self._session: AnalysisSession | None = None
        self._stdout_cursor = 0
        self._stderr_cursor = 0
        self._tools: dict[str, ToolSpec] = {tool.name: tool for tool in self._build_tools()}

    def handle_request(self, request: JSON) -> JSON | None:
        method = request.get("method")
        request_id = request.get("id")
        params = request.get("params")
        params_dict = params if isinstance(params, dict) else {}

        if not isinstance(method, str):
            if request_id is None:
                return None
            return self._error(request_id, -32600, "invalid request: method must be a string")

        if method == "initialize":
            if request_id is None:
                return None
            return self._ok(
                request_id,
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
                    "capabilities": {"tools": {}},
                },
            )

        if method == "notifications/initialized":
            return None

        if method == "tools/list":
            if request_id is None:
                return None
            return self._ok(request_id, {"tools": [tool.to_mcp() for tool in self._tools.values()]})

        if method == "tools/call":
            if request_id is None:
                return None
            name = params_dict.get("name")
            arguments = params_dict.get("arguments")
            if not isinstance(name, str):
                return self._error(request_id, -32602, "tools/call: missing tool name")
            if arguments is None:
                arguments_dict: JSON = {}
            elif isinstance(arguments, dict):
                arguments_dict = arguments
            else:
                return self._error(request_id, -32602, "tools/call: arguments must be an object")
            return self._ok(request_id, self._call_tool(name, arguments_dict))

        if method == "ping":
            if request_id is None:
                return None
            return self._ok(request_id, {})

        if request_id is None:
            return None
        return self._error(request_id, -32601, f"method not found: {method}")

    def _ensure_session(self) -> AnalysisSession:
        if self._session is None:
            self._session = self._session_factory()
        return self._session

    def _call_tool(self, name: str, arguments: JSON) -> JSON:
        if name not in self._tools:
            return self._tool_error(f"unknown tool: {name}")

        _debug_log(f"tool call name={name} args={arguments!r} has_session={self._session is not None}")
        try:
            if name == "start":
                session = self._ensure_session()
                qemu_config: JSON = {"launch": True}
                locked_qemu_path = os.getenv(MCP_LOCKED_QEMU_PATH_ENV)
                if isinstance(locked_qemu_path, str) and locked_qemu_path.strip():
                    qemu_config["qemu_user_path"] = locked_qemu_path.strip()
                target_value = arguments.get("target")
                if not isinstance(target_value, str) or target_value.strip() == "":
                    return self._tool_error(
                        "start requires non-empty string argument `target` "
                        '(example: {"target":"/path/to/target_binary"})'
                    )
                target = target_value.strip()
                # Reject malformed placeholder-like targets early to avoid
                # entering launch/connect timeout paths.
                if not self._looks_like_path_token(target):
                    return self._tool_error(
                        "start target appears malformed. "
                        "Provide a real target path."
                    )
                args = self._parse_string_list(arguments, "args", default=[])
                cwd = self._parse_optional_string(arguments, "cwd", default=None)
                qemu_user_path = self._parse_optional_string(arguments, "qemu_user_path", default=None)
                if isinstance(qemu_user_path, str) and qemu_user_path.strip():
                    qemu_config["qemu_user_path"] = qemu_user_path.strip()
                qemu_args = self._parse_string_list(arguments, "qemu_args", default=[])
                if qemu_args:
                    qemu_config["qemu_args"] = qemu_args
                env = self._parse_string_map(arguments, "env", default={})
                if env:
                    qemu_config["env"] = env
                try:
                    result = session.start(
                        target=target,
                        args=args,
                        cwd=cwd,
                        qemu_config=qemu_config,
                    )
                except InvalidStateError as exc:
                    if "session already started" not in str(exc):
                        raise
                    session.close()
                    result = session.start(
                        target=target,
                        args=args,
                        cwd=cwd,
                        qemu_config=qemu_config,
                    )
                self._reset_stream_cursors()
                return self._tool_ok(result)

            if name == "close":
                session = self._ensure_session()
                result = session.close()
                self._reset_stream_cursors()
                return self._tool_ok(result)

            if name == "caps":
                return self._tool_ok(self._ensure_session().capabilities())
            if name == "state":
                return self._tool_ok(self._ensure_session().get_state())
            if name == "syms":
                max_count = self._parse_int(arguments, "max_count", default=500, minimum=1)
                name_filter = self._parse_optional_string(arguments, "name_filter", default=None)
                return self._tool_ok(
                    self._ensure_session().symbols(
                        max_count=max_count,
                        name_filter=name_filter,
                    )
                )
            if name == "advance":
                timeout = self._parse_positive_float(arguments, "timeout", default=5.0)
                mode = self._parse_nonempty_string(arguments, "mode")
                count = arguments.get("count")
                if count is not None:
                    count = self._parse_int(arguments, "count", required=True, minimum=1)
                try:
                    return self._tool_ok(self._ensure_session().advance(mode=mode, count=count, timeout=timeout))
                except SessionTimeoutError as exc:
                    return self._tool_timeout(command="advance", timeout=timeout, message=str(exc))
            if name == "pause":
                timeout = self._parse_positive_float(arguments, "timeout", default=5.0)
                try:
                    return self._tool_ok(self._ensure_session().pause(timeout=timeout))
                except SessionTimeoutError as exc:
                    return self._tool_timeout(command="pause", timeout=timeout, message=str(exc))
            if name == "regs":
                names = self._parse_optional_string_list(arguments, "names", default=None)
                return self._tool_ok(self._ensure_session().get_registers(names))
            if name == "bt":
                max_frames = self._parse_int(arguments, "max_frames", default=16, minimum=1)
                return self._tool_ok(self._ensure_session().backtrace(max_frames=max_frames))
            if name == "disasm":
                address = self._parse_nonempty_string(arguments, "address")
                count = self._parse_int(arguments, "count", default=16, minimum=1)
                return self._tool_ok(
                    self._ensure_session().disassemble(
                        address=address,
                        count=count,
                    )
                )
            if name == "mem":
                address = self._parse_nonempty_string(arguments, "address")
                size = self._parse_int(arguments, "size", required=True, minimum=0)
                return self._tool_ok(
                    self._ensure_session().read_memory(
                        address=address,
                        size=size,
                    )
                )
            if name == "symbolize_mem":
                address = self._parse_nonempty_string(arguments, "address")
                size = self._parse_int(arguments, "size", required=True, minimum=1)
                label_name = self._parse_optional_string(arguments, "name", default=None)
                return self._tool_ok(
                    self._ensure_session().symbolize_memory(
                        address=address,
                        size=size,
                        name=label_name,
                    )
                )
            if name == "symbolize_reg":
                register = self._parse_nonempty_string(arguments, "register")
                label_name = self._parse_optional_string(arguments, "name", default=None)
                return self._tool_ok(
                    self._ensure_session().symbolize_register(
                        register=register,
                        name=label_name,
                    )
                )
            if name == "expr":
                label = self._parse_nonempty_string(arguments, "label")
                return self._tool_ok(self._ensure_session().get_symbolic_expression(label=label))
            if name == "recent_path_constraints":
                limit = self._parse_int(arguments, "limit", default=16, minimum=1)
                return self._tool_ok(self._ensure_session().recent_path_constraints(limit=limit))
            if name == "path_constraint_closure":
                label = self._parse_nonempty_string(arguments, "label")
                return self._tool_ok(self._ensure_session().path_constraint_closure(label=label))
            if name == "maps":
                return self._tool_ok(self._ensure_session().list_memory_maps())
            if name == "trace_start":
                event_types = self._parse_optional_string_list(arguments, "event_types", default=None)
                address_ranges = self._parse_optional_address_ranges(arguments, "address_ranges")
                return self._tool_ok(
                    self._ensure_session().trace_start(
                        event_types=event_types,
                        address_ranges=address_ranges,
                    )
                )
            if name == "trace_stop":
                return self._tool_ok(self._ensure_session().trace_stop())
            if name == "trace_status":
                return self._tool_ok(self._ensure_session().trace_status())
            if name == "trace_get":
                limit = self._parse_int(arguments, "limit", default=100, minimum=1)
                since_start = self._parse_bool(arguments, "since_start", default=True)
                return self._tool_ok(
                    self._ensure_session().trace_get(
                        limit=limit,
                        since_start=since_start,
                    )
                )
            if name == "bp_add":
                address = self._parse_nonempty_string(arguments, "address")
                return self._tool_ok(self._ensure_session().bp_add(address=address))
            if name == "bp_del":
                address = self._parse_nonempty_string(arguments, "address")
                return self._tool_ok(self._ensure_session().bp_del(address=address))
            if name == "bp_list":
                return self._tool_ok(self._ensure_session().bp_list())
            if name == "bp_clear":
                return self._tool_ok(self._ensure_session().bp_clear())
            if name == "send_bytes":
                data = arguments.get("data")
                data_hex = arguments.get("data_hex")
                symbolic = self._parse_bool(arguments, "symbolic", default=False)
                if data is not None and data_hex is not None:
                    return self._tool_error("send_bytes accepts either `data` or `data_hex`, not both")
                if data_hex is not None:
                    if not isinstance(data_hex, str) or data_hex.strip() == "":
                        return self._tool_error(
                            "send_bytes `data_hex` must be a non-empty hex string "
                            '(example: {"data_hex":"040000000680ffffffffffff"})'
                        )
                    compact = "".join(data_hex.split())
                    if compact.startswith(("0x", "0X")):
                        compact = compact[2:]
                    try:
                        payload = bytes.fromhex(compact)
                    except ValueError:
                        return self._tool_error("send_bytes `data_hex` must contain only hex byte pairs")
                    if len(payload) == 0:
                        return self._tool_error("send_bytes decoded payload is empty")
                    return self._tool_ok(self._ensure_session().write_stdin(data=payload, symbolic=symbolic))
                if not isinstance(data, str) or data == "":
                    return self._tool_error(
                        "send_bytes requires non-empty string argument `data` or `data_hex` "
                        '(example: {"data":"1\n"} or {"data_hex":"4142430a"})'
                    )
                return self._tool_ok(self._ensure_session().write_stdin(data=data, symbolic=symbolic))
            if name == "send_line":
                line = arguments.get("line", "")
                symbolic = self._parse_bool(arguments, "symbolic", default=False)
                if not isinstance(line, str):
                    return self._tool_error(
                        "send_line requires string argument `line` "
                        '(example: {"line":"1"})'
                    )
                return self._tool_ok(self._ensure_session().write_stdin(data=f"{line}\n", symbolic=symbolic))
            if name == "send_file":
                path_value = arguments.get("path")
                if not isinstance(path_value, str) or path_value.strip() == "":
                    return self._tool_error(
                        "send_file requires non-empty string argument `path` "
                        '(example: {"path":"/tmp/pov_input.txt"})'
                    )
                append_newline = self._parse_bool(arguments, "append_newline", default=False)
                symbolic = self._parse_bool(arguments, "symbolic", default=False)
                path = Path(path_value)
                if not path.exists() or not path.is_file():
                    return self._tool_error(f"send_file path is not a readable file: {path_value}")
                total_written = 0
                session = self._ensure_session()
                with path.open("rb") as fp:
                    while True:
                        chunk = fp.read(4096)
                        if not chunk:
                            break
                        write_result = session.write_stdin(data=chunk, symbolic=symbolic)
                        total_written += int(write_result["result"].get("written", 0))
                if append_newline:
                    write_result = session.write_stdin(data=b"\n", symbolic=symbolic)
                    total_written += int(write_result["result"].get("written", 0))
                return self._tool_ok({"written": total_written, "path": str(path), "append_newline": append_newline, "symbolic": symbolic})
            if name == "stdout":
                max_chars = self._parse_int(arguments, "max_chars", default=4096, minimum=1)
                wait_ms = self._parse_int(arguments, "wait_ms", default=150, minimum=0)
                result = self._read_stream_with_wait(
                    read_fn=self._ensure_session().read_stdout,
                    cursor=self._stdout_cursor,
                    max_chars=max_chars,
                    wait_ms=wait_ms,
                )
                payload = result.get("result") if isinstance(result, dict) else None
                if isinstance(payload, dict):
                    cursor = payload.get("cursor")
                    if isinstance(cursor, int) and cursor >= 0:
                        self._stdout_cursor = cursor
                return self._tool_ok(result)
            if name == "stderr":
                max_chars = self._parse_int(arguments, "max_chars", default=4096, minimum=1)
                wait_ms = self._parse_int(arguments, "wait_ms", default=150, minimum=0)
                result = self._read_stream_with_wait(
                    read_fn=self._ensure_session().read_stderr,
                    cursor=self._stderr_cursor,
                    max_chars=max_chars,
                    wait_ms=wait_ms,
                )
                payload = result.get("result") if isinstance(result, dict) else None
                if isinstance(payload, dict):
                    cursor = payload.get("cursor")
                    if isinstance(cursor, int) and cursor >= 0:
                        self._stderr_cursor = cursor
                return self._tool_ok(result)
            return self._tool_error(f"tool not implemented: {name}")
        except KeyError as exc:
            _debug_log(f"tool error name={name} missing_arg={exc.args[0]!r}")
            return self._tool_error(f"missing required argument: {exc.args[0]}")
        except Exception as exc:  # noqa: BLE001
            _debug_log(f"tool error name={name} exc={exc!r}")
            return self._tool_error(str(exc))

    def shutdown(self) -> None:
        _teardown_log(f"shutdown start has_session={self._session is not None}")
        if self._session is None:
            return
        try:
            _teardown_log("shutdown calling session.close")
            self._session.close()
            _teardown_log("shutdown session.close returned")
        except Exception as exc:
            _teardown_log(f"shutdown session.close raised {exc!r}")
        self._session = None
        self._reset_stream_cursors()
        _teardown_log("shutdown done")

    def _reset_stream_cursors(self) -> None:
        self._stdout_cursor = 0
        self._stderr_cursor = 0

    @staticmethod
    def _parse_object(arguments: JSON, key: str, default: dict[str, Any] | None = None) -> dict[str, Any]:
        if key not in arguments:
            return dict(default or {})
        value = arguments.get(key)
        if not isinstance(value, dict):
            raise ValueError(f"{key} must be an object")
        return dict(value)

    @staticmethod
    def _parse_string_map(arguments: JSON, key: str, default: dict[str, str] | None = None) -> dict[str, str]:
        if key not in arguments:
            return dict(default or {})
        value = arguments.get(key)
        if not isinstance(value, dict):
            raise ValueError(f"{key} must be an object with string values")
        result: dict[str, str] = {}
        for item_key, item_value in value.items():
            if not isinstance(item_key, str) or not isinstance(item_value, str):
                raise ValueError(f"{key} must be an object with string keys and string values")
            result[item_key] = item_value
        return result

    @staticmethod
    def _parse_optional_string(arguments: JSON, key: str, default: str | None = None) -> str | None:
        if key not in arguments:
            return default
        value = arguments.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError(f"{key} must be a string or null")
        return value

    @staticmethod
    def _parse_nonempty_string(arguments: JSON, key: str) -> str:
        value = arguments.get(key)
        if not isinstance(value, str) or value.strip() == "":
            raise ValueError(f"{key} must be a non-empty string")
        return value

    @staticmethod
    def _parse_string_list(arguments: JSON, key: str, default: list[str] | None = None) -> list[str]:
        if key not in arguments:
            return list(default or [])
        value = arguments.get(key)
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError(f"{key} must be an array of strings")
        return list(value)

    @staticmethod
    def _parse_optional_string_list(arguments: JSON, key: str, default: list[str] | None = None) -> list[str] | None:
        if key not in arguments:
            return default
        value = arguments.get(key)
        if value is None:
            return None
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            raise ValueError(f"{key} must be an array of strings")
        return list(value)

    @staticmethod
    def _parse_int(
        arguments: JSON,
        key: str,
        default: int | None = None,
        required: bool = False,
        minimum: int | None = None,
    ) -> int:
        if key not in arguments:
            if required:
                raise KeyError(key)
            if default is None:
                raise ValueError(f"{key} is required")
            value = default
        else:
            value = arguments.get(key)
        if not isinstance(value, int) or isinstance(value, bool):
            raise ValueError(f"{key} must be an integer")
        if minimum is not None and value < minimum:
            raise ValueError(f"{key} must be >= {minimum}")
        return value

    @staticmethod
    def _parse_positive_float(arguments: JSON, key: str, default: float) -> float:
        value = arguments.get(key, default)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{key} must be a number")
        parsed = float(value)
        if parsed <= 0:
            raise ValueError(f"{key} must be > 0")
        return parsed

    @staticmethod
    def _parse_bool(arguments: JSON, key: str, default: bool) -> bool:
        if key not in arguments:
            return default
        value = arguments.get(key)
        if not isinstance(value, bool):
            raise ValueError(f"{key} must be a boolean")
        return value

    @staticmethod
    def _parse_optional_address_ranges(arguments: JSON, key: str) -> list[tuple[str, str]] | None:
        if key not in arguments or arguments.get(key) is None:
            return None
        raw = arguments.get(key)
        if not isinstance(raw, list):
            raise ValueError(f"{key} must be an array")
        parsed: list[tuple[str, str]] = []
        for index, item in enumerate(raw):
            if not isinstance(item, dict):
                raise ValueError(f"{key}[{index}] must be an object with start/end")
            start = item.get("start")
            end = item.get("end")
            if not isinstance(start, str) or start.strip() == "":
                raise ValueError(f"{key}[{index}].start must be a non-empty string")
            if not isinstance(end, str) or end.strip() == "":
                raise ValueError(f"{key}[{index}].end must be a non-empty string")
            parsed.append((start.strip(), end.strip()))
        return parsed

    @staticmethod
    def _looks_like_path_token(value: str) -> bool:
        # Accept common path-ish inputs (absolute/relative/POSIX/Windows-ish)
        # and reject punctuation-only placeholders (",", "[]", "{}", etc.).
        allowed_extra = {"/", "\\", ".", "_", "-", ":"}
        return any(ch.isalnum() or ch in allowed_extra for ch in value)

    @staticmethod
    def _read_stream_with_wait(
        read_fn: Callable[..., JSON],
        cursor: int,
        max_chars: int,
        wait_ms: int,
    ) -> JSON:
        if wait_ms < 0:
            raise ValueError("wait_ms must be >= 0")
        result = read_fn(cursor=cursor, max_chars=max_chars)
        payload = result.get("result")
        if not isinstance(payload, dict):
            return result
        data = payload.get("data")
        eof = bool(payload.get("eof"))
        current_cursor = payload.get("cursor")
        if isinstance(data, str) and data != "":
            return result
        if eof:
            return result
        if not isinstance(current_cursor, int) or current_cursor < 0:
            return result
        deadline = time.monotonic() + (wait_ms / 1000.0)
        poll_interval = 0.02
        while time.monotonic() < deadline:
            time.sleep(poll_interval)
            result = read_fn(cursor=current_cursor, max_chars=max_chars)
            payload = result.get("result")
            if not isinstance(payload, dict):
                return result
            data = payload.get("data")
            eof = bool(payload.get("eof"))
            next_cursor = payload.get("cursor")
            if isinstance(data, str) and data != "":
                return result
            if eof:
                return result
            if isinstance(next_cursor, int) and next_cursor >= 0:
                current_cursor = next_cursor
        return result

    @staticmethod
    def _tool_ok(payload: JSON) -> JSON:
        # Always include machine-readable JSON for text-only clients.
        text = json.dumps(
            {
                "ok": bool(payload.get("ok", True)),
                "command": payload.get("command", "tool"),
                "result": payload.get("result", {}),
            },
            sort_keys=True,
        )
        return {
            "content": [{"type": "text", "text": text}],
            "structuredContent": payload,
            "isError": False,
        }

    @staticmethod
    def _tool_error(message: str) -> JSON:
        return {
            "content": [{"type": "text", "text": message}],
            "isError": True,
        }

    @staticmethod
    def _tool_timeout(command: str, timeout: float, message: str) -> JSON:
        payload = {
            "ok": False,
            "command": command,
            "result": {
                # Keep legacy fields for compatibility with existing clients.
                "timed_out": True,
                "timeout": timeout,
                # Preferred machine-readable status for LLM/tooling flows.
                "status": "incomplete",
                "reason": "window_elapsed",
                "window_elapsed": True,
                "guidance_code": "FOLLOW_IO_POLL_LOOP",
                "next_action": ["stdout", "stderr", "state"],
                "message": message,
            },
        }
        return {
            "content": [{"type": "text", "text": json.dumps(payload, sort_keys=True)}],
            "structuredContent": payload,
            "isError": False,
        }

    @staticmethod
    def _ok(request_id: Any, result: JSON) -> JSON:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> JSON:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}

    @staticmethod
    def _build_tools() -> list[ToolSpec]:
        return [
            ToolSpec(
                name="start",
                description=(
                    "Start an analysis session for a target binary. "
                    "After start, session is typically paused. "
                    "Recommended next steps: syms -> bp_add (using loaded_address) -> advance {\"mode\":\"continue\"}."
                ),
                input_schema={
                    "type": "object",
                    "description": "Session launch options.",
                    "properties": {
                        "target": {
                            "type": "string",
                            "description": "Absolute path to the guest binary to execute.",
                            "minLength": 1,
                        },
                        "args": {
                            "type": "array",
                            "description": "Command-line arguments passed to the guest binary.",
                            "items": {"type": "string"},
                            "default": [],
                        },
                        "cwd": {
                            "type": ["string", "null"],
                            "description": "Working directory for process launch.",
                            "default": None,
                        },
                        "qemu_user_path": {
                            "type": ["string", "null"],
                            "description": "Optional explicit SymFit qemu-user binary path.",
                            "default": None,
                        },
                        "qemu_args": {
                            "type": "array",
                            "description": "Extra arguments passed to qemu-user before the target, for example ['-L', '.'].",
                            "items": {"type": "string"},
                            "default": [],
                        },
                        "env": {
                            "type": "object",
                            "description": "Extra environment variables for the qemu-user process.",
                            "additionalProperties": {"type": "string"},
                            "default": {},
                        },
                    },
                    "required": ["target"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="close",
                description="Close the active analysis session.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="caps",
                description="Return backend capabilities.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="state",
                description=(
                    "Return full session state. "
                    "Use this to confirm session_status transitions (idle/paused/running/exited). "
                    "If session_status is paused with pending_termination=true, the target is in terminal-exit "
                    "pause and is still inspectable with regs, mem, maps, disasm, and bt."
                ),
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="syms",
                description=(
                    "List ELF symbols and resolve runtime loaded addresses for THIS session. "
                    "Always use returned loaded_address for breakpoints; do not hardcode addresses across sessions."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "max_count": {"type": "integer", "minimum": 1, "default": 500},
                        "name_filter": {"type": ["string", "null"]},
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="advance",
                description=(
                    "Advance execution using one of four modes: continue, insn, bb, or return. "
                    "All modes may stop early on input, breakpoints, process exit, or other interactive stop conditions. "
                    "When stop_reason is termination_pending, do post-mortem inspection with regs, mem, maps, "
                    "disasm, or bt before closing or resuming."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "mode": {
                            "type": "string",
                            "enum": ["continue", "insn", "bb", "return"],
                            "description": "Advance mode: continue, insn, bb, or return.",
                        },
                        "count": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Required for insn and bb modes; ignored otherwise.",
                        },
                        "timeout": {
                            "type": "number",
                            "exclusiveMinimum": 0,
                            "default": 5.0,
                            "description": "Execution window in seconds.",
                        }
                    },
                    "required": ["mode"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="pause",
                description=(
                    "Pause target execution. "
                    "If pause window elapses, MUST call stdout, stderr, and state before recovery."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "timeout": {
                            "type": "number",
                            "exclusiveMinimum": 0,
                            "description": (
                                "Pause window in seconds (field name `timeout` kept for compatibility)."
                            ),
                            "default": 5.0,
                        }
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="regs",
                description=(
                    "Read selected registers (or default set). "
                    "Works while paused, including terminal-exit pause with pending_termination=true."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "names": {
                            "type": "array",
                            "description": "Optional register names to read. If omitted, backend defaults are used.",
                            "items": {"type": "string"},
                        }
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="bt",
                description=(
                    "Best-effort stack backtrace (gdb-like). "
                    "Uses current PC + frame-pointer unwinding and resolves nearest symbols. "
                    "Works while paused, including terminal-exit pause with pending_termination=true."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "max_frames": {
                            "type": "integer",
                            "minimum": 1,
                            "default": 16,
                            "description": "Maximum stack frames to return.",
                        }
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="disasm",
                description=(
                    "Disassemble code at a guest address. "
                    "Works while paused, including terminal-exit pause with pending_termination=true."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Guest virtual address (hex string)."},
                        "count": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Maximum number of instructions to decode.",
                            "default": 16,
                        },
                    },
                    "required": ["address"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="mem",
                description=(
                    "Read guest memory bytes plus symbolic byte metadata when available. "
                    "Works while paused, including terminal-exit pause with pending_termination=true; "
                    "do not skip memory reads just because a process exit is pending."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Guest virtual address (hex string)."},
                        "size": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Number of bytes to read.",
                        },
                    },
                    "required": ["address", "size"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="symbolize_mem",
                description="Mark a guest memory range symbolic in the current paused execution.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "address": {"type": "string", "description": "Guest virtual address (hex string)."},
                        "size": {"type": "integer", "minimum": 1, "description": "Number of bytes to symbolize."},
                        "name": {"type": ["string", "null"], "description": "Optional symbolic variable hint."},
                    },
                    "required": ["address", "size"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="symbolize_reg",
                description="Mark a guest register symbolic in the current paused execution.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "register": {"type": "string", "description": "Register name, for example x0, x30, rax, or eax."},
                        "name": {"type": ["string", "null"], "description": "Optional symbolic variable hint."},
                    },
                    "required": ["register"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="expr",
                description="Show the symbolic expression for a concrete symbolic label.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "label": {"type": "string", "description": "Symbolic label id as a hex string, for example 0x3."},
                    },
                    "required": ["label"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="recent_path_constraints",
                description="List the newest path-condition labels recorded in this session.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "limit": {
                            "type": "integer",
                            "minimum": 1,
                            "default": 16,
                            "description": "Maximum number of recent path constraints to return.",
                        }
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="path_constraint_closure",
                description="Return the earlier constraints that a branch-condition label depends on.",
                input_schema={
                    "type": "object",
                    "properties": {
                        "label": {
                            "type": "string",
                            "description": "Branch-condition symbolic label as a hex string.",
                        }
                    },
                    "required": ["label"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="maps",
                description="List current memory map regions.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),

            ToolSpec(
                name="trace_start",
                description=(
                    "Start trace tracing for this session with optional filters and a start marker. "
                    "Use trace_get to retrieve trace entries."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "event_types": {
                            "type": "array",
                            "description": "Optional event type filters.",
                            "items": {"type": "string"},
                        },
                        "address_ranges": {
                            "type": "array",
                            "description": "Optional address range filters.",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "start": {"type": "string"},
                                    "end": {"type": "string"},
                                },
                                "required": ["start", "end"],
                                "additionalProperties": False,
                            },
                        },
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="trace_stop",
                description="Stop trace tracing marker for this session.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="trace_status",
                description="Show trace tracing status, filters, and marker heads.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="trace_get",
                description="Fetch trace entries (defaults to entries since trace_start).",
                input_schema={
                    "type": "object",
                    "properties": {
                        "limit": {"type": "integer", "minimum": 1, "default": 100},
                        "since_start": {"type": "boolean", "default": True},
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="bp_add",
                description=(
                    "Add a persistent breakpoint address. "
                    "Use syms.loaded_address from current session; avoid guessed static/base+offset addresses."
                ),
                input_schema={
                    "type": "object",
                    "properties": {"address": {"type": "string", "minLength": 1}},
                    "required": ["address"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="bp_del",
                description="Remove a persistent breakpoint address.",
                input_schema={
                    "type": "object",
                    "properties": {"address": {"type": "string", "minLength": 1}},
                    "required": ["address"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="bp_list",
                description="List configured persistent breakpoints.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="bp_clear",
                description="Clear all configured persistent breakpoints.",
                input_schema={"type": "object", "properties": {}, "additionalProperties": False},
            ),
            ToolSpec(
                name="send_bytes",
                description=(
                    "Pwntools-style raw send. Write data to target stdin immediately. "
                    "Session must be active (idle/running/paused). "
                    "Use `data` for text or `data_hex` for exact raw bytes."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "data": {
                            "type": "string",
                            "description": "Text data to write (UTF-8 encoding). Provide either data or data_hex.",
                        },
                        "data_hex": {
                            "type": "string",
                            "description": "Exact raw bytes encoded as hex. Provide either data or data_hex.",
                        },
                        "symbolic": {
                            "type": "boolean",
                            "description": "Queue this stdin chunk for symbolic labeling when the guest consumes it.",
                            "default": False,
                        },
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="send_line",
                description=(
                    "Pwntools-style line send. Appends a single '\\n' and writes to stdin. "
                    "If `line` is omitted, sends only newline. "
                    "Session must be active (idle/running/paused). "
                    "For menu flows, prefer send_line over send_bytes."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "line": {
                            "type": "string",
                            "description": "Line content without trailing newline.",
                            "default": "",
                        },
                        "symbolic": {
                            "type": "boolean",
                            "description": "Queue this stdin line for symbolic labeling when the guest consumes it.",
                            "default": False,
                        }
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="send_file",
                description=(
                    "Stream a local file's raw bytes into target stdin using fixed internal chunks. "
                    "Session must be active (idle/running/paused). "
                    "Use this for large payloads that are too long for a single send_bytes call."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "path": {
                            "type": "string",
                            "description": "Absolute or relative path to local input file.",
                            "minLength": 1,
                        },
                        "append_newline": {
                            "type": "boolean",
                            "description": "Append a final newline after file contents.",
                            "default": False,
                        },
                        "symbolic": {
                            "type": "boolean",
                            "description": "Queue streamed file bytes for symbolic labeling when the guest consumes them.",
                            "default": False,
                        },
                    },
                    "required": ["path"],
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="stdout",
                description=(
                    "Read next buffered stdout chunk (server maintains cursor internally). "
                    "Calls briefly wait for fresh output to reduce run/read races."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "max_chars": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Maximum characters to return in this chunk.",
                            "default": 4096,
                        },
                        "wait_ms": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Optional wait budget (ms) for new output before returning empty.",
                            "default": 150,
                        },
                    },
                    "additionalProperties": False,
                },
            ),
            ToolSpec(
                name="stderr",
                description=(
                    "Read next buffered stderr chunk (server maintains cursor internally). "
                    "Calls briefly wait for fresh output to reduce run/read races."
                ),
                input_schema={
                    "type": "object",
                    "properties": {
                        "max_chars": {
                            "type": "integer",
                            "minimum": 1,
                            "description": "Maximum characters to return in this chunk.",
                            "default": 4096,
                        },
                        "wait_ms": {
                            "type": "integer",
                            "minimum": 0,
                            "description": "Optional wait budget (ms) for new output before returning empty.",
                            "default": 150,
                        },
                    },
                    "additionalProperties": False,
                },
            ),
        ]


def run_stdio(server: InteractiveAnalysisMcpServer) -> int:
    try:
        for raw in sys.stdin:
            raw = raw.strip()
            if not raw:
                continue
            try:
                request = json.loads(raw)
            except json.JSONDecodeError:
                response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
            else:
                if not isinstance(request, dict):
                    response = {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
                else:
                    response = server.handle_request(request)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
    finally:
        server.shutdown()
    return 0


def _install_shutdown_hooks(server: InteractiveAnalysisMcpServer) -> None:
    atexit.register(server.shutdown)

    def _handle_signal(signum: int, _frame: object) -> None:
        server.shutdown()
        raise SystemExit(128 + signum)

    for signum in (signal.SIGINT, signal.SIGTERM):
        signal.signal(signum, _handle_signal)


def _arm_parent_death_signal() -> None:
    if sys.platform != "linux":
        return
    try:
        libc = ctypes.CDLL(None)
        prctl = libc.prctl
        prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        prctl.restype = ctypes.c_int
        if prctl(_PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0) != 0:
            return
    except Exception:
        return


def main() -> int:
    parser = argparse.ArgumentParser(description="Interactive Dynamic Analysis MCP server (stdio)")
    parser.add_argument("--transport", choices=["stdio"], default="stdio")
    parser.parse_args()
    _arm_parent_death_signal()
    server = InteractiveAnalysisMcpServer()
    _install_shutdown_hooks(server)
    return run_stdio(server)


if __name__ == "__main__":
    raise SystemExit(main())
