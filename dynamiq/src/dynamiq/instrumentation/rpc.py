from __future__ import annotations

import errno
import json
import socket
import time
from collections.abc import Callable
from typing import Any

from ..errors import InteractiveAnalysisError, SessionTimeoutError


class InstrumentationRpcError(InteractiveAnalysisError):
    """Raised when the instrumentation RPC channel reports an error."""


class InstrumentationRpcClient:
    def __init__(
        self,
        socket_path: str,
        timeout: float = 2.0,
        connector: Callable[[str, float], Any] | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.timeout = timeout
        self.connector = connector
        self._socket: socket.socket | None = None
        self._reader = None
        self._next_id = 1

    def connect(self) -> None:
        if self._socket is not None:
            return
        if self.connector is not None:
            sock = self.connector(self.socket_path, self.timeout)
        else:
            deadline = time.time() + self.timeout
            last_error: OSError | None = None
            while True:
                sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                try:
                    sock.connect(self.socket_path)
                    break
                except OSError as exc:
                    sock.close()
                    last_error = exc
                    if exc.errno not in {errno.ENOENT, errno.ECONNREFUSED}:
                        raise
                    if time.time() >= deadline:
                        raise InstrumentationRpcError(
                            f"timed out connecting to instrumentation RPC socket: {self.socket_path}"
                        ) from exc
                    time.sleep(0.05)
        self._socket = sock
        self._reader = sock.makefile("r", encoding="utf-8")

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()
            self._reader = None
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    def request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        if self._socket is None or self._reader is None:
            raise InstrumentationRpcError("instrumentation RPC client is not connected")
        effective_timeout = self.timeout if timeout is None else float(timeout)
        if effective_timeout <= 0:
            raise ValueError("timeout must be > 0")
        settimeout = getattr(self._socket, "settimeout", None)
        if callable(settimeout):
            settimeout(effective_timeout)
        request_id = self._next_id
        self._next_id += 1
        payload = {
            "id": request_id,
            "method": method,
            "params": dict(params or {}),
        }
        self._socket.sendall(json.dumps(payload).encode("utf-8") + b"\n")
        while True:
            message = self._read_message()
            if message.get("id") != request_id:
                continue
            ok = message.get("ok")
            if ok is False:
                error = message.get("error")
                if isinstance(error, dict):
                    code = error.get("code")
                    detail = error.get("message")
                    if isinstance(code, str) and isinstance(detail, str):
                        raise InstrumentationRpcError(f"{code}: {detail}")
                raise InstrumentationRpcError(str(error))
            if "error" in message:
                error = message["error"]
                if isinstance(error, dict):
                    code = error.get("code")
                    detail = error.get("message")
                    if isinstance(code, str) and isinstance(detail, str):
                        raise InstrumentationRpcError(f"{code}: {detail}")
                raise InstrumentationRpcError(str(error))
            result = message.get("result")
            if not isinstance(result, dict):
                raise InstrumentationRpcError("instrumentation RPC result must be an object")
            return result

    def _read_message(self) -> dict[str, Any]:
        assert self._reader is not None
        try:
            line = self._reader.readline()
        except TimeoutError as exc:
            raise SessionTimeoutError("timed out waiting for instrumentation RPC response") from exc
        if not line:
            raise InstrumentationRpcError("instrumentation RPC connection closed")
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            raise InstrumentationRpcError("received malformed instrumentation RPC message") from exc
        if not isinstance(message, dict):
            raise InstrumentationRpcError("received non-object instrumentation RPC message")
        return message
