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
        """Idempotently release the socket and reader.

        State is cleared before closing so a failing close() still leaves
        the client reconnectable, and a second close() is a no-op. Dropping
        the socket also discards any per-request socket deadline, so a later
        connect() starts from the configured default timeout.
        """
        reader, self._reader = self._reader, None
        sock, self._socket = self._socket, None
        if reader is not None:
            try:
                reader.close()
            except Exception:
                pass
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    def reconnect(self) -> None:
        """Close and re-establish the channel with a fresh socket+reader.

        Safe to call after a SessionTimeoutError: a timed-out resume leaves
        the local ``socket.makefile`` reader stale (later reads fail without
        waiting) while the server keeps running. Reconnecting gives the next
        explicit caller retry a fresh channel. It does not retry the timed-out
        request itself; execution is forward-only, so the caller decides.
        """
        self.close()
        self.connect()

    def request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        """Send one RPC request and wait for its reply.

        A socket timeout raises SessionTimeoutError without retrying: the
        guest keeps running forward-only, so the caller decides whether to
        retry. After a timeout the local reader is stale; call reconnect()
        before reusing this client.
        """
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
