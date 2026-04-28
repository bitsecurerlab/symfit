from __future__ import annotations

import json
import socket
from collections.abc import Callable
from typing import Any

from ..errors import InteractiveAnalysisError, SessionTimeoutError


class QmpError(InteractiveAnalysisError):
    """Raised when QMP reports an error or invalid reply."""


class QmpClient:
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
        self._greeting: dict[str, Any] | None = None

    @property
    def connected(self) -> bool:
        return self._socket is not None

    def connect(self) -> dict[str, Any]:
        if self._socket is not None:
            return self._greeting or {}
        if self.connector is not None:
            sock = self.connector(self.socket_path, self.timeout)
        else:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect(self.socket_path)
        reader = sock.makefile("r", encoding="utf-8")
        greeting = self._read_message(reader)
        self._socket = sock
        self._reader = reader
        self._greeting = greeting
        self.execute("qmp_capabilities")
        return greeting

    def execute(self, command: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        if self._socket is None or self._reader is None:
            raise QmpError("QMP client is not connected")
        payload: dict[str, Any] = {"execute": command}
        if arguments:
            payload["arguments"] = arguments
        wire = json.dumps(payload).encode("utf-8") + b"\n"
        self._socket.sendall(wire)
        while True:
            message = self._read_message(self._reader)
            if "return" in message:
                return dict(message["return"])
            if "error" in message:
                raise QmpError(str(message["error"]))

    def close(self) -> None:
        if self._reader is not None:
            self._reader.close()
            self._reader = None
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        self._greeting = None

    def _read_message(self, reader: Any) -> dict[str, Any]:
        try:
            line = reader.readline()
        except TimeoutError as exc:
            raise SessionTimeoutError("timed out waiting for QMP message") from exc
        if not line:
            raise QmpError("QMP connection closed")
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            raise QmpError("received malformed QMP message") from exc
        if not isinstance(message, dict):
            raise QmpError("received non-object QMP message")
        return message
