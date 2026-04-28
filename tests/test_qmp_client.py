from __future__ import annotations

import json

from dynamiq.qmp import QmpClient


class FakeReader:
    def __init__(self, lines: list[str]) -> None:
        self._lines = list(lines)

    def readline(self) -> str:
        if not self._lines:
            return ""
        return self._lines.pop(0)

    def close(self) -> None:
        return None


class FakeSocket:
    def __init__(self, lines: list[str]) -> None:
        self.reader = FakeReader(lines)
        self.sent: list[dict] = []
        self.timeout: float | None = None

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def connect(self, path: str) -> None:
        self.path = path

    def makefile(self, mode: str, encoding: str) -> FakeReader:
        assert mode == "r"
        assert encoding == "utf-8"
        return self.reader

    def sendall(self, data: bytes) -> None:
        self.sent.append(json.loads(data.decode().strip()))

    def close(self) -> None:
        return None


def test_qmp_client_connects_and_executes(monkeypatch) -> None:
    fake_socket = FakeSocket(
        [
            '{"QMP":{"version":{"qemu":{"major":8}}}}\n',
            '{"return":{}}\n',
            '{"return":{"status":"running"}}\n',
        ]
    )
    monkeypatch.setattr("socket.socket", lambda *args, **kwargs: fake_socket)

    client = QmpClient("/tmp/qmp.sock")
    greeting = client.connect()
    result = client.execute("query-status")
    client.close()

    assert "QMP" in greeting
    assert result == {"status": "running"}
    assert fake_socket.sent[0]["execute"] == "qmp_capabilities"
    assert fake_socket.sent[1]["execute"] == "query-status"
