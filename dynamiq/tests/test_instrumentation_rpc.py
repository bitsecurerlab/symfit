from __future__ import annotations

import json

import pytest

from dynamiq.instrumentation import InstrumentationRpcClient
from dynamiq.instrumentation.rpc import InstrumentationRpcError


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


def test_instrumentation_rpc_client_round_trips_request(monkeypatch) -> None:
    fake_socket = FakeSocket(['{"id":1,"result":{"registers":{"rax":"0x1"}}}\n'])
    monkeypatch.setattr("socket.socket", lambda *args, **kwargs: fake_socket)

    client = InstrumentationRpcClient("/tmp/instrument.sock")
    client.connect()
    result = client.request("get_registers", {"names": ["rax"]})
    client.close()

    assert fake_socket.sent[0] == {"id": 1, "method": "get_registers", "params": {"names": ["rax"]}}
    assert result == {"registers": {"rax": "0x1"}}


def test_instrumentation_rpc_client_raises_on_error(monkeypatch) -> None:
    fake_socket = FakeSocket(['{"id":1,"error":{"message":"bad request"}}\n'])
    monkeypatch.setattr("socket.socket", lambda *args, **kwargs: fake_socket)

    client = InstrumentationRpcClient("/tmp/instrument.sock")
    client.connect()
    with pytest.raises(InstrumentationRpcError):
        client.request("get_registers")


def test_instrumentation_rpc_client_request_overrides_timeout(monkeypatch) -> None:
    fake_socket = FakeSocket(['{"id":1,"result":{"status":"paused"}}\n'])
    monkeypatch.setattr("socket.socket", lambda *args, **kwargs: fake_socket)

    client = InstrumentationRpcClient("/tmp/instrument.sock", timeout=2.0)
    client.connect()
    _ = client.request("resume_until_address", {"address": "0x401000"}, timeout=7.5)
    client.close()

    assert fake_socket.timeout == 7.5


def test_instrumentation_rpc_client_accepts_ok_envelope(monkeypatch) -> None:
    fake_socket = FakeSocket(['{"id":1,"ok":true,"result":{"status":"paused"}}\n'])
    monkeypatch.setattr("socket.socket", lambda *args, **kwargs: fake_socket)

    client = InstrumentationRpcClient("/tmp/instrument.sock")
    client.connect()
    result = client.request("query_status")
    client.close()

    assert result == {"status": "paused"}


def test_instrumentation_rpc_client_raises_on_ok_false(monkeypatch) -> None:
    fake_socket = FakeSocket(
        ['{"id":1,"ok":false,"error":{"code":"unknown_method","message":"unknown instrumentation RPC method"}}\n']
    )
    monkeypatch.setattr("socket.socket", lambda *args, **kwargs: fake_socket)

    client = InstrumentationRpcClient("/tmp/instrument.sock")
    client.connect()
    with pytest.raises(InstrumentationRpcError, match="unknown_method"):
        client.request("pause")
