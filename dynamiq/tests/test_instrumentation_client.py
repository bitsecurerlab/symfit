from __future__ import annotations

import json
import time

from dynamiq.instrumentation import InstrumentationClient


class FakeReader:
    def __init__(self, lines: list[str]) -> None:
        self._lines = list(lines)

    def readline(self) -> str:
        if not self._lines:
            time.sleep(0.01)
            return ""
        return self._lines.pop(0)

    def close(self) -> None:
        return None


class FakeSocket:
    def __init__(self, lines: list[str]) -> None:
        self.reader = FakeReader(lines)
        self.timeout: float | None = None

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def connect(self, path: str) -> None:
        self.path = path

    def makefile(self, mode: str, encoding: str) -> FakeReader:
        assert mode == "r"
        assert encoding == "utf-8"
        return self.reader

    def close(self) -> None:
        return None


def test_instrumentation_client_receives_events(monkeypatch) -> None:
    event = {
        "event_id": "e-1",
        "seq": 1,
        "type": "branch",
        "timestamp": 1.0,
        "pc": "0x401000",
        "thread_id": "1",
        "cpu_id": 0,
        "payload": {"target": "0x401010", "taken": True},
    }
    fake_socket = FakeSocket([json.dumps(event) + "\n"])
    monkeypatch.setattr("socket.socket", lambda *args, **kwargs: fake_socket)

    client = InstrumentationClient("/tmp/events.sock")
    client.connect()
    matched = client.wait_for_event(["branch"], timeout=1.0)
    recent = client.get_recent_events()
    client.close()

    assert matched["event_id"] == "e-1"
    assert recent[0]["type"] == "branch"
    assert client.stats.events_received == 1
