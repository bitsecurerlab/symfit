from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from dynamiq.backends.qemu_user_instrumented import QemuUserInstrumentedBackend
from dynamiq.instrumentation import InstrumentationClient, InstrumentationRpcClient
from dynamiq.qmp import QmpClient


HELPER = Path(__file__).resolve().parent / "helpers" / "fake_runtime_server.py"


class ProcessChannel:
    def __init__(self, proc: subprocess.Popen[str]) -> None:
        self.proc = proc
        assert proc.stdin is not None
        assert proc.stdout is not None
        self.stdin = proc.stdin
        self.stdout = proc.stdout

    def makefile(self, mode: str, encoding: str):
        assert mode == "r"
        assert encoding == "utf-8"
        return self.stdout

    def sendall(self, data: bytes) -> None:
        self.stdin.write(data.decode("utf-8"))
        self.stdin.flush()

    def close(self) -> None:
        self.stdin.close()
        self.stdout.close()
        self.proc.terminate()
        self.proc.wait(timeout=2.0)


def _spawn_channel(mode: str, timeout: float) -> ProcessChannel:
    del timeout
    proc = subprocess.Popen(
        [sys.executable, str(HELPER), mode],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return ProcessChannel(proc)


def test_backend_process_integration_round_trip() -> None:
    events = InstrumentationClient("events-process", connector=lambda path, timeout: _spawn_channel("events", timeout))
    rpc = InstrumentationRpcClient("rpc-process", connector=lambda path, timeout: _spawn_channel("rpc", timeout))
    backend = QemuUserInstrumentedBackend(
        qmp_client=None,
        instrumentation_client=events,
        instrumentation_rpc_client=rpc,
    )

    backend.start("target.bin", [], None, {})
    stop = backend.run_until_address("0x401000", timeout=1.0)
    regs = backend.get_registers(["rax"])
    mem = backend.read_memory("0x401000", 2)
    maps = backend.list_memory_maps()
    events_result = backend.get_recent_events(limit=5)
    trace_result = backend.get_trace(limit=5)
    state = backend.get_state()
    backend.close()

    assert any(item["type"] == "backend_ready" for item in events_result["result"]["events"])
    assert stop["result"]["matched_address"] == "0x401000"
    assert regs["result"]["registers"]["rip"] == "0x401000"
    assert mem["result"] == {"address": "0x401000", "size": 2, "bytes": "0102"}
    assert maps["result"]["maps"]["regions"][0]["start"] == "0x400000"
    assert "payload" in events_result["result"]["events"][0]
    assert "index" not in events_result["result"]["events"][0]
    assert trace_result["result"]["trace"] == []
    assert state["registers"]["rax"] == "0x1"
