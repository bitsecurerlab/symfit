from __future__ import annotations

from dynamiq.session import AnalysisSession


class FakeBacktraceBackend:
    def __init__(self, registers: dict[str, str], memory: dict[int, bytes]) -> None:
        self._registers = registers
        self._memory = memory

    def get_registers(self, names=None):  # noqa: ANN001
        del names
        return {"state": {"session_status": "paused"}, "result": {"registers": dict(self._registers)}}

    def read_memory(self, address, size):  # noqa: ANN001
        addr = int(address, 0)
        data = self._memory.get(addr, b"\x00" * size)
        return {
            "state": {"session_status": "paused"},
            "result": {"address": address, "size": size, "bytes": data[:size].hex()},
        }

    def capabilities(self):
        return {"read_registers": True, "read_memory": True}

    def get_state(self):
        return {"session_status": "paused", "capabilities": self.capabilities()}

    def close(self):
        return None


def _pack_u64(value: int) -> bytes:
    return value.to_bytes(8, byteorder="little", signed=False)


def _pack_u32(value: int) -> bytes:
    return value.to_bytes(4, byteorder="little", signed=False)


def test_backtrace_unwinds_x86_64_frame_chain(monkeypatch) -> None:  # noqa: ANN001
    memory = {
        0x7000: _pack_u64(0x7100),
        0x7008: _pack_u64(0x402010),
        0x7100: _pack_u64(0x0),
        0x7108: _pack_u64(0x403000),
    }
    backend = FakeBacktraceBackend(
        registers={"rip": "0x401050", "rbp": "0x7000", "rsp": "0x6ff0"},
        memory=memory,
    )
    session = AnalysisSession(backend=backend)
    session.state.session_status = "paused"
    session.state.launched_qemu_user_path = "/tmp/qemu-x86_64"
    monkeypatch.setattr(
        AnalysisSession,
        "_build_symbol_lookup",
        lambda self: [(0x401000, "main"), (0x402000, "worker")],  # noqa: ARG005
    )

    result = session.backtrace(max_frames=8)
    frames = result["result"]["frames"]

    assert result["result"]["pointer_size"] == 8
    assert frames[0]["pc"] == "0x401050"
    assert frames[0]["symbol"] == "main"
    assert frames[0]["offset"] == 0x50
    assert frames[1]["pc"] == "0x402010"
    assert frames[1]["symbol"] == "worker"
    assert frames[1]["offset"] == 0x10


def test_backtrace_unwinds_i386_frame_chain(monkeypatch) -> None:  # noqa: ANN001
    memory = {
        0x3000: _pack_u32(0x3100),
        0x3004: _pack_u32(0x401090),
        0x3100: _pack_u32(0x0),
        0x3104: _pack_u32(0x0),
    }
    backend = FakeBacktraceBackend(
        registers={"eip": "0x401020", "ebp": "0x3000", "esp": "0x2ff0"},
        memory=memory,
    )
    session = AnalysisSession(backend=backend)
    session.state.session_status = "paused"
    session.state.launched_qemu_user_path = "/tmp/qemu-i386"
    monkeypatch.setattr(
        AnalysisSession,
        "_build_symbol_lookup",
        lambda self: [(0x401000, "entry")],  # noqa: ARG005
    )

    result = session.backtrace(max_frames=8)
    frames = result["result"]["frames"]

    assert result["result"]["pointer_size"] == 4
    assert frames[0]["pc"] == "0x401020"
    assert frames[1]["pc"] == "0x401090"
    assert result["result"]["reason"] == "return_address_unavailable"
