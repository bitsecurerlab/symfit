from __future__ import annotations

from dynamiq.session import AnalysisSession


class FakeBackend:
    def __init__(self, maps_result):
        self._maps_result = maps_result

    def start(self, target, args, cwd, qemu_config=None):  # noqa: ANN001
        del target, args, cwd, qemu_config

    def resume(self, timeout):  # noqa: ANN001
        del timeout
        return {"state": {}, "result": {}}

    def pause(self, timeout):  # noqa: ANN001
        del timeout
        return {"state": {}, "result": {}}

    def run_until_event(self, event_types, timeout):  # noqa: ANN001
        del event_types, timeout
        return {"state": {}, "result": {}}

    def run_until_address(self, address, timeout):  # noqa: ANN001
        del address, timeout
        return {"state": {}, "result": {}}

    def step(self, count, timeout):  # noqa: ANN001
        del count, timeout
        return {"state": {}, "result": {}}

    def advance_basic_blocks(self, count, timeout):  # noqa: ANN001
        del count, timeout
        return {"state": {}, "result": {}}

    def write_stdin(self, data):  # noqa: ANN001
        del data
        return {"state": {}, "result": {"written": 0}}

    def read_stdout(self, cursor=0, max_chars=4096):  # noqa: ANN001
        del cursor, max_chars
        return {"state": {}, "result": {"data": "", "cursor": 0, "eof": False}}

    def read_stderr(self, cursor=0, max_chars=4096):  # noqa: ANN001
        del cursor, max_chars
        return {"state": {}, "result": {"data": "", "cursor": 0, "eof": False}}

    def get_registers(self, names=None):  # noqa: ANN001
        del names
        return {"state": {}, "result": {"registers": {}}}

    def read_memory(self, address, size):  # noqa: ANN001
        del address, size
        return {"state": {}, "result": {}}

    def disassemble(self, address, count):  # noqa: ANN001
        del address, count
        return {"state": {}, "result": {}}

    def list_memory_maps(self):
        return {"state": {}, "result": {"maps": {"regions": self._maps_result}}}

    def take_snapshot(self, name=None):  # noqa: ANN001
        del name
        return {"state": {}, "result": {}}

    def restore_snapshot(self, snapshot_id):  # noqa: ANN001
        del snapshot_id
        return {"state": {}, "result": {}}

    def diff_snapshots(self, left_id, right_id):  # noqa: ANN001
        del left_id, right_id
        return {"state": {}, "result": {}}

    def get_recent_events(self, limit=100, event_types=None):  # noqa: ANN001
        del limit, event_types
        return {"state": {}, "result": {}}

    def get_trace(self, limit):  # noqa: ANN001
        del limit
        return {"state": {}, "result": {}}

    def configure_event_filters(self, event_types=None, address_ranges=None):  # noqa: ANN001
        del event_types, address_ranges
        return {"state": {}, "result": {}}

    def get_state(self):
        return {"session_status": "paused", "capabilities": self.capabilities()}

    def capabilities(self):
        return {
            "pause_resume": True,
            "read_registers": True,
            "read_memory": True,
            "disassemble": True,
            "list_memory_maps": True,
            "take_snapshot": False,
            "restore_snapshot": False,
            "trace_basic_block": False,
            "trace_branch": False,
            "trace_memory": False,
            "trace_syscall": False,
            "run_until_address": True,
            "single_step": True,
        }

    def close(self):
        return None


class ProcResult:
    def __init__(self, stdout: str) -> None:
        self.stdout = stdout


def test_symbols_exec(monkeypatch) -> None:
    def fake_run(cmd, check, capture_output, text):  # noqa: ANN001
        del check, capture_output, text
        if cmd[1] == "-h":
            return ProcResult("Type:                              EXEC (Executable file)\n")
        return ProcResult(
            "Symbol table '.symtab' contains 2 entries:\n"
            "   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
            "     1: 0000000000401130    42 FUNC    GLOBAL DEFAULT   14 main\n"
        )

    monkeypatch.setattr("dynamiq.session.subprocess.run", fake_run)
    session = AnalysisSession(backend=FakeBackend(maps_result=[]))
    session.state.target = "/tmp/a.out"

    result = session.symbols()

    assert result["result"]["elf_type"] == "EXEC"
    assert result["result"]["symbols"][0]["name"] == "main"
    assert result["result"]["symbols"][0]["loaded_address"] == "0x401130"


def test_symbols_pie_uses_map_base(monkeypatch) -> None:
    def fake_run(cmd, check, capture_output, text):  # noqa: ANN001
        del check, capture_output, text
        if cmd[1] == "-h":
            return ProcResult("Type:                              DYN (Position-Independent Executable file)\n")
        return ProcResult(
            "Symbol table '.symtab' contains 2 entries:\n"
            "   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
            "     1: 0000000000001130    42 FUNC    GLOBAL DEFAULT   14 main\n"
        )

    monkeypatch.setattr("dynamiq.session.subprocess.run", fake_run)
    maps = [{"start": "0x555555554000", "end": "0x555555556000", "perm": "r-x", "name": "a.out"}]
    session = AnalysisSession(backend=FakeBackend(maps_result=maps))
    session.state.target = "/tmp/a.out"

    result = session.symbols()

    assert result["result"]["elf_type"] == "DYN"
    assert result["result"]["load_base"] == "0x555555554000"
    assert result["result"]["symbols"][0]["loaded_address"] == "0x555555555130"


def test_symbols_pie_prefers_exact_path_with_zero_offset(monkeypatch) -> None:
    def fake_run(cmd, check, capture_output, text):  # noqa: ANN001
        del check, capture_output, text
        if cmd[1] == "-h":
            return ProcResult("Type:                              DYN (Position-Independent Executable file)\n")
        return ProcResult(
            "Symbol table '.symtab' contains 2 entries:\n"
            "   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
            "     1: 0000000000001130    42 FUNC    GLOBAL DEFAULT   14 main\n"
        )

    monkeypatch.setattr("dynamiq.session.subprocess.run", fake_run)
    target = "/tmp/bin/a.out"
    maps = [
        {"start": "0x500000000000", "end": "0x500000001000", "perm": "r-x", "path": "/tmp/other/a.out", "offset": "0x0"},
        {"start": "0x555555554000", "end": "0x555555556000", "perm": "r-x", "path": "/tmp/bin/a.out", "offset": "0x0"},
        {"start": "0x555555557000", "end": "0x555555559000", "perm": "r--", "path": "/tmp/bin/a.out", "offset": "0x2000"},
    ]
    session = AnalysisSession(backend=FakeBackend(maps_result=maps))
    session.state.target = target

    result = session.symbols()

    assert result["result"]["elf_type"] == "DYN"
    assert result["result"]["load_base"] == "0x555555554000"
    assert result["result"]["symbols"][0]["loaded_address"] == "0x555555555130"


def test_symbols_pie_falls_back_to_basename_contains(monkeypatch) -> None:
    def fake_run(cmd, check, capture_output, text):  # noqa: ANN001
        del check, capture_output, text
        if cmd[1] == "-h":
            return ProcResult("Type:                              DYN (Position-Independent Executable file)\n")
        return ProcResult(
            "Symbol table '.symtab' contains 2 entries:\n"
            "   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
            "     1: 0000000000001130    42 FUNC    GLOBAL DEFAULT   14 main\n"
        )

    monkeypatch.setattr("dynamiq.session.subprocess.run", fake_run)
    target = "/tmp/x/sample_target"
    maps = [
        {"start": "0x400000", "end": "0x402000", "perm": "r-x", "name": "sample_target"},
    ]
    session = AnalysisSession(backend=FakeBackend(maps_result=maps))
    session.state.target = target

    result = session.symbols()

    assert result["result"]["load_base"] == "0x400000"
    assert result["result"]["symbols"][0]["loaded_address"] == "0x401130"


def test_symbols_include_imported_plt_entries_for_exec(monkeypatch) -> None:
    def fake_run(cmd, check, capture_output, text):  # noqa: ANN001
        del check, capture_output, text
        if cmd[0] == "readelf" and cmd[1] == "-h":
            return ProcResult("Type:                              EXEC (Executable file)\n")
        if cmd[0] == "readelf" and cmd[1] == "-Ws":
            return ProcResult(
                "Symbol table '.dynsym' contains 2 entries:\n"
                "   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
                "     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT   UND read\n"
            )
        if cmd[0] == "objdump":
            return ProcResult(
                "Disassembly of section .plt.sec:\n"
                "\n"
                "00000000004010b0 <read@plt>:\n"
                "  4010b0:\tf3 0f 1e fa\tendbr64\n"
            )
        raise AssertionError(cmd)

    monkeypatch.setattr("dynamiq.session.subprocess.run", fake_run)
    session = AnalysisSession(backend=FakeBackend(maps_result=[]))
    session.state.target = "/tmp/stripped.out"

    result = session.symbols(name_filter="read")
    symbols = result["result"]["symbols"]

    assert [item["name"] for item in symbols] == ["read", "read@plt"]
    assert symbols[0]["loaded_address"] is None
    assert symbols[1]["loaded_address"] == "0x4010b0"


def test_symbols_include_imported_plt_entries_for_pie(monkeypatch) -> None:
    def fake_run(cmd, check, capture_output, text):  # noqa: ANN001
        del check, capture_output, text
        if cmd[0] == "readelf" and cmd[1] == "-h":
            return ProcResult("Type:                              DYN (Position-Independent Executable file)\n")
        if cmd[0] == "readelf" and cmd[1] == "-Ws":
            return ProcResult(
                "Symbol table '.dynsym' contains 2 entries:\n"
                "   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
                "     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT   UND read\n"
            )
        if cmd[0] == "objdump":
            return ProcResult(
                "Disassembly of section .plt.sec:\n"
                "\n"
                "00000000000010b0 <read@plt>:\n"
                "    10b0:\tf3 0f 1e fa\tendbr64\n"
            )
        raise AssertionError(cmd)

    monkeypatch.setattr("dynamiq.session.subprocess.run", fake_run)
    maps = [{"start": "0x555555554000", "end": "0x555555556000", "perm": "r-x", "name": "stripped.out"}]
    session = AnalysisSession(backend=FakeBackend(maps_result=maps))
    session.state.target = "/tmp/stripped.out"

    result = session.symbols(name_filter="read")
    symbols = result["result"]["symbols"]

    assert [item["name"] for item in symbols] == ["read", "read@plt"]
    assert symbols[1]["loaded_address"] == "0x5555555550b0"
