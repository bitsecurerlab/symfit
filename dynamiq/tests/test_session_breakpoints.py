from __future__ import annotations

import pytest

from dynamiq.errors import InvalidStateError, SessionTimeoutError
from dynamiq.session import AnalysisSession


class FakeBackend:
    def __init__(self) -> None:
        self.pc_seq = ["0x1000", "0x1004", "0x1008", "0x100c"]
        self.idx = 0
        self.step_calls = 0
        self.run_until_calls = 0
        self.pause_calls = 0
        self.set_breakpoints_calls: list[list[str]] = []

    def start(self, target, args, cwd, qemu_config=None):  # noqa: ANN001
        del target, args, cwd, qemu_config

    def resume(self, timeout):  # noqa: ANN001
        del timeout
        return {"state": {"session_status": "running"}, "result": {}}

    def pause(self, timeout):  # noqa: ANN001
        del timeout
        self.pause_calls += 1
        return {"state": {"session_status": "paused"}, "result": {}}

    def run_until_event(self, event_types, timeout):  # noqa: ANN001
        del event_types, timeout
        return {"state": {}, "result": {}}

    def run_until_address(self, address, timeout):  # noqa: ANN001
        self.run_until_calls += 1
        del timeout
        return {"state": {"pc": address, "session_status": "paused"}, "result": {"matched_address": address}}

    def set_breakpoints(self, addresses):  # noqa: ANN001
        normalized = list(addresses)
        self.set_breakpoints_calls.append(normalized)
        return {
            "state": {},
            "result": {"armed": bool(normalized), "breakpoints": normalized},
        }

    def step(self, count, timeout):  # noqa: ANN001
        del timeout
        self.step_calls += 1
        self.idx = min(self.idx + count, len(self.pc_seq) - 1)
        pc = self.pc_seq[self.idx]
        return {"state": {"pc": pc, "session_status": "paused"}, "result": {"pc": pc, "count": count}}

    def advance_basic_blocks(self, count, timeout):  # noqa: ANN001
        del count, timeout
        return {"state": {}, "result": {}}

    def write_stdin(self, data):  # noqa: ANN001
        del data
        return {"state": {}, "result": {}}

    def read_stdout(self, cursor=0, max_chars=4096):  # noqa: ANN001
        del cursor, max_chars
        return {"state": {}, "result": {"data": "", "cursor": 0, "eof": False}}

    def read_stderr(self, cursor=0, max_chars=4096):  # noqa: ANN001
        del cursor, max_chars
        return {"state": {}, "result": {"data": "", "cursor": 0, "eof": False}}

    def get_registers(self, names=None):  # noqa: ANN001
        del names
        return {"state": {"pc": self.pc_seq[self.idx]}, "result": {"registers": {"rip": self.pc_seq[self.idx]}}}

    def read_memory(self, address, size):  # noqa: ANN001
        del address, size
        return {"state": {}, "result": {}}

    def disassemble(self, address, count):  # noqa: ANN001
        del address, count
        return {"state": {}, "result": {}}

    def list_memory_maps(self):
        return {"state": {}, "result": {}}

    def recent_path_constraints(self, limit=16):  # noqa: ANN001
        count = min(limit, 2)
        return {
            "state": {},
            "result": {
                "constraints": [
                    {"label": "0x12", "pc": "0x1008", "taken": True, "op": "ICmp"},
                    {"label": "0x6", "pc": "0x1004", "taken": True, "op": "ICmp"},
                ][:count],
                "count": count,
                "truncated": False,
            },
        }

    def path_constraint_closure(self, label):  # noqa: ANN001
        return {
            "state": {},
            "result": {
                "root": {"label": label, "op": "ICmp", "taken": True},
                "constraints": [{"label": "0x6", "op": "ICmp", "taken": True}],
                "count": 1,
            },
        }

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
        return {"session_status": "paused", "pc": self.pc_seq[self.idx], "capabilities": self.capabilities()}

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


class FakeBackendNoRegisterReads(FakeBackend):
    def get_registers(self, names=None):  # noqa: ANN001
        del names
        raise RuntimeError("unsupported_arch: get_registers is only implemented for x86_64")


class FakeBackendExitBeforeBreakpoint(FakeBackend):
    def break_at_addresses(self, addresses, timeout, max_steps=10000):  # noqa: ANN001
        del addresses, timeout, max_steps
        return {
            "state": {"session_status": "exited", "pc": "0x1004"},
            "result": {"status": "exited", "matched": False, "pc": "0x1004", "matched_pc": "0x0"},
        }


class FakeBackendContinueIo(FakeBackend):
    def __init__(self) -> None:
        super().__init__()
        self.stdout_reads = 0
        self.state_reads = 0
        self.running = False

    def resume(self, timeout):  # noqa: ANN001
        del timeout
        self.running = True
        return {"state": {"session_status": "running"}, "result": {}}

    def pause(self, timeout):  # noqa: ANN001
        del timeout
        self.pause_calls += 1
        self.running = False
        return {"state": {"session_status": "paused"}, "result": {}}

    def get_state(self):
        self.state_reads += 1
        if self.running and self.state_reads >= 2:
            self.running = False
        status = "running" if self.running else "paused"
        return {"session_status": status, "pc": self.pc_seq[self.idx], "capabilities": self.capabilities()}

    def read_stdout(self, cursor=0, max_chars=4096):  # noqa: ANN001
        del max_chars
        self.stdout_reads += 1
        return {"state": {}, "result": {"data": ">", "cursor": cursor + 1, "eof": False}}


class FakeBackendContinueTimeout(FakeBackend):
    def __init__(self) -> None:
        super().__init__()
        self.running = False

    def resume(self, timeout):  # noqa: ANN001
        del timeout
        self.running = True
        return {"state": {"session_status": "running"}, "result": {}}

    def get_state(self):
        status = "running" if self.running else "paused"
        return {"session_status": status, "pc": self.pc_seq[self.idx], "capabilities": self.capabilities()}

    def read_stdout(self, cursor=0, max_chars=4096):  # noqa: ANN001
        del max_chars
        return {"state": {}, "result": {"data": "", "cursor": cursor, "eof": False}}

    def read_stderr(self, cursor=0, max_chars=4096):  # noqa: ANN001
        del max_chars
        return {"state": {}, "result": {"data": "", "cursor": cursor, "eof": False}}


class FakeBackendContinueTerminalPause(FakeBackend):
    def __init__(self) -> None:
        super().__init__()
        self.running = False

    def resume(self, timeout):  # noqa: ANN001
        del timeout
        self.running = True
        return {"state": {"session_status": "running"}, "result": {}}

    def get_state(self):
        if self.running:
            self.running = False
            return {
                "session_status": "paused",
                "pc": self.pc_seq[self.idx],
                "pending_termination": True,
                "termination_kind": "exit",
                "capabilities": self.capabilities(),
            }
        return {
            "session_status": "paused",
            "pc": self.pc_seq[self.idx],
            "pending_termination": True,
            "termination_kind": "exit",
            "capabilities": self.capabilities(),
        }

    def read_stdout(self, cursor=0, max_chars=4096):  # noqa: ANN001
        del max_chars
        return {"state": {}, "result": {"data": "", "cursor": cursor, "eof": False}}

    def read_stderr(self, cursor=0, max_chars=4096):  # noqa: ANN001
        del max_chars
        return {"state": {}, "result": {"data": "", "cursor": cursor, "eof": False}}


class FakeBackendContinueSilentIo(FakeBackend):
    def __init__(self) -> None:
        super().__init__()
        self.running = False

    def resume(self, timeout):  # noqa: ANN001
        del timeout
        self.running = True
        return {"state": {"session_status": "running"}, "result": {}}

    def get_state(self):
        if self.running:
            self.running = False
            return {"session_status": "paused", "pc": self.pc_seq[self.idx], "capabilities": self.capabilities()}
        return {"session_status": "paused", "pc": self.pc_seq[self.idx], "capabilities": self.capabilities()}

    def read_stdout(self, cursor=0, max_chars=4096):  # noqa: ANN001
        del max_chars
        return {"state": {}, "result": {"data": "", "cursor": cursor, "eof": False}}

    def read_stderr(self, cursor=0, max_chars=4096):  # noqa: ANN001
        del max_chars
        return {"state": {}, "result": {"data": "", "cursor": cursor, "eof": False}}


class FakeBackendAdvanceBasicBlocks(FakeBackend):
    def __init__(self) -> None:
        super().__init__()
        self.bb_calls = 0

    def advance_basic_blocks(self, count, timeout):  # noqa: ANN001
        del timeout
        self.bb_calls += 1
        self.idx = min(self.idx + count, len(self.pc_seq) - 1)
        pc = self.pc_seq[self.idx]
        return {"state": {"pc": pc, "session_status": "paused"}, "result": {"pc": pc, "count": count}}


class FakeBackendContinueExited(FakeBackend):
    def __init__(self) -> None:
        super().__init__()
        self.running = False

    def resume(self, timeout):  # noqa: ANN001
        del timeout
        self.running = True
        return {"state": {"session_status": "running"}, "result": {}}

    def get_state(self):
        if self.running:
            self.running = False
            return {"session_status": "exited", "pc": self.pc_seq[self.idx], "capabilities": self.capabilities()}
        return {"session_status": "exited", "pc": self.pc_seq[self.idx], "capabilities": self.capabilities()}

    def read_stdout(self, cursor=0, max_chars=4096):  # noqa: ANN001
        del max_chars
        return {"state": {}, "result": {"data": "", "cursor": cursor, "eof": False}}

    def read_stderr(self, cursor=0, max_chars=4096):  # noqa: ANN001
        del max_chars
        return {"state": {}, "result": {"data": "", "cursor": cursor, "eof": False}}


def test_session_bp_run_multiple_breakpoints_selects_nearest_forward() -> None:
    session = AnalysisSession(backend=FakeBackend())
    session.state.session_status = "paused"
    session.state.pc = "0x1004"
    session.bp_add("0x1008")
    session.bp_add("0x2000")

    result = session.bp_run(timeout=1.0, max_steps=10)

    assert result["result"]["matched_address"] == "0x1008"
    assert result["result"]["steps"] == 2
    assert session.backend.run_until_calls == 0
    assert session.backend.step_calls == 2


def test_session_bp_add_arms_running_backend_without_pausing() -> None:
    backend = FakeBackend()
    session = AnalysisSession(backend=backend)
    session.state.session_status = "running"

    result = session.bp_add("0x1008")

    assert result["state"]["session_status"] == "running"
    assert result["result"]["armed"] is True
    assert result["result"]["breakpoints"] == ["0x1008"]
    assert backend.pause_calls == 0
    assert backend.set_breakpoints_calls == [["0x1008"]]


def test_session_bp_add_resolves_module_relative_offset() -> None:
    backend = FakeBackend()
    backend.list_memory_maps = lambda: {  # type: ignore[method-assign]
        "state": {},
        "result": {
            "maps": {
                "regions": [
                    {
                        "start": "0x7f00001000",
                        "end": "0x7f00002000",
                        "perm": "r-x",
                        "path": "/usr/lib/libffmpeg.so",
                        "offset": "0x1000",
                    },
                    {
                        "start": "0x7f00004000",
                        "end": "0x7f00005000",
                        "perm": "r--",
                        "path": "/usr/lib/libffmpeg.so",
                        "offset": "0x4000",
                    },
                ]
            }
        },
    }
    session = AnalysisSession(backend=backend)

    result = session.bp_add(module="libffmpeg.so", offset="0xad1548")

    assert result["result"]["address"] == "0x7f00ad1548"
    assert result["result"]["resolved"]["module_base"] == "0x7f00000000"
    assert result["result"]["resolved"]["offset"] == "0xad1548"
    assert result["result"]["armed"] is True
    assert backend.set_breakpoints_calls == [["0x7f00ad1548"]]


def test_session_bp_add_resolves_module_relative_offset_while_running_from_backend_maps() -> None:
    backend = FakeBackend()
    backend.list_memory_maps = lambda: {  # type: ignore[method-assign]
        "state": {"session_status": "running"},
        "result": {
            "maps": {
                "regions": [
                    {
                        "start": "0x7f00001000",
                        "end": "0x7f00002000",
                        "perm": "r-x",
                        "path": "/usr/lib/libffmpeg.so",
                        "offset": "0x1000",
                    }
                ]
            }
        },
    }
    session = AnalysisSession(backend=backend)
    session.state.session_status = "running"

    result = session.bp_add(module="libffmpeg.so", offset="0xad1548")

    assert result["state"]["session_status"] == "running"
    assert result["result"]["address"] == "0x7f00ad1548"
    assert result["result"]["armed"] is True
    assert backend.set_breakpoints_calls == [["0x7f00ad1548"]]


def test_session_bp_add_resolves_symbol_in_module(monkeypatch) -> None:
    def fake_run(cmd, check, capture_output, text):  # noqa: ANN001
        del check, capture_output, text
        if cmd[0] == "readelf" and cmd[1] == "-h":
            return ProcResult("Type:                              DYN (Shared object file)\n")
        if cmd[0] == "readelf":
            return ProcResult(
                "Symbol table '.dynsym' contains 2 entries:\n"
                "   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"
                "     1: 0000000000ad1548    42 FUNC    GLOBAL DEFAULT   14 write_frame_8\n"
            )
        raise AssertionError(f"unexpected command: {cmd}")

    monkeypatch.setattr("dynamiq.session.subprocess.run", fake_run)
    backend = FakeBackend()
    backend.list_memory_maps = lambda: {  # type: ignore[method-assign]
        "state": {},
        "result": {
            "maps": {
                "regions": [
                    {
                        "start": "0x7f00001000",
                        "end": "0x7f00002000",
                        "perm": "r-x",
                        "path": "/usr/lib/libffmpeg.so",
                        "offset": "0x1000",
                    }
                ]
            }
        },
    }
    session = AnalysisSession(backend=backend)

    result = session.bp_add(symbol="write_frame_8", module="libffmpeg.so")

    assert result["result"]["address"] == "0x7f00ad1548"
    assert result["result"]["resolved"]["matched_symbol"] == "write_frame_8"
    assert result["result"]["resolved"]["module_base"] == "0x7f00000000"


def test_session_bp_run_multiple_breakpoints_wraps_to_first_when_all_behind() -> None:
    session = AnalysisSession(backend=FakeBackend())
    session.state.session_status = "paused"
    session.state.pc = "0x1004"
    session.bp_add("0x1008")
    session.bp_add("0x100c")

    result = session.bp_run(timeout=1.0, max_steps=10)

    assert result["result"]["matched_address"] == "0x1008"


def test_session_bp_run_single_breakpoint_uses_run_until_address() -> None:
    backend = FakeBackend()
    session = AnalysisSession(backend=backend)
    session.state.session_status = "paused"
    session.bp_add("0x1008")

    result = session.bp_run(timeout=1.0, max_steps=10)

    assert result["result"]["matched_address"] == "0x1008"
    assert backend.run_until_calls == 0
    assert backend.step_calls == 2


def test_session_bp_run_rejects_backend_stop_before_breakpoint() -> None:
    session = AnalysisSession(backend=FakeBackendExitBeforeBreakpoint())
    session.state.session_status = "paused"
    session.bp_add("0x1008")

    with pytest.raises(InvalidStateError, match="stopped before hitting"):
        session.bp_run(timeout=1.0, max_steps=10)


def test_session_close_clears_breakpoints_before_reuse() -> None:
    backend = FakeBackend()
    session = AnalysisSession(backend=backend)

    session.start(target="/tmp/first", args=[], cwd=None)
    session.bp_add("0x1008")
    assert session.bp_list()["result"]["breakpoints"] == ["0x1008"]

    session.close()
    assert session.breakpoints == []

    session.start(target="/tmp/second", args=[], cwd=None)
    assert session.bp_list()["result"]["breakpoints"] == []


def test_session_bp_run_uses_live_pc_not_stale_state_pc() -> None:
    backend = FakeBackend()
    session = AnalysisSession(backend=backend)
    session.state.session_status = "paused"
    # Stale cached PC appears to be already at breakpoint.
    session.state.pc = "0x1008"
    session.bp_add("0x1008")

    result = session.bp_run(timeout=1.0, max_steps=10)

    # Live backend PC is 0x1000, so bp_run must resume to 0x1008
    # instead of immediately short-circuiting on stale cached state.pc.
    assert result["result"]["matched_address"] == "0x1008"
    assert backend.run_until_calls == 0


def test_session_bp_run_works_without_register_reads() -> None:
    backend = FakeBackendNoRegisterReads()
    session = AnalysisSession(backend=backend)
    session.state.session_status = "paused"
    session.state.pc = "0x1004"
    session.bp_add("0x1008")
    session.bp_add("0x100c")

    result = session.bp_run(timeout=1.0, max_steps=10)

    assert result["result"]["matched_address"] == "0x1008"
    assert backend.run_until_calls == 0


def test_session_bp_run_does_not_immediately_rehit_current_breakpoint() -> None:
    backend = FakeBackend()
    backend.idx = 2  # live PC at 0x1008
    session = AnalysisSession(backend=backend)
    session.state.session_status = "paused"
    session.bp_add("0x1008")
    session.bp_add("0x100c")

    result = session.bp_run(timeout=1.0, max_steps=10)

    assert result["result"]["matched_address"] == "0x100c"
    assert backend.step_calls == 1
    assert backend.run_until_calls == 0


def test_session_pause_noop_when_idle_or_paused() -> None:
    backend = FakeBackend()
    session = AnalysisSession(backend=backend)
    session.state.session_status = "idle"

    first = session.pause(timeout=1.0)
    assert first["result"]["noop"] is True
    assert first["state"]["session_status"] == "paused"
    assert backend.pause_calls == 0

    second = session.pause(timeout=1.0)
    assert second["result"]["noop"] is True
    assert second["state"]["session_status"] == "paused"
    assert backend.pause_calls == 0


def test_session_pause_raises_when_not_started() -> None:
    session = AnalysisSession(backend=FakeBackend())
    with pytest.raises(InvalidStateError, match="session is not started"):
        session.pause(timeout=1.0)


def test_session_advance_continue_uses_breakpoint_logic_when_present() -> None:
    backend = FakeBackend()
    session = AnalysisSession(backend=backend)
    session.state.session_status = "paused"
    session.bp_add("0x1008")

    result = session.advance(mode="continue", timeout=1.0)

    assert result["command"] == "advance"
    assert result["result"]["mode"] == "continue"
    assert result["result"]["stop_reason"] == "breakpoint"
    assert result["result"]["matched_address"] == "0x1008"


def test_session_advance_insn_counts_and_stops_at_target() -> None:
    backend = FakeBackend()
    session = AnalysisSession(backend=backend)
    session.state.session_status = "paused"

    result = session.advance(mode="insn", count=2, timeout=1.0)

    assert result["result"]["mode"] == "insn"
    assert result["result"]["completed"] is True
    assert result["result"]["requested_count"] == 2
    assert result["result"]["actual_count"] == 2
    assert backend.step_calls == 2


def test_session_advance_bb_counts_and_stops_at_target() -> None:
    backend = FakeBackendAdvanceBasicBlocks()
    session = AnalysisSession(backend=backend)
    session.state.session_status = "paused"

    result = session.advance(mode="bb", count=2, timeout=1.0)

    assert result["result"]["mode"] == "bb"
    assert result["result"]["completed"] is True
    assert result["result"]["requested_count"] == 2
    assert result["result"]["actual_count"] == 2
    assert backend.bb_calls == 2


def test_session_advance_return_uses_current_frame_return_address(monkeypatch) -> None:  # noqa: ANN001
    backend = FakeBackend()
    session = AnalysisSession(backend=backend)
    session.state.session_status = "paused"
    monkeypatch.setattr(AnalysisSession, "_current_return_address", lambda self: 0x1008)

    result = session.advance(mode="return", timeout=1.0)

    assert result["result"]["mode"] == "return"
    assert result["result"]["return_address"] == "0x1008"
    assert result["result"]["matched_address"] == "0x1008"
    assert result["result"]["completed"] is True
    assert result["result"]["stop_reason"] == "target_reached"


def test_session_advance_insn_stops_early_on_breakpoint() -> None:
    backend = FakeBackend()
    session = AnalysisSession(backend=backend)
    session.state.session_status = "paused"
    session.bp_add("0x1008")

    result = session.advance(mode="insn", count=3, timeout=1.0)

    assert result["result"]["mode"] == "insn"
    assert result["result"]["completed"] is False
    assert result["result"]["stop_reason"] == "breakpoint"
    assert result["result"]["actual_count"] == 2
    assert backend.step_calls == 2


def test_session_advance_rejects_invalid_mode() -> None:
    session = AnalysisSession(backend=FakeBackend())
    with pytest.raises(InvalidStateError, match="advance mode"):
        session.advance(mode="weird", timeout=1.0)


def test_session_advance_rejects_count_for_continue() -> None:
    session = AnalysisSession(backend=FakeBackend())
    with pytest.raises(InvalidStateError, match="only valid for insn and bb modes"):
        session.advance(mode="continue", count=1, timeout=1.0)


def test_session_advance_rejects_nonpositive_count_for_insn() -> None:
    session = AnalysisSession(backend=FakeBackend())
    with pytest.raises(InvalidStateError, match="count must be >= 1"):
        session.advance(mode="insn", count=0, timeout=1.0)


def test_session_advance_continue_ignores_stdout_until_real_pause() -> None:
    backend = FakeBackendContinueIo()
    session = AnalysisSession(backend=backend)
    session.state.session_status = "paused"

    result = session.advance(mode="continue", timeout=1.0)

    assert result["result"]["mode"] == "continue"
    assert result["result"]["stop_reason"] == "io"
    assert result["result"]["stdout_ready"] is False
    assert result["result"]["stderr_ready"] is False
    assert backend.pause_calls == 0


def test_session_advance_continue_reports_exited_without_io() -> None:
    backend = FakeBackendContinueExited()
    session = AnalysisSession(backend=backend)
    session.state.session_status = "paused"

    result = session.advance(mode="continue", timeout=1.0)

    assert result["result"]["mode"] == "continue"
    assert result["result"]["completed"] is False
    assert result["result"]["stop_reason"] == "exited"
    assert result["state"]["session_status"] == "exited"


def test_session_advance_continue_reports_terminal_pause_before_exit() -> None:
    backend = FakeBackendContinueTerminalPause()
    session = AnalysisSession(backend=backend)
    session.state.session_status = "paused"

    result = session.advance(mode="continue", timeout=1.0)

    assert result["result"]["mode"] == "continue"
    assert result["result"]["completed"] is False
    assert result["result"]["stop_reason"] == "termination_pending"
    assert result["result"]["termination_kind"] == "exit"
    assert result["state"]["session_status"] == "paused"
    assert result["state"]["pending_termination"] is True
    assert result["state"]["termination_kind"] == "exit"


def test_session_advance_continue_classifies_silent_pause_as_io() -> None:
    backend = FakeBackendContinueSilentIo()
    session = AnalysisSession(backend=backend)
    session.state.session_status = "paused"

    result = session.advance(mode="continue", timeout=1.0)

    assert result["result"]["mode"] == "continue"
    assert result["result"]["completed"] is False
    assert result["result"]["stop_reason"] == "io"
    assert result["result"]["stdout_ready"] is False
    assert result["result"]["stderr_ready"] is False


def test_session_advance_continue_times_out_non_fatally() -> None:
    backend = FakeBackendContinueTimeout()
    session = AnalysisSession(backend=backend)
    session.state.session_status = "paused"

    result = session.advance(mode="continue", timeout=0.1)

    assert result["result"]["mode"] == "continue"
    assert result["result"]["completed"] is False
    assert result["result"]["timed_out"] is True
    assert result["result"]["stop_reason"] == "running"
    assert result["state"]["session_status"] == "running"


def test_session_recent_path_constraints_forwards_backend_result() -> None:
    session = AnalysisSession(backend=FakeBackend())
    session.start("target.bin")

    result = session.recent_path_constraints(limit=4)

    assert result["command"] == "recent_path_constraints"
    assert result["result"]["count"] == 2
    assert result["result"]["constraints"][0]["label"] == "0x12"


def test_session_path_constraint_closure_forwards_backend_result() -> None:
    session = AnalysisSession(backend=FakeBackend())
    session.start("target.bin")

    result = session.path_constraint_closure("0x12")

    assert result["command"] == "path_constraint_closure"
    assert result["result"]["root"]["label"] == "0x12"
    assert result["result"]["root"]["taken"] is True
    assert result["result"]["constraints"][0]["label"] == "0x6"
    assert result["result"]["constraints"][0]["taken"] is True
