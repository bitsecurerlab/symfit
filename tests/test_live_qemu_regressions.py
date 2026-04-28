from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import pytest

from dynamiq.backends.qemu_user_instrumented import QemuUserInstrumentedBackend
from dynamiq.errors import SessionTimeoutError
from dynamiq.session import AnalysisSession


def _compile_breakpoint_stress_binary(workdir: Path) -> Path:
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.skip("gcc is required for live regression tests")
    source = workdir / "bp_stress.c"
    binary = workdir / "bp_stress"
    source.write_text(
        (
            "#include <stdio.h>\n"
            "#include <stdint.h>\n"
            "\n"
            "volatile uint64_t sink = 0;\n"
            "\n"
            "__attribute__((noinline))\n"
            "void marker(uint64_t x) {\n"
            "    sink += (x ^ 0x5a5a5a5aULL);\n"
            "}\n"
            "\n"
            "int main(void) {\n"
            "    for (uint64_t i = 0; i < 200; i++) {\n"
            "        marker(i);\n"
            "    }\n"
            "    printf(\"done:%llu\\n\", (unsigned long long)(sink & 0xffff));\n"
            "    fflush(stdout);\n"
            "    return 0;\n"
            "}\n"
        ),
        encoding="utf-8",
    )
    subprocess.run(
        [gcc, "-O0", "-g", "-fno-omit-frame-pointer", "-o", str(binary), str(source)],
        check=True,
    )
    return binary


def _resolve_x86_64_qemu() -> str:
    candidates = [
        Path(__file__).resolve().parents[1] / "tools" / "qemu" / "qemu-x86_64-instrumented",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    discovered = shutil.which("qemu-x86_64")
    if discovered is None:
        pytest.skip("qemu-x86_64 not found")
    return discovered


def _marker_address(session: AnalysisSession) -> str:
    symbols = session.symbols(max_count=512, name_filter="marker")["result"]["symbols"]
    for sym in symbols:
        if sym.get("name") == "marker" and isinstance(sym.get("loaded_address"), str):
            return str(sym["loaded_address"])
    raise AssertionError("marker symbol not found in live target")


def _start_live_session(binary: Path, cwd: Path) -> AnalysisSession:
    session = AnalysisSession(backend=QemuUserInstrumentedBackend())
    qemu_user_path = _resolve_x86_64_qemu()
    try:
        session.start(
            target=str(binary),
            args=[],
            cwd=str(cwd),
            qemu_config={
                "launch": True,
                "qemu_user_path": qemu_user_path,
                "launch_connect_timeout": 10.0,
            },
        )
    except SessionTimeoutError:
        pytest.skip("live qemu RPC socket unavailable in this environment")
    return session


@pytest.mark.live_qemu
def test_live_breakpoint_rehit_stability(tmp_path: Path) -> None:
    binary = _compile_breakpoint_stress_binary(tmp_path)
    session = _start_live_session(binary, tmp_path)
    try:
        marker = _marker_address(session)
        session.bp_add(marker)

        # Repeatedly continue through the same breakpoint; this catches
        # regressions where continue immediately re-hits with no progress.
        for _ in range(8):
            hit = session.bp_run(timeout=5.0)
            assert hit["result"]["matched_address"] == marker.lower()
            state = hit["state"]
            assert state["session_status"] == "paused"
            assert state["last_rpc_method"] == "resume_until_address"

        session.bp_clear()
        session.resume(timeout=5.0)

        deadline = time.time() + 5.0
        final_state = None
        while time.time() < deadline:
            state = session.get_state()["state"]
            final_state = state
            if state.get("session_status") == "exited":
                break
            time.sleep(0.05)

        assert isinstance(final_state, dict)
        assert final_state.get("session_status") == "exited"
        assert final_state.get("exit_code") == 0
        assert final_state.get("exit_signal") is None
    finally:
        session.close()


@pytest.mark.live_qemu
def test_live_session_advance_insn_and_bb_modes(tmp_path: Path) -> None:
    binary = _compile_breakpoint_stress_binary(tmp_path)
    session = _start_live_session(binary, tmp_path)
    try:
        regs_before = session.get_registers(["rip"])["result"]["registers"]
        rip_before = regs_before["rip"]

        insn = session.advance(mode="insn", count=2, timeout=5.0)
        regs_after_insn = session.get_registers(["rip"])["result"]["registers"]

        assert insn["result"]["mode"] == "insn"
        assert insn["result"]["completed"] is True
        assert insn["result"]["requested_count"] == 2
        assert insn["result"]["actual_count"] == 2
        assert insn["result"]["stop_reason"] == "target_reached"
        assert insn["state"]["last_rpc_method"] == "single_step"
        assert regs_after_insn["rip"] == insn["result"]["pc"]
        assert regs_after_insn["rip"] != rip_before

        bb = session.advance(mode="bb", count=1, timeout=5.0)
        regs_after_bb = session.get_registers(["rip"])["result"]["registers"]

        assert bb["result"]["mode"] == "bb"
        assert bb["result"]["completed"] is True
        assert bb["result"]["requested_count"] == 1
        assert bb["result"]["actual_count"] == 1
        assert bb["result"]["stop_reason"] == "target_reached"
        assert bb["state"]["last_rpc_method"] == "resume_until_basic_block"
        assert regs_after_bb["rip"] == bb["result"]["pc"]
        assert regs_after_bb["rip"] != regs_after_insn["rip"]
    finally:
        session.close()


@pytest.mark.live_qemu
def test_live_session_advance_return_mode(tmp_path: Path) -> None:
    binary = _compile_breakpoint_stress_binary(tmp_path)
    session = _start_live_session(binary, tmp_path)
    try:
        marker = _marker_address(session)
        session.bp_add(marker)

        hit = session.advance(mode="continue", timeout=5.0)
        regs_at_marker = session.get_registers(["rip"])["result"]["registers"]

        assert hit["result"]["stop_reason"] == "breakpoint"
        assert hit["result"]["matched_address"] == marker.lower()
        assert regs_at_marker["rip"] == marker.lower()
        assert hit["state"]["session_status"] == "paused"

        returned = session.advance(mode="return", timeout=5.0)
        regs_after_return = session.get_registers(["rip"])["result"]["registers"]

        assert returned["result"]["mode"] == "return"
        assert returned["result"]["completed"] is True
        assert returned["result"]["stop_reason"] == "target_reached"
        assert returned["result"]["matched_address"] == returned["result"]["return_address"]
        assert regs_after_return["rip"] == returned["result"]["return_address"]
        assert returned["state"]["session_status"] == "paused"
        assert regs_after_return["rip"] != marker.lower()
    finally:
        session.close()
