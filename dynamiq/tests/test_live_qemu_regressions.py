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


def _compile_dlopen_breakpoint_target(workdir: Path) -> tuple[Path, Path]:
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.skip("gcc is required for live regression tests")
    library_source = workdir / "dynamiq_bp_lib.c"
    library = workdir / "libdynamiq_bp_e2e.so"
    target_source = workdir / "dlopen_bp_main.c"
    target = workdir / "dlopen_bp_main"

    library_source.write_text(
        (
            "#include <stdint.h>\n"
            "\n"
            "volatile uint64_t dynamiq_bp_sink = 0;\n"
            "\n"
            "__attribute__((noinline))\n"
            "void dynamiq_bp_symbol_marker(uint64_t value) {\n"
            "    dynamiq_bp_sink += value + 0x11;\n"
            "}\n"
            "\n"
            "__attribute__((noinline))\n"
            "void dynamiq_bp_offset_marker(uint64_t value) {\n"
            "    dynamiq_bp_sink += value + 0x22;\n"
            "}\n"
        ),
        encoding="utf-8",
    )
    subprocess.run(
        [gcc, "-shared", "-fPIC", "-O0", "-g", "-o", str(library), str(library_source)],
        check=True,
    )

    target_source.write_text(
        (
            "#include <dlfcn.h>\n"
            "#include <stdint.h>\n"
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            "\n"
            "typedef void (*marker_fn)(uint64_t);\n"
            "\n"
            "__attribute__((noinline))\n"
            "void after_dlopen_marker(void) {\n"
            "    asm volatile(\"\" ::: \"memory\");\n"
            "}\n"
            "\n"
            "int main(void) {\n"
            "    void *handle = dlopen(\"./libdynamiq_bp_e2e.so\", RTLD_NOW);\n"
            "    if (!handle) {\n"
            "        puts(dlerror());\n"
            "        return 2;\n"
            "    }\n"
            "    marker_fn symbol_marker = (marker_fn)dlsym(handle, \"dynamiq_bp_symbol_marker\");\n"
            "    marker_fn offset_marker = (marker_fn)dlsym(handle, \"dynamiq_bp_offset_marker\");\n"
            "    if (!symbol_marker || !offset_marker) {\n"
            "        return 3;\n"
            "    }\n"
            "    after_dlopen_marker();\n"
            "    symbol_marker(7);\n"
            "    offset_marker(9);\n"
            "    dlclose(handle);\n"
            "    return 0;\n"
            "}\n"
        ),
        encoding="utf-8",
    )
    subprocess.run(
        [gcc, "-O0", "-g", "-fno-omit-frame-pointer", "-o", str(target), str(target_source), "-ldl"],
        check=True,
    )
    return target, library


def _resolve_x86_64_qemu() -> str:
    candidates = [
        Path(__file__).resolve().parents[2] / "build" / "symfit" / "x86_64-linux-user" / "symfit-x86_64",
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


def _symbol_value(path: Path, name: str) -> str:
    proc = subprocess.run(
        ["nm", "-D", str(path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == name:
            return "0x" + parts[0].lower()
    raise AssertionError(f"symbol not found in {path}: {name}")


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
def test_live_dlopen_module_breakpoints_resolve_under_aslr(tmp_path: Path) -> None:
    binary, library = _compile_dlopen_breakpoint_target(tmp_path)
    session = _start_live_session(binary, tmp_path)
    try:
        after_dlopen = None
        symbols = session.symbols(max_count=512, name_filter="after_dlopen_marker")["result"]["symbols"]
        for sym in symbols:
            if sym.get("name") == "after_dlopen_marker" and isinstance(sym.get("loaded_address"), str):
                after_dlopen = str(sym["loaded_address"])
                break
        assert after_dlopen is not None

        session.bp_add(after_dlopen)
        loaded = session.bp_run(timeout=5.0, max_steps=10000)
        assert loaded["result"]["matched_address"] == after_dlopen.lower()
        session.bp_clear()

        symbol_bp = session.bp_add(
            module=library.name,
            symbol="dynamiq_bp_symbol_marker",
        )
        symbol_hit = session.bp_run(timeout=5.0, max_steps=10000)
        assert symbol_hit["result"]["matched_address"] == symbol_bp["result"]["address"]
        assert symbol_bp["result"]["resolved"]["module"] == library.name
        assert symbol_bp["result"]["resolved"]["matched_symbol"] == "dynamiq_bp_symbol_marker"
        session.bp_clear()

        offset = _symbol_value(library, "dynamiq_bp_offset_marker")
        offset_bp = session.bp_add(module=library.name, offset=offset)
        offset_hit = session.bp_run(timeout=5.0, max_steps=10000)
        assert offset_hit["result"]["matched_address"] == offset_bp["result"]["address"]
        assert offset_bp["result"]["resolved"]["module"] == library.name
        assert offset_bp["result"]["resolved"]["offset"] == hex(int(offset, 0))
    finally:
        session.close()


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
