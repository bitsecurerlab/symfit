from __future__ import annotations

import shutil
import subprocess
import time
from pathlib import Path

import pytest

from dynamiq.backends.qemu_user_instrumented import QemuUserInstrumentedBackend
from dynamiq.errors import SessionTimeoutError
from dynamiq.session import AnalysisSession


def _compile_stdin_echo_binary(workdir: Path) -> Path:
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.skip("gcc is required for live stdin roundtrip test")
    source = workdir / "stdin_echo.c"
    binary = workdir / "stdin_echo"
    source.write_text(
        (
            "#include <stdio.h>\n"
            "#include <unistd.h>\n"
            "\n"
            "int main(void) {\n"
            "    char buf[256];\n"
            "    if (fgets(buf, sizeof(buf), stdin) == NULL) {\n"
            "        return 2;\n"
            "    }\n"
            "    printf(\"ECHO:%s\", buf);\n"
            "    fflush(stdout);\n"
            "    usleep(200000);\n"
            "    return 0;\n"
            "}\n"
        ),
        encoding="utf-8",
    )
    subprocess.run([gcc, str(source), "-O0", "-g", "-o", str(binary)], check=True)
    return binary


def _resolve_x86_64_qemu() -> str:
    local_qemu = Path(__file__).resolve().parents[2] / "build" / "symfit" / "x86_64-linux-user" / "symfit-x86_64"
    if local_qemu.exists():
        return str(local_qemu)
    discovered = shutil.which("qemu-x86_64")
    if discovered is None:
        pytest.skip("qemu-x86_64 not found")
    return discovered


@pytest.mark.live_qemu
def test_live_qemu_stdin_roundtrip(tmp_path: Path) -> None:
    binary = _compile_stdin_echo_binary(tmp_path)
    backend = QemuUserInstrumentedBackend()
    qemu_user_path = _resolve_x86_64_qemu()

    backend.start(
        target=str(binary),
        args=[],
        cwd=str(tmp_path),
        qemu_config={
            "launch": True,
            "qemu_user_path": qemu_user_path,
            "launch_connect_timeout": 5.0,
        },
    )
    try:
        backend.resume(timeout=1.0)
        backend.write_stdin("ping\n")
        cursor = 0
        seen = ""
        deadline = time.time() + 3.0
        while time.time() < deadline:
            out = backend.read_stdout(cursor=cursor, max_chars=4096)["result"]
            cursor = int(out["cursor"])
            chunk = str(out["data"])
            if chunk:
                seen += chunk
                if "ECHO:ping" in seen:
                    break
            time.sleep(0.05)

        assert "ECHO:ping" in seen
    finally:
        backend.close()


@pytest.mark.live_qemu
def test_live_session_advance_continue_stops_on_io_and_exit(tmp_path: Path) -> None:
    binary = _compile_stdin_echo_binary(tmp_path)
    session = AnalysisSession(backend=QemuUserInstrumentedBackend())
    qemu_user_path = _resolve_x86_64_qemu()

    try:
        session.start(
            target=str(binary),
            args=[],
            cwd=str(tmp_path),
            qemu_config={
                "launch": True,
                "qemu_user_path": qemu_user_path,
                "launch_connect_timeout": 5.0,
            },
        )
    except SessionTimeoutError:
        pytest.skip("live qemu RPC socket unavailable in this environment")

    try:
        first = session.advance(mode="continue", timeout=3.0)
        assert first["result"]["mode"] == "continue"
        assert first["result"]["completed"] is False
        assert first["result"]["stop_reason"] == "io"
        assert first["result"]["stdout_ready"] is False
        assert first["result"]["stderr_ready"] is False
        assert first["state"]["session_status"] == "paused"

        session.write_stdin("ping\n")

        second = session.advance(mode="continue", timeout=3.0)
        assert second["result"]["mode"] == "continue"
        assert second["result"]["completed"] is False
        assert second["result"]["stop_reason"] == "exited"

        stdout = session.read_stdout(max_chars=4096)["result"]["data"]
        assert "ECHO:ping" in stdout

        deadline = time.time() + 3.0
        final_state = None
        while time.time() < deadline:
            final_state = session.get_state()["state"]
            if final_state.get("session_status") == "exited":
                break
            time.sleep(0.05)

        assert isinstance(final_state, dict)
        assert final_state.get("session_status") == "exited"
        assert final_state.get("exit_code") == 0
    finally:
        session.close()
