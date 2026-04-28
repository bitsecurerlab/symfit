from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from dynamiq.backends.qemu_user_instrumented import QemuUserInstrumentedBackend
from dynamiq.session import AnalysisSession


ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
TARGET_SRC = EXAMPLES / "sample_target.c"
TARGET_BIN = EXAMPLES / "sample_target"
SIDECAR = EXAMPLES / "instrumentation_sidecar.py"


def compile_target() -> None:
    gcc = shutil.which("gcc")
    if gcc is None:
        raise SystemExit("gcc is required to build examples/sample_target.c")
    subprocess.run(
        [gcc, "-g", "-O0", "-fno-omit-frame-pointer", "-o", str(TARGET_BIN), str(TARGET_SRC)],
        check=True,
    )


def wait_for_socket(path: Path, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return
        time.sleep(0.05)
    raise SystemExit(f"timed out waiting for socket: {path}")


def ensure_qemu() -> str:
    qemu = shutil.which("qemu-x86_64")
    if qemu is None:
        raise SystemExit("qemu-x86_64 is required for the live demo")
    return qemu


def wait_for_backend_ready(session: AnalysisSession, timeout: float = 2.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        state = session.get_state()
        recent_events = state["result"].get("recent_events", [])
        for event in recent_events:
            if event.get("type") == "backend_ready":
                return event
        time.sleep(0.05)
    raise SystemExit("timed out waiting for backend_ready in current state")


def main() -> int:
    compile_target()
    qemu_user_path = ensure_qemu()

    with tempfile.TemporaryDirectory(prefix="ia-demo-") as tmp:
        tmpdir = Path(tmp)
        event_socket = tmpdir / "events.sock"
        rpc_socket = tmpdir / "rpc.sock"

        env = os.environ.copy()
        env["IA_EVENT_SOCKET"] = str(event_socket)
        env["IA_RPC_SOCKET"] = str(rpc_socket)

        sidecar = subprocess.Popen(
            [sys.executable, str(SIDECAR)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            wait_for_socket(event_socket)
            wait_for_socket(rpc_socket)

            session = AnalysisSession(backend=QemuUserInstrumentedBackend())
            session.start(
                target=str(TARGET_BIN),
                args=["demo"],
                cwd=str(ROOT),
                qemu_config={
                    "launch": True,
                    "qemu_user_path": qemu_user_path,
                    "instrumentation_socket_path": str(event_socket),
                    "instrumentation_rpc_socket_path": str(rpc_socket),
                },
            )

            print("== capabilities ==")
            print(session.capabilities())

            print("== state ==")
            print(session.get_state())

            print("== wait for ready ==")
            print(wait_for_backend_ready(session, timeout=2.0))

            print("== wait for branch ==")
            print(session.run_until_event(["branch"], timeout=2.0))

            print("== registers ==")
            print(session.get_registers(["rip", "rax"]))

            print("== memory maps ==")
            print(session.list_memory_maps())

            print("== memory ==")
            print(session.read_memory("0x401000", 16))

            print("== trace ==")
            print(session.get_trace(limit=5))

            print("== close ==")
            print(session.close())
        finally:
            sidecar.terminate()
            try:
                sidecar.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                sidecar.kill()
                sidecar.wait(timeout=2.0)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
