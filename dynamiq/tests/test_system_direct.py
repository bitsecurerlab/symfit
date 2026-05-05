#!/usr/bin/env python3
"""Direct test of system-mode backend without pytest fixtures."""
from __future__ import annotations

import os
import socket
import sys
import time
from pathlib import Path

# Add the source path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dynamiq.script_api import ScriptSession


def _find_symfit_system() -> Path | None:
    """Find symfit-system-x86_64 binary."""
    # Check environment variable first (for CI/testing flexibility)
    env_path = os.environ.get("DYNAMIQ_SYMFIT_SYSTEM_PATH")
    if env_path:
        candidate = Path(env_path)
        if candidate.exists() and os.access(candidate, os.X_OK):
            return candidate
    
    # Check relative to test file (works in checkout)
    # test_dir = /path/to/repo/dynamiq/tests
    # test_dir.parent = /path/to/repo/dynamiq
    # test_dir.parent.parent = /path/to/repo
    test_dir = Path(__file__).resolve().parent
    candidates = [
        test_dir.parent.parent / "build" / "symfit" / "x86_64-softmmu" / "symfit-system-x86_64",
        test_dir.parent.parent.parent / "build" / "symfit" / "x86_64-softmmu" / "symfit-system-x86_64",
    ]
    for candidate in candidates:
        if candidate.exists() and os.access(candidate, os.X_OK):
            return candidate
    
    # Check system PATH as last resort
    import shutil
    system_path = shutil.which("symfit-system-x86_64")
    if system_path:
        return Path(system_path)
    
    return None


def wait_for_socket(socket_path: Path, timeout: float = 5.0) -> None:
    """Wait for QMP socket to be created by QEMU."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if socket_path.exists():
            return
        time.sleep(0.05)
    raise TimeoutError(f"QMP socket not created: {socket_path}")


def check_backend_type(session: ScriptSession) -> None:
    """Verify correct backend type is used."""
    assert type(session._backend).__name__ == "QemuSystemInstrumentedBackend", \
        f"Wrong backend type: {type(session._backend).__name__}"
    state = session.get_state()["state"]
    assert state["qemu_mode"] == "system", f"Wrong qemu_mode: {state['qemu_mode']}"
    assert state["backend"] == "qemu_system_instrumented", f"Wrong backend name: {state['backend']}"
    print("✓ test_backend_type passed")


def check_system_starts_paused(session: ScriptSession) -> None:
    """System should start in paused state with -S flag."""
    state = session.get_state()["state"]
    assert state["session_status"] == "paused", f"Wrong status: {state['session_status']}"
    print("✓ test_system_starts_paused passed")


def check_read_physical_memory(session: ScriptSession) -> None:
    """Test reading physical memory (BIOS/boot sector area)."""
    result = session.read_memory("0x7c00", 4, address_space="physical")
    memory = result["result"]
    assert memory["address"] == "0x7c00", f"Wrong address: {memory['address']}"
    assert memory["size"] == 4, f"Wrong size: {memory['size']}"
    assert "bytes" in memory, "Missing 'bytes' in result"
    assert len(memory["bytes"]) == 8, f"Wrong bytes length: {len(memory['bytes'])}"
    print("✓ test_read_physical_memory passed")


def check_get_registers(session: ScriptSession) -> None:
    """Test reading CPU registers."""
    result = session.get_registers(["rip", "rsp", "rax"])
    registers = result["result"]["registers"]
    assert "rip" in registers, "Missing 'rip' in registers"
    assert "rsp" in registers, "Missing 'rsp' in registers"
    assert "rax" in registers, "Missing 'rax' in registers"
    print("✓ test_get_registers passed")


def main() -> int:
    symfit_path = _find_symfit_system()
    if symfit_path is None:
        print("SKIP: symfit-system-x86_64 not found")
        return 0

    print(f"Using symfit-system: {symfit_path}")

    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="dynamiq-system-test-")
    qmp_socket = Path(tmpdir) / "qmp.sock"

    try:
        session = ScriptSession.system(
            qemu_system_path=str(symfit_path),
            qemu_args=["-machine", "pc", "-display", "none", "-S",
                        "-qmp", f"unix:{qmp_socket},server,nowait"],
            arch="x86_64",
            qemu_config={"launch": True, "qmp_socket_path": str(qmp_socket)},
            auto_start=False,
        )

        # Start the session (launches QEMU which creates the socket)
        session.start()

        # Wait for QMP socket to be created by QEMU
        wait_for_socket(qmp_socket, timeout=5.0)

        # Run tests
        tests = [
            check_backend_type,
            check_system_starts_paused,
            check_read_physical_memory,
            check_get_registers,
        ]

        passed = 0
        failed = 0
        for test in tests:
            try:
                test(session)
                passed += 1
            except AssertionError as e:
                print(f"✗ {test.__name__} failed: {e}")
                failed += 1
            except Exception as e:
                print(f"✗ {test.__name__} error: {type(e).__name__}: {e}")
                failed += 1

        print(f"\nResults: {passed} passed, {failed} failed")
        return 1 if failed > 0 else 0

    finally:
        try:
            session.close()
        except:
            pass
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
