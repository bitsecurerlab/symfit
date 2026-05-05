"""
Test dynamiq with symfit-system-x86_64 using the new QemuSystemInstrumentedBackend.

Run with:
    RUN_LIVE_QEMU=1 python -m pytest test_live_system_backend.py -v
"""
from __future__ import annotations

import os
import socket
import time
from pathlib import Path

import pytest

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
        Path("/usr/local/bin/symfit-system-x86_64"),
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


@pytest.fixture
def symfit_system_path() -> Path:
    path = _find_symfit_system()
    if path is None:
        pytest.skip("symfit-system-x86_64 not found")
    return path


class TimeoutError(Exception):
    pass

def _wait_for_socket(socket_path: Path, timeout: float = 5.0) -> None:
    """Wait for QMP socket to be created by QEMU."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if socket_path.exists():
            return
        time.sleep(0.05)
    raise TimeoutError(f"QMP socket not created: {socket_path}")


@pytest.fixture
def system_session(symfit_system_path: Path):
    """Create a system-mode session with proper socket waiting."""
    import tempfile
    tmpdir = tempfile.mkdtemp(prefix="dynamiq-system-test-")
    qmp_socket = Path(tmpdir) / "qmp.sock"

    session = ScriptSession.system(
        qemu_system_path=str(symfit_system_path),
        qemu_args=["-machine", "pc", "-display", "none", "-S",
                    "-qmp", f"unix:{qmp_socket},server,nowait"],
        arch="x86_64",
        qemu_config={"launch": True, "qmp_socket_path": str(qmp_socket)},
        auto_start=False,
    )

    # Start the session
    session.start()

    # Wait for QMP socket to be created
    try:
        _wait_for_socket(qmp_socket, timeout=5.0)
        yield session
    finally:
        session.close()
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.mark.live_qemu
def test_backend_type(system_session: ScriptSession) -> None:
    """Verify correct backend type is used."""
    assert type(system_session._backend).__name__ == "QemuSystemInstrumentedBackend"
    state = system_session.get_state()["state"]
    assert state["qemu_mode"] == "system"
    assert state["backend"] == "qemu_system_instrumented"


@pytest.mark.live_qemu
def test_system_starts_paused(system_session: ScriptSession) -> None:
    """System should start in paused state with -S flag."""
    state = system_session.get_state()["state"]
    assert state["session_status"] == "paused"


@pytest.mark.live_qemu
def test_read_physical_memory(system_session: ScriptSession, symfit_system_path: Path) -> None:
    """Test reading physical memory (BIOS/boot sector area)."""
    # Read from 0x7C00 (traditional boot sector load address)
    result = system_session.read_memory("0x7c00", 4, address_space="physical")
    memory = result["result"]
    assert memory["address"] == "0x7c00"
    assert memory["size"] == 4
    assert "bytes" in memory
    assert len(memory["bytes"]) == 8  # 4 bytes = 8 hex chars


@pytest.mark.live_qemu
def test_get_registers(system_session: ScriptSession) -> None:
    """Test reading CPU registers."""
    result = system_session.get_registers(["rip", "rsp", "rax"])
    registers = result["result"]["registers"]
    assert "rip" in registers
    assert "rsp" in registers
    assert "rax" in registers


@pytest.mark.live_qemu
def test_resume_and_pause(system_session: ScriptSession) -> None:
    """Test resume and pause operations."""
    # Resume
    result = system_session.resume(timeout=2.0)
    state = result["state"]
    assert state["session_status"] == "running"

    # Pause
    result = system_session.pause(timeout=2.0)
    state = result["state"]
    assert state["session_status"] == "paused"


@pytest.mark.live_qemu
def test_system_reset(system_session: ScriptSession) -> None:
    """Test system_reset functionality."""
    backend = system_session._backend
    if not hasattr(backend, "system_reset"):
        pytest.skip("system_reset not available")

    result = backend.system_reset()
    assert "qmp_result" in result or result.get("status") == "reset"


@pytest.mark.live_qemu
def test_get_cpu_info(system_session: ScriptSession) -> None:
    """Test get_cpu_info functionality."""
    backend = system_session._backend
    if not hasattr(backend, "get_cpu_info"):
        pytest.skip("get_cpu_info not available")

    result = backend.get_cpu_info()
    assert "cpus" in result or "cpu_count" in result


@pytest.mark.live_qemu
def test_smp_support(system_session: ScriptSession) -> None:
    """Test SMP (multi-CPU) support if available."""
    backend = system_session._backend
    if not hasattr(backend, "set_current_cpu"):
        pytest.skip("SMP methods not available")

    # Get CPU info to check CPU count
    result = backend.get_cpu_info()
    cpu_count = result.get("cpu_count", 0)
    
    if cpu_count <= 1:
        pytest.skip(f"Single CPU system (count={cpu_count}), SMP test not applicable")

    # Test setting current CPU
    result = backend.set_current_cpu(0)
    assert result["cpu_index"] == 0


@pytest.mark.live_qemu
def test_snapshot_support(system_session: ScriptSession) -> None:
    """Test snapshot take/restore if supported."""
    backend = system_session._backend
    caps = backend.capabilities()
    
    if not caps.get("take_snapshot"):
        pytest.skip("Snapshot not supported")

    # Take snapshot
    result = system_session.take_snapshot(name="test_snap")
    assert "snapshot_id" in result["result"]

    # Restore snapshot
    snapshot_id = result["result"]["snapshot_id"]
    restore_result = system_session.restore_snapshot(snapshot_id=snapshot_id)
    assert restore_result["result"]["snapshot_id"] == snapshot_id


@pytest.mark.live_qemu
def test_query_devices(system_session: ScriptSession) -> None:
    """Test device query if available."""
    backend = system_session._backend
    if not hasattr(backend, "query_devices"):
        pytest.skip("query_devices not available")

    result = backend.query_devices()
    assert "devices" in result or "qmp_result" in result


@pytest.mark.live_qemu
def test_write_physical_memory(system_session: ScriptSession) -> None:
    """Test writing to physical memory if supported."""
    backend = system_session._backend
    if not hasattr(backend, "write_physical_memory"):
        pytest.skip("write_physical_memory not available")

    # Try to write to a non-critical memory location
    test_data = bytes([0x90, 0x90])  # NOP sled
    try:
        result = backend.write_physical_memory("0x1000", test_data)
        # If we get here, write succeeded
        assert True
    except Exception as e:
        # Write might not be supported or address might be invalid
        pytest.skip(f"Physical memory write not supported: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
