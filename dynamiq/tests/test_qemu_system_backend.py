from __future__ import annotations

import pytest

from dynamiq.backends.qemu_system_instrumented import QemuSystemInstrumentedBackend
from dynamiq.errors import SessionTimeoutError
from dynamiq.qemu_system import QemuSystemLaunchConfig


class FakeProcessRunner:
    def __init__(self) -> None:
        self.summary: str | None = None

    def exited_summary(self) -> str | None:
        return self.summary


def test_system_backend_default_capabilities() -> None:
    backend = QemuSystemInstrumentedBackend()
    caps = backend._default_capabilities()
    assert caps.pause_resume is True
    assert caps.read_registers is True
    assert caps.read_memory is True
    assert caps.disassemble is True
    assert caps.list_memory_maps is True
    assert caps.take_snapshot is True
    assert caps.restore_snapshot is True
    assert caps.trace_basic_block is True
    assert caps.trace_branch is True
    assert caps.trace_memory is True
    assert caps.trace_syscall is True
    assert caps.run_until_address is True
    assert caps.single_step is True
    assert caps.watchpoints is True


def test_system_backend_initial_state() -> None:
    backend = QemuSystemInstrumentedBackend()
    assert backend._started is False
    assert backend._state["session_status"] == "not_started"
    assert backend._state["qemu_mode"] == "system"
    assert backend._state["backend"] == "qemu_system_instrumented"


def test_system_backend_capabilities_method() -> None:
    backend = QemuSystemInstrumentedBackend()
    caps = backend.capabilities()
    assert isinstance(caps, dict)
    assert caps["pause_resume"] is True
    assert caps["read_registers"] is True
    assert caps["read_memory"] is True


def test_system_backend_write_stdin_raises() -> None:
    """System-mode backend should not support stdin."""
    from dynamiq.errors import UnsupportedOperationError
    backend = QemuSystemInstrumentedBackend()
    try:
        backend.write_stdin("test")
        assert False, "Should have raised UnsupportedOperationError"
    except UnsupportedOperationError:
        pass


def test_system_backend_close_stdin() -> None:
    backend = QemuSystemInstrumentedBackend()
    result = backend.close_stdin()
    assert result["closed"] is True
    assert result["available"] is False


def test_system_backend_system_reset_not_implemented_without_qmp() -> None:
    """system_reset requires QMP controller."""
    from dynamiq.errors import UnsupportedOperationError
    backend = QemuSystemInstrumentedBackend()
    backend._started = True
    try:
        backend.system_reset()
        assert False, "Should have raised UnsupportedOperationError"
    except UnsupportedOperationError:
        pass


def test_system_backend_system_powerdown_not_implemented_without_qmp() -> None:
    """system_powerdown requires QMP controller."""
    from dynamiq.errors import UnsupportedOperationError
    backend = QemuSystemInstrumentedBackend()
    backend._started = True
    try:
        backend.system_powerdown()
        assert False, "Should have raised UnsupportedOperationError"
    except UnsupportedOperationError:
        pass


def test_system_launch_config_adds_qmp_socket_arg() -> None:
    config = QemuSystemLaunchConfig.from_config(
        qemu_config={
            "qemu_system_path": "/usr/bin/qemu-system-x86_64",
            "qemu_args": ["-machine", "pc"],
            "qmp_socket_path": "/tmp/dynamiq-qmp.sock",
        },
    )

    assert config.args == [
        "-machine",
        "pc",
        "-qmp",
        "unix:/tmp/dynamiq-qmp.sock,server,nowait",
    ]


def test_system_launch_config_does_not_duplicate_qmp_arg() -> None:
    config = QemuSystemLaunchConfig.from_config(
        qemu_config={
            "qemu_system_path": "/usr/bin/qemu-system-x86_64",
            "qemu_args": ["-qmp", "unix:/tmp/manual.sock,server,nowait"],
            "qmp_socket_path": "/tmp/auto.sock",
        },
    )

    assert config.args == ["-qmp", "unix:/tmp/manual.sock,server,nowait"]


def test_system_backend_socket_timeout_includes_qemu_exit_summary() -> None:
    runner = FakeProcessRunner()
    runner.summary = "qemu-system exited with code 1; stderr: bind qmp socket failed"
    backend = QemuSystemInstrumentedBackend(process_runner=runner)

    with pytest.raises(
        SessionTimeoutError,
        match=r"start timed out waiting for QMP socket after 0.2s: /tmp/qmp\.sock; qemu-system exited with code 1; stderr: bind qmp socket failed",
    ):
        backend._raise_launch_socket_timeout("/tmp/qmp.sock", 0.2, "QMP")
