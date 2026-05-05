from __future__ import annotations

from dynamiq.backends.qemu_system_instrumented import QemuSystemInstrumentedBackend
from dynamiq.errors import InvalidStateError, UnsupportedOperationError


class FakeController:
    def __init__(self) -> None:
        self.commands: list[tuple[str, dict | None]] = []
        self.monitor_commands: list[str] = []

    def execute(self, command: str, arguments: dict | None = None) -> dict:
        self.commands.append((command, arguments))
        return {}

    def monitor_command(self, command_line: str) -> dict:
        self.monitor_commands.append(command_line)
        return {"command-line": command_line}

    def query_status(self) -> dict:
        return {"status": "paused"}


def test_system_backend_has_smp_methods() -> None:
    """Test that system backend has SMP (multi-CPU) methods."""
    backend = QemuSystemInstrumentedBackend()
    assert hasattr(backend, 'set_current_cpu')
    assert hasattr(backend, 'stop_cpu')
    assert hasattr(backend, 'cont_cpu')
    assert hasattr(backend, 'get_cpu_info')


def test_system_backend_has_device_methods() -> None:
    """Test that system backend has device emulation methods."""
    backend = QemuSystemInstrumentedBackend()
    assert hasattr(backend, 'query_devices')
    assert hasattr(backend, 'device_add')
    assert hasattr(backend, 'device_del')


def test_system_backend_has_memory_methods() -> None:
    """Test that system backend has physical memory methods."""
    backend = QemuSystemInstrumentedBackend()
    assert hasattr(backend, 'read_physical_memory')
    assert hasattr(backend, 'write_physical_memory')
    assert hasattr(backend, 'get_machine_info')


def test_set_current_cpu_requires_qmp() -> None:
    """set_current_cpu requires QMP controller."""
    backend = QemuSystemInstrumentedBackend()
    backend._started = True
    try:
        backend.set_current_cpu(0)
        assert False, "Should have raised UnsupportedOperationError"
    except UnsupportedOperationError:
        pass


def test_stop_cpu_requires_qmp() -> None:
    """stop_cpu requires QMP controller."""
    backend = QemuSystemInstrumentedBackend()
    backend._started = True
    try:
        backend.stop_cpu()
        assert False, "Should have raised UnsupportedOperationError"
    except UnsupportedOperationError:
        pass


def test_device_add_requires_qmp() -> None:
    """device_add requires QMP controller."""
    backend = QemuSystemInstrumentedBackend()
    backend._started = True
    try:
        backend.device_add("e1000")
        assert False, "Should have raised UnsupportedOperationError"
    except UnsupportedOperationError:
        pass


def test_read_physical_memory_requires_started() -> None:
    """read_physical_memory requires started session."""
    backend = QemuSystemInstrumentedBackend()
    try:
        backend.read_physical_memory("0x1000", 16)
        assert False, "Should have raised InvalidStateError"
    except InvalidStateError:
        pass


def test_cpu_count_in_initial_state() -> None:
    """Initial state should have cpu_count and current_cpu_id."""
    backend = QemuSystemInstrumentedBackend()
    assert "cpu_count" in backend._state
    assert "current_cpu_id" in backend._state
    assert backend._state["cpu_count"] == 0
    assert backend._state["current_cpu_id"] is None


def test_set_current_cpu_uses_hmp_cpu_command() -> None:
    backend = QemuSystemInstrumentedBackend()
    controller = FakeController()
    backend._controller = controller
    backend._started = True
    backend._state["session_status"] = "paused"

    backend.set_current_cpu(2)

    assert controller.monitor_commands == ["cpu 2"]
    assert controller.commands == []
    assert backend._state["current_cpu_id"] == 2


def test_cpu_specific_stop_and_cont_are_rejected() -> None:
    backend = QemuSystemInstrumentedBackend()
    backend._controller = FakeController()
    backend._started = True

    try:
        backend.stop_cpu(1)
        assert False, "Should have raised UnsupportedOperationError"
    except UnsupportedOperationError:
        pass

    try:
        backend.cont_cpu(1)
        assert False, "Should have raised UnsupportedOperationError"
    except UnsupportedOperationError:
        pass


def test_query_devices_uses_qom_list() -> None:
    backend = QemuSystemInstrumentedBackend()
    controller = FakeController()
    backend._controller = controller
    backend._started = True
    backend._state["session_status"] = "paused"

    backend.query_devices()

    assert controller.commands[:2] == [
        ("qom-list", {"path": "/machine/peripheral"}),
        ("qom-list", {"path": "/machine/peripheral-anon"}),
    ]
