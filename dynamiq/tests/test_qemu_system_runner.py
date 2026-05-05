from __future__ import annotations

from pathlib import Path

from dynamiq.qemu_system import QemuSystemLaunchConfig, resolve_qemu_system_path


def test_qemu_system_launch_config_builds_command_and_env() -> None:
    config = QemuSystemLaunchConfig.from_config(
        cwd="/tmp/vm",
        qemu_config={
            "qemu_system_path": "/usr/bin/qemu-system-x86_64",
            "qemu_args": ["-machine", "pc", "-display", "none"],
            "instrumentation_socket_path": "/tmp/events.sock",
            "instrumentation_rpc_socket_path": "/tmp/rpc.sock",
            "instrumentation_trace_file_path": "/tmp/trace.ndjson",
            "env": {"FOO": "bar"},
        },
    )

    assert config.command() == ["/usr/bin/qemu-system-x86_64", "-machine", "pc", "-display", "none"]
    assert config.cwd == "/tmp/vm"
    env = config.environment()
    assert env["FOO"] == "bar"
    assert env["IA_EVENT_SOCKET"] == "/tmp/events.sock"
    assert env["IA_RPC_SOCKET"] == "/tmp/rpc.sock"
    assert env["IA_TRACE_FILE"] == "/tmp/trace.ndjson"


def test_qemu_system_resolver_prefers_symfit_build(monkeypatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    preferred = repo_root / "build" / "symfit" / "aarch64-softmmu" / "symfit-system-aarch64"
    preferred.parent.mkdir(parents=True)
    preferred.write_text("", encoding="utf-8")

    monkeypatch.setattr("dynamiq.qemu_system.Path.resolve", lambda self: repo_root / "src" / "dynamiq" / "qemu_system.py")
    monkeypatch.setattr("dynamiq.qemu_system.shutil.which", lambda _name: None)

    assert resolve_qemu_system_path({"arch": "aarch64"}) == str(preferred)


def test_qemu_system_launch_config_to_backend_config() -> None:
    config = QemuSystemLaunchConfig(
        qemu_system_path="/opt/symfit-system-x86_64",
        args=["-machine", "pc"],
        instrumentation_rpc_socket="/tmp/rpc.sock",
    )

    backend_config = config.to_backend_config()

    assert backend_config["mode"] == "system"
    assert backend_config["launch"] is True
    assert backend_config["qemu_system_path"] == "/opt/symfit-system-x86_64"
    assert backend_config["qemu_args"] == ["-machine", "pc"]
    assert backend_config["instrumentation_rpc_socket_path"] == "/tmp/rpc.sock"
