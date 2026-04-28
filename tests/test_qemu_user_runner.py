from __future__ import annotations

import os
import signal
import subprocess
import time
from pathlib import Path

from dynamiq.qemu_user import QemuUserLaunchConfig, QemuUserProcessRunner, _resolve_qemu_from_candidates


def test_qemu_user_launch_config_builds_command_and_env() -> None:
    config = QemuUserLaunchConfig.from_target(
        target="./bin/sample",
        args=["a", "b"],
        cwd="/tmp/work",
        qemu_config={
            "qemu_user_path": "/usr/bin/qemu-x86_64",
            "qemu_args": ["-strace"],
            "instrumentation_socket_path": "/tmp/events.sock",
            "instrumentation_rpc_socket_path": "/tmp/rpc.sock",
            "instrumentation_trace_file_path": "/tmp/trace.ndjson",
            "env": {"FOO": "bar"},
        },
    )

    assert config.command() == ["/usr/bin/qemu-x86_64", "-strace", "./bin/sample", "a", "b"]
    env = config.environment()
    assert env["FOO"] == "bar"
    assert env["IA_EVENT_SOCKET"] == "/tmp/events.sock"
    assert env["IA_RPC_SOCKET"] == "/tmp/rpc.sock"
    assert env["IA_TRACE_FILE"] == "/tmp/trace.ndjson"


def test_qemu_user_launch_config_prefers_local_build_when_available(monkeypatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    preferred = repo_root / "tools" / "qemu" / "qemu-x86_64-instrumented"
    preferred.parent.mkdir(parents=True)
    preferred.write_text("", encoding="utf-8")

    monkeypatch.setattr("dynamiq.qemu_user.Path.resolve", lambda self: repo_root / "src" / "dynamiq" / "qemu_user.py")
    monkeypatch.setattr("dynamiq.qemu_user.shutil.which", lambda _name: "/usr/bin/qemu-x86_64")

    config = QemuUserLaunchConfig.from_target(target="./bin/sample", qemu_config={})

    assert config.qemu_user_path == str(preferred)


def test_qemu_user_launch_config_selects_i386_for_32bit_elf(monkeypatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    preferred = repo_root / "tools" / "qemu" / "qemu-i386-instrumented"
    preferred.parent.mkdir(parents=True)
    preferred.write_text("", encoding="utf-8")

    target = tmp_path / "sample-32"
    # ELF32 + little-endian + ET_EXEC + EM_386
    target.write_bytes(b"\x7fELF\x01\x01\x01" + b"\x00" * 9 + b"\x02\x00\x03\x00")

    monkeypatch.setattr("dynamiq.qemu_user.Path.resolve", lambda self: repo_root / "src" / "dynamiq" / "qemu_user.py")
    monkeypatch.setattr("dynamiq.qemu_user.shutil.which", lambda _name: None)

    config = QemuUserLaunchConfig.from_target(target=str(target), qemu_config={})

    assert config.qemu_user_path == str(preferred)


def test_qemu_user_launch_config_selects_aarch64_for_64bit_arm_elf(monkeypatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    preferred = repo_root / "tools" / "qemu" / "qemu-aarch64-instrumented"
    preferred.parent.mkdir(parents=True)
    preferred.write_text("", encoding="utf-8")

    target = tmp_path / "sample-aarch64"
    # ELF64 + little-endian + ET_EXEC + EM_AARCH64
    target.write_bytes(b"\x7fELF\x02\x01\x01" + b"\x00" * 9 + b"\x02\x00\xb7\x00")

    monkeypatch.setattr("dynamiq.qemu_user.Path.resolve", lambda self: repo_root / "src" / "dynamiq" / "qemu_user.py")
    monkeypatch.setattr("dynamiq.qemu_user.shutil.which", lambda _name: None)

    config = QemuUserLaunchConfig.from_target(target=str(target), qemu_config={})

    assert config.qemu_user_path == str(preferred)


def test_qemu_user_launch_config_falls_back_to_x86_64_when_arch_unknown(monkeypatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    target = tmp_path / "not-elf"
    target.write_text("plain text", encoding="utf-8")

    monkeypatch.setattr("dynamiq.qemu_user.Path.resolve", lambda self: repo_root / "src" / "dynamiq" / "qemu_user.py")
    monkeypatch.setattr("dynamiq.qemu_user.shutil.which", lambda _name: None)

    config = QemuUserLaunchConfig.from_target(target=str(target), qemu_config={})

    assert config.qemu_user_path == "qemu-x86_64"


def test_qemu_user_launch_config_honors_explicit_qemu_path(monkeypatch, tmp_path: Path) -> None:
    target = tmp_path / "sample-32"
    target.write_bytes(b"\x7fELF\x01\x01\x01" + b"\x00" * 9 + b"\x02\x00\x03\x00")

    monkeypatch.setattr("dynamiq.qemu_user.shutil.which", lambda _name: "/usr/bin/qemu-i386")

    config = QemuUserLaunchConfig.from_target(
        target=str(target),
        qemu_config={"qemu_user_path": "/custom/qemu-user"},
    )

    assert config.qemu_user_path == "/custom/qemu-user"


def test_resolve_qemu_prefers_repo_tools_qemu_folder(monkeypatch, tmp_path: Path) -> None:
    repo_root = tmp_path / "repo"
    preferred = repo_root / "tools" / "qemu" / "qemu-i386-instrumented"
    preferred.parent.mkdir(parents=True)
    preferred.write_text("", encoding="utf-8")

    monkeypatch.setattr("dynamiq.qemu_user.shutil.which", lambda _name: None)

    resolved = _resolve_qemu_from_candidates(["qemu-i386"], repo_root=repo_root)

    assert resolved == str(preferred)


def test_qemu_user_process_runner_reads_stdout_and_stderr_nonblocking() -> None:
    runner = QemuUserProcessRunner()
    config = QemuUserLaunchConfig(
        qemu_user_path="/bin/sh",
        target="-c",
        args=["printf 'out-line\\n'; printf 'err-line\\n' >&2"],
        cwd=None,
    )
    runner.start(config)
    assert runner.process is not None
    runner.process.wait(timeout=2.0)
    time.sleep(0.05)

    out = runner.read_stdout(cursor=0, max_chars=4096)
    err = runner.read_stderr(cursor=0, max_chars=4096)

    assert "out-line" in out["data"]
    assert "err-line" in err["data"]
    assert out["eof"] is True
    assert err["eof"] is True
    runner.close()


def test_qemu_user_process_runner_uses_process_group_cleanup() -> None:
    runner = QemuUserProcessRunner()
    config = QemuUserLaunchConfig(
        qemu_user_path="/bin/sh",
        target="-c",
        args=["sleep 30 & wait"],
        cwd=None,
    )
    process = runner.start(config)

    assert process.poll() is None
    assert os.getsid(process.pid) == process.pid

    runner.close()

    assert process.poll() is not None


class _StubbornProcess:
    def __init__(self) -> None:
        self.pid = 4242
        self._returncode = None
        self.kill_calls = 0
        self.wait_timeouts: list[float] = []

    def poll(self):
        return self._returncode

    def wait(self, timeout: float):
        self.wait_timeouts.append(timeout)
        if self.kill_calls:
            self._returncode = -signal.SIGKILL
            return self._returncode
        raise subprocess.TimeoutExpired(cmd="qemu-x86_64-instrumented", timeout=timeout)

    def kill(self) -> None:
        self.kill_calls += 1

    def terminate(self) -> None:
        pass


def test_qemu_user_process_runner_forces_kill_after_sigkill_timeout(monkeypatch) -> None:
    process = _StubbornProcess()
    monkeypatch.setattr("dynamiq.qemu_user.os.killpg", lambda _pid, _sig: None)

    QemuUserProcessRunner._terminate_process_group(process, signal.SIGKILL, timeout=0.01)

    assert process.kill_calls == 1
    assert process.poll() == -signal.SIGKILL
    assert process.wait_timeouts == [0.01, 0.1]
