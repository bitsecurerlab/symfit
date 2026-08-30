from __future__ import annotations

import os
import fcntl
import shutil
import signal
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


_QEMU_SYSTEM_TO_SYMFIT = {
    "i386": ("i386-softmmu", "symfit-system-i386"),
    "x86_64": ("x86_64-softmmu", "symfit-system-x86_64"),
    "aarch64": ("aarch64-softmmu", "symfit-system-aarch64"),
}

_ARCH_ALIASES = {
    "amd64": "x86_64",
    "x86": "i386",
    "arm64": "aarch64",
}

def _candidate_roots(repo_root: Path) -> list[Path]:
    roots = [repo_root]
    parent = repo_root.parent
    if parent != repo_root and (parent / "build.sh").exists():
        roots.append(parent)
    return roots


def resolve_qemu_system_path(qemu_config: dict[str, Any]) -> str:
    configured = qemu_config.get("qemu_system_path") or qemu_config.get("qemu_path")
    if configured:
        return str(configured)

    arch = _normalize_arch(str(qemu_config.get("arch") or qemu_config.get("system_arch") or "x86_64"))
    repo_root = Path(__file__).resolve().parents[2]
    target = _QEMU_SYSTEM_TO_SYMFIT.get(arch)
    if target is not None:
        target_dir, executable = target
        for root in _candidate_roots(repo_root):
            for candidate in (
                root / "build" / "symfit" / target_dir / executable,
                root / "build" / "release" / "symfit" / target_dir / executable,
            ):
                if candidate.exists():
                    return str(candidate)
        discovered = shutil.which(executable)
        if discovered is not None:
            return discovered

    fallback = f"qemu-system-{arch}"
    discovered = shutil.which(fallback)
    if discovered is not None:
        return discovered
    return fallback


@dataclass(slots=True)
class QemuSystemLaunchConfig:
    qemu_system_path: str = "qemu-system-x86_64"
    args: list[str] = field(default_factory=list)
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    instrumentation_event_socket: str | None = None
    instrumentation_rpc_socket: str | None = None
    instrumentation_trace_file: str | None = None
    machine: str | None = None
    cpu: str | None = None
    memory: str | None = None
    kernel: str | None = None
    append: str | None = None
    drive: str | None = None
    drives: list[str] = field(default_factory=list)
    display: str | None = "none"
    monitor: str | None = "none"
    serial: str | None = "mon:stdio"
    nodefaults: bool = False
    no_reboot: bool = True
    qmp_socket: str | None = None
    inherit_stderr: bool = False

    @classmethod
    def from_config(
        cls,
        target: str = "",
        target_args: list[str] | None = None,
        cwd: str | None = None,
        qemu_config: dict[str, Any] | None = None,
    ) -> "QemuSystemLaunchConfig":
        qemu_config = dict(qemu_config or {})
        # Argument collection was reworked
        #args = [str(item) for item in list(qemu_config.get("qemu_args") or [])]
        raw_args = qemu_config.get("qemu_args")
        if raw_args is None:
            raw_args = qemu_config.get("system_args")
        args = [str(item) for item in list(raw_args or [])]
        qmp_socket_path = qemu_config.get("qmp_socket_path")
        if args and qmp_socket_path and not _has_qmp_option(args):
            args.extend(["-qmp", f"unix:{qmp_socket_path},server,nowait"])
        kernel = qemu_config.get("kernel")
        if not kernel and target:
            kernel = target
        append = qemu_config.get("append")
        if append is None and target_args:
            append = " ".join(str(item) for item in target_args)
        drives = qemu_config.get("drives")
        if drives is None:
            drives = []
        return cls(
            qemu_system_path=resolve_qemu_system_path(qemu_config),
            args=args,
            cwd=cwd,
            env={str(key): str(value) for key, value in dict(qemu_config.get("env") or {}).items()},
            instrumentation_event_socket=qemu_config.get("instrumentation_socket_path"),
            instrumentation_rpc_socket=qemu_config.get("instrumentation_rpc_socket_path"),
            instrumentation_trace_file=qemu_config.get("instrumentation_trace_file_path"),
            machine=qemu_config.get("machine") or qemu_config.get("qemu_machine"),
            cpu=qemu_config.get("cpu") or qemu_config.get("qemu_cpu"),
            memory=qemu_config.get("memory") or qemu_config.get("qemu_memory"),
            kernel=str(kernel) if kernel else None,
            append=str(append) if append else None,
            drive=str(qemu_config.get("drive") or qemu_config.get("disk_image") or "") or None,
            drives=[str(item) for item in list(drives or [])],
            display=qemu_config.get("display", "none"),
            monitor=qemu_config.get("monitor", "none"),
            serial=qemu_config.get("serial", "mon:stdio"),
            nodefaults=bool(qemu_config.get("nodefaults", False)),
            no_reboot=bool(qemu_config.get("no_reboot", True)),
            qmp_socket=str(qmp_socket_path) if qmp_socket_path else None,
            inherit_stderr=bool(qemu_config.get("inherit_stderr", False)),
        )

    def command(self) -> list[str]:
        #return [self.qemu_system_path, *self.args]
        command = [self.qemu_system_path]
        if self.args:
            command.extend(self.args)
            return command
        if self.machine:
            command.extend(["-machine", self.machine])
        if self.cpu:
            command.extend(["-cpu", self.cpu])
        if self.memory:
            command.extend(["-m", self.memory])
        if self.display:
            command.extend(["-display", self.display])
        if self.monitor:
            command.extend(["-monitor", self.monitor])
        if self.serial:
            command.extend(["-serial", self.serial])
        if self.nodefaults:
            command.append("-nodefaults")
        if self.no_reboot:
            command.append("-no-reboot")
        if self.qmp_socket:
            command.extend(["-qmp", f"unix:{self.qmp_socket},server,nowait"])
        if self.kernel:
            command.extend(["-kernel", self.kernel])
        if self.append:
            command.extend(["-append", self.append])
        for drive in self._normalized_drives():
            command.extend(["-drive", drive])
        return command

    def environment(self) -> dict[str, str]:
        env = os.environ.copy()
        env.update(self.env)
        if self.instrumentation_event_socket:
            env["IA_EVENT_SOCKET"] = self.instrumentation_event_socket
        if self.instrumentation_rpc_socket:
            env["IA_RPC_SOCKET"] = self.instrumentation_rpc_socket
        if self.instrumentation_trace_file:
            env["IA_TRACE_FILE"] = self.instrumentation_trace_file
        return env

    def to_backend_config(self, launch: bool = True) -> dict[str, Any]:
        return {
            "mode": "system",
            "launch": launch,
            "qemu_system_path": self.qemu_system_path,
            "instrumentation_socket_path": self.instrumentation_event_socket,
            "instrumentation_rpc_socket_path": self.instrumentation_rpc_socket,
            "instrumentation_trace_file_path": self.instrumentation_trace_file,
            "qemu_args": list(self.args),
            "machine": self.machine,
            "cpu": self.cpu,
            "memory": self.memory,
            "kernel": self.kernel,
            "append": self.append,
            "drive": self.drive,
            "drives": list(self.drives),
            "display": self.display,
            "monitor": self.monitor,
            "serial": self.serial,
            "nodefaults": self.nodefaults,
            "no_reboot": self.no_reboot,
            "qmp_socket_path": self.qmp_socket,
            "env": dict(self.env),
            "inherit_stderr": self.inherit_stderr,
        }

    def _normalized_drives(self) -> list[str]:
        raw_drives = list(self.drives)
        if self.drive:
            raw_drives.insert(0, self.drive)
        normalized: list[str] = []
        for drive in raw_drives:
            if "=" in drive or "," in drive:
                normalized.append(drive)
            else:
                normalized.append(f"file={drive},format=raw")
        return normalized


def _has_qmp_option(args: list[str]) -> bool:
    return any(arg == "-qmp" or arg == "-qmp-pretty" for arg in args)

def _normalize_arch(arch: str) -> str:
    normalized = arch.strip().lower()
    return _ARCH_ALIASES.get(normalized, normalized)

class QemuSystemProcessRunner:
    def __init__(self) -> None:
        self._process: subprocess.Popen[bytes] | None = None
        self._config: QemuSystemLaunchConfig | None = None
        self._stdout_buffer = ""
        self._stderr_buffer = ""

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.poll() is None

    @property
    def process(self) -> subprocess.Popen[bytes] | None:
        return self._process

    @property
    def config(self) -> QemuSystemLaunchConfig | None:
        return self._config

    def start(self, config: QemuSystemLaunchConfig) -> subprocess.Popen[bytes]:
        if self.running:
            raise RuntimeError("qemu-system process is already running")
        self._config = config
        self._stdout_buffer = ""
        self._stderr_buffer = ""
        self._process = subprocess.Popen(
            config.command(),
            cwd=config.cwd,
            env=config.environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=None if config.inherit_stderr else subprocess.PIPE,
            text=False,
            start_new_session=True,
        )
        if self._process.stdout is not None:
            self._set_nonblocking(self._process.stdout.fileno())
        if self._process.stderr is not None:
            self._set_nonblocking(self._process.stderr.fileno())
        return self._process

    def close(self) -> None:
        if self._process is None:
            return
        if self._process.poll() is None:
            self._terminate_process_group(self._process, signal.SIGTERM, timeout=2.0)
            if self._process.poll() is None:
                self._terminate_process_group(self._process, signal.SIGKILL, timeout=2.0)
        self._process = None
        self._config = None

    def write_stdin(self, data: str | bytes) -> int:
        del data
        raise RuntimeError("stdin is not available for qemu-system launches")

    def close_stdin(self) -> dict[str, Any]:
        return {"closed": True, "already_closed": True, "available": False}

    def read_stdout(self, cursor: int = 0, max_chars: int = 4096) -> dict[str, Any]:
        self._drain_available_output()
        return self._read_stream("stdout", cursor, max_chars)

    def read_stderr(self, cursor: int = 0, max_chars: int = 4096) -> dict[str, Any]:
        self._drain_available_output()
        return self._read_stream("stderr", cursor, max_chars)

    def exited_summary(self) -> str | None:
        if self._process is None:
            return None
        returncode = self._process.poll()
        if returncode is None:
            return None
        self._drain_available_output()
        stderr = self._stderr_buffer.strip()
        stdout = self._stdout_buffer.strip()
        parts = [f"qemu-system exited with code {returncode}"]
        if stderr:
            parts.append(f"stderr: {stderr}")
        elif stdout:
            parts.append(f"stdout: {stdout}")
        return "; ".join(parts)

    def _drain_available_output(self) -> None:
        if self._process is None:
            return
        if self._process.stdout is not None:
            self._drain_stream(self._process.stdout, "stdout")
        if self._process.stderr is not None:
            self._drain_stream(self._process.stderr, "stderr")

    def _drain_stream(self, stream: Any, stream_name: str) -> None:
        while True:
            try:
                raw = stream.read1(4096)
            except (BlockingIOError, OSError):
                return
            if not raw:
                return
            chunk = raw.decode("utf-8", errors="replace")
            if stream_name == "stdout":
                self._stdout_buffer += chunk
            else:
                self._stderr_buffer += chunk

    def _read_stream(self, stream_name: str, cursor: int, max_chars: int) -> dict[str, Any]:
        if cursor < 0:
            raise ValueError("cursor must be >= 0")
        if max_chars < 1:
            raise ValueError("max_chars must be >= 1")
        payload = self._stdout_buffer if stream_name == "stdout" else self._stderr_buffer
        if cursor > len(payload):
            cursor = len(payload)
        end = min(len(payload), cursor + max_chars)
        return {
            "data": payload[cursor:end],
            "cursor": end,
            "eof": self._process is None or self._process.poll() is not None,
        }

    @staticmethod
    def _set_nonblocking(fd: int) -> None:
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

    @staticmethod
    def _terminate_process_group(
        process: subprocess.Popen[bytes],
        sig: signal.Signals,
        timeout: float,
    ) -> None:
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            return
        except OSError:
            if sig == signal.SIGKILL:
                process.kill()
            else:
                process.terminate()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            if sig == signal.SIGKILL:
                process.kill()
