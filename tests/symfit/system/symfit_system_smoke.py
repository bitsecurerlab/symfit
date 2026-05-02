#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pathlib
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[3]
DEFAULT_BUILD_DIR = PROJECT_ROOT / "build" / "symfit"

SYSTEM_TARGETS = {
    "x86_64": {
        "target_dir": "x86_64-softmmu",
        "binary": "symfit-system-x86_64",
        "machine_markers": ("none", "pc", "q35"),
        "boot_marker": "SYMFIT_X86_VM_OK",
    },
    "aarch64": {
        "target_dir": "aarch64-softmmu",
        "binary": "symfit-system-aarch64",
        "machine_markers": ("none", "virt"),
        "boot_marker": "SYMFIT_AARCH64_VM_OK",
    },
}


class SmokeFailure(RuntimeError):
    pass


class X86BootSectorBuilder:
    def __init__(self) -> None:
        self.base = 0x7C00
        self.code = bytearray()
        self.labels: dict[str, int] = {}
        self.patches: list[tuple[int, str, str]] = []

    def emit(self, *values: int) -> None:
        self.code.extend(values)

    def emit_bytes(self, values: bytes) -> None:
        self.code.extend(values)

    def label(self, name: str) -> None:
        self.labels[name] = self.base + len(self.code)

    def mov_dx(self, value: int) -> None:
        self.emit(0xBA, value & 0xFF, (value >> 8) & 0xFF)

    def mov_al(self, value: int) -> None:
        self.emit(0xB0, value & 0xFF)

    def mov_si_label(self, name: str) -> None:
        self.emit(0xBE, 0x00, 0x00)
        self.patches.append((len(self.code) - 2, name, "abs16"))

    def jmp_short(self, name: str) -> None:
        self.emit(0xEB, 0x00)
        self.patches.append((len(self.code) - 1, name, "rel8"))

    def jz_short(self, name: str) -> None:
        self.emit(0x74, 0x00)
        self.patches.append((len(self.code) - 1, name, "rel8"))

    def image(self) -> bytes:
        if len(self.code) > 510:
            raise SmokeFailure(f"x86 boot sector is too large: {len(self.code)} bytes")
        for offset, name, kind in self.patches:
            if name not in self.labels:
                raise SmokeFailure(f"missing x86 boot-sector label: {name}")
            target = self.labels[name]
            if kind == "abs16":
                self.code[offset] = target & 0xFF
                self.code[offset + 1] = (target >> 8) & 0xFF
            elif kind == "rel8":
                rel = target - (self.base + offset + 1)
                if rel < -128 or rel > 127:
                    raise SmokeFailure(f"x86 short jump to {name} out of range: {rel}")
                self.code[offset] = rel & 0xFF
            else:
                raise SmokeFailure(f"unknown x86 boot-sector patch kind: {kind}")
        return bytes(self.code).ljust(510, b"\x00") + b"\x55\xaa"


def run_command(command: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise SmokeFailure(f"command timed out after {timeout:.1f}s: {' '.join(command)}") from exc


def require_executable(path: pathlib.Path) -> None:
    if not path.exists():
        raise SmokeFailure(f"system binary is missing: {path}")
    if not os.access(path, os.X_OK):
        raise SmokeFailure(f"system binary is not executable: {path}")


def run_step(name: str, action: Any) -> Any:
    try:
        return action()
    except SmokeFailure as exc:
        raise SmokeFailure(f"{name} failed: {exc}") from exc
    except Exception as exc:
        raise SmokeFailure(f"{name} failed: {type(exc).__name__}: {exc}") from exc


def check_version(binary: pathlib.Path, timeout: float) -> dict[str, Any]:
    result = run_command([str(binary), "--version"], timeout=timeout)
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0:
        raise SmokeFailure(f"{binary.name} --version exited {result.returncode}:\n{output}")
    if "QEMU emulator version" not in output:
        raise SmokeFailure(f"{binary.name} --version did not look like a QEMU/SymFit binary:\n{output}")
    return {"returncode": result.returncode, "first_line": output.splitlines()[0] if output else ""}


def check_machine_help(binary: pathlib.Path, markers: tuple[str, ...], timeout: float) -> dict[str, Any]:
    result = run_command([str(binary), "-machine", "help"], timeout=timeout)
    output = (result.stdout or "") + (result.stderr or "")
    if result.returncode != 0:
        raise SmokeFailure(f"{binary.name} -machine help exited {result.returncode}:\n{output}")
    missing = [marker for marker in markers if marker not in output]
    if missing:
        raise SmokeFailure(f"{binary.name} -machine help missing expected markers {missing}:\n{output}")
    return {"returncode": result.returncode, "markers": list(markers)}


def write_x86_boot_sector(path: pathlib.Path, marker: str) -> None:
    b = X86BootSectorBuilder()
    b.emit(0xFA)  # cli
    b.emit(0x31, 0xC0)  # xor ax, ax
    b.emit(0x8E, 0xD8)  # mov ds, ax
    b.mov_si_label("message")

    b.mov_dx(0x03F9)
    b.emit(0x30, 0xC0)  # xor al, al
    b.emit(0xEE)  # out dx, al
    b.mov_dx(0x03FB)
    b.mov_al(0x80)
    b.emit(0xEE)
    b.mov_dx(0x03F8)
    b.mov_al(0x03)
    b.emit(0xEE)
    b.mov_dx(0x03F9)
    b.emit(0x30, 0xC0)
    b.emit(0xEE)
    b.mov_dx(0x03FB)
    b.mov_al(0x03)
    b.emit(0xEE)
    b.mov_dx(0x03FA)
    b.mov_al(0xC7)
    b.emit(0xEE)
    b.mov_dx(0x03FC)
    b.mov_al(0x0B)
    b.emit(0xEE)

    b.label("print_loop")
    b.emit(0xAC)  # lodsb
    b.emit(0x84, 0xC0)  # test al, al
    b.jz_short("done")
    b.emit(0x88, 0xC3)  # mov bl, al
    b.label("wait_tx")
    b.mov_dx(0x03FD)
    b.emit(0xEC)  # in al, dx
    b.emit(0xA8, 0x20)  # test al, 0x20
    b.jz_short("wait_tx")
    b.emit(0x88, 0xD8)  # mov al, bl
    b.mov_dx(0x03F8)
    b.emit(0xEE)  # out dx, al
    b.jmp_short("print_loop")

    b.label("done")
    b.mov_dx(0x00F4)
    b.emit(0x30, 0xC0)  # xor al, al
    b.emit(0xEE)  # out dx, al
    b.emit(0xF4)  # hlt
    b.emit(0xEB, 0xFE)  # jmp $
    b.label("message")
    b.emit_bytes(marker.encode("ascii") + b"\n\x00")

    path.write_bytes(b.image())


def aarch64_u32(value: int) -> bytes:
    return (value & 0xFFFFFFFF).to_bytes(4, byteorder="little")


def aarch64_adr(rd: int, current_offset: int, target_offset: int) -> int:
    imm = target_offset - current_offset
    if imm < -(1 << 20) or imm >= (1 << 20):
        raise SmokeFailure(f"AArch64 ADR target out of range: {imm}")
    imm &= (1 << 21) - 1
    immlo = imm & 0x3
    immhi = imm >> 2
    return 0x10000000 | (immlo << 29) | (immhi << 5) | rd


def aarch64_b(current_offset: int, target_offset: int) -> int:
    delta = target_offset - current_offset
    if delta % 4 != 0:
        raise SmokeFailure(f"AArch64 branch target is not aligned: {delta}")
    imm = delta // 4
    if imm < -(1 << 25) or imm >= (1 << 25):
        raise SmokeFailure(f"AArch64 branch target out of range: {imm}")
    return 0x14000000 | (imm & 0x03FFFFFF)


def aarch64_cbz(rt: int, current_offset: int, target_offset: int) -> int:
    delta = target_offset - current_offset
    if delta % 4 != 0:
        raise SmokeFailure(f"AArch64 CBZ target is not aligned: {delta}")
    imm = delta // 4
    if imm < -(1 << 18) or imm >= (1 << 18):
        raise SmokeFailure(f"AArch64 CBZ target out of range: {imm}")
    return 0x34000000 | ((imm & 0x7FFFF) << 5) | rt


def write_aarch64_kernel(path: pathlib.Path, marker: str) -> None:
    message = marker.encode("ascii") + b"\n\x00"
    message_offset = 40
    instructions = [
        aarch64_adr(1, 0, message_offset),  # adr x1, message
        0xD2800002,  # movz x2, #0
        0xF2A12002,  # movk x2, #0x900, lsl #16 (PL011 UART0 at 0x09000000)
        0x39400020,  # loop: ldrb w0, [x1]
        aarch64_cbz(0, 16, 32),  # cbz w0, done
        0x91000421,  # add x1, x1, #1
        0x39000040,  # strb w0, [x2]
        aarch64_b(28, 12),  # b loop
        0xD503207F,  # done: wfi
        aarch64_b(36, 32),  # b done
    ]
    path.write_bytes(b"".join(aarch64_u32(insn) for insn in instructions) + message)


def wait_for_socket(path: pathlib.Path, process: subprocess.Popen[str], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        returncode = process.poll()
        if returncode is not None:
            stdout, stderr = process.communicate(timeout=1.0)
            raise SmokeFailure(
                f"system binary exited before QMP socket was ready: rc={returncode}\n"
                f"stdout:\n{stdout}\nstderr:\n{stderr}"
            )
        try:
            mode = path.stat().st_mode
        except FileNotFoundError:
            time.sleep(0.05)
            continue
        if stat.S_ISSOCK(mode):
            return
        time.sleep(0.05)
    raise SmokeFailure(f"timed out waiting for QMP socket: {path}")


def read_qmp(sock: socket.socket) -> dict[str, Any]:
    chunks: list[bytes] = []
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise SmokeFailure("QMP socket closed before a complete JSON message")
        chunks.append(chunk)
        data = b"".join(chunks)
        if b"\n" in data:
            line = data.split(b"\n", 1)[0]
            try:
                decoded = json.loads(line.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise SmokeFailure(f"invalid QMP JSON: {line!r}") from exc
            if not isinstance(decoded, dict):
                raise SmokeFailure(f"QMP message was not an object: {decoded!r}")
            return decoded


def send_qmp(sock: socket.socket, payload: dict[str, Any]) -> dict[str, Any]:
    sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")
    while True:
        response = read_qmp(sock)
        if "event" in response and "return" not in response and "error" not in response:
            continue
        if "error" in response:
            raise SmokeFailure(f"QMP command failed: {payload!r} -> {response!r}")
        return response


def send_qmp_nowait(sock: socket.socket, payload: dict[str, Any]) -> None:
    sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")


def read_line_json(sock: socket.socket, protocol: str) -> dict[str, Any]:
    chunks: list[bytes] = []
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            raise SmokeFailure(f"{protocol} socket closed before a complete JSON message")
        chunks.append(chunk)
        data = b"".join(chunks)
        if b"\n" in data:
            line = data.split(b"\n", 1)[0]
            try:
                decoded = json.loads(line.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise SmokeFailure(f"invalid {protocol} JSON: {line!r}") from exc
            if not isinstance(decoded, dict):
                raise SmokeFailure(f"{protocol} message was not an object: {decoded!r}")
            return decoded


def ia_rpc_connect(rpc_socket: pathlib.Path, process: subprocess.Popen[str], timeout: float) -> socket.socket:
    wait_for_socket(rpc_socket, process, timeout=timeout)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(timeout)
        client.connect(str(rpc_socket))
        return client
    except Exception:
        client.close()
        raise


def send_ia_rpc(sock: socket.socket, req_id: int, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    payload: dict[str, Any] = {"id": req_id, "method": method}
    if params is not None:
        payload["params"] = params
    sock.sendall(json.dumps(payload).encode("utf-8") + b"\n")
    response = read_line_json(sock, "IA/RPC")
    if response.get("id") != req_id:
        raise SmokeFailure(f"IA/RPC response id mismatch: request={req_id}, response={response!r}")
    if response.get("ok") is not True:
        raise SmokeFailure(f"IA/RPC {method} failed: {response!r}")
    result = response.get("result")
    if not isinstance(result, dict):
        raise SmokeFailure(f"IA/RPC {method} returned malformed result: {response!r}")
    return result


def qmp_connect(qmp_socket: pathlib.Path, process: subprocess.Popen[str], timeout: float) -> socket.socket:
    wait_for_socket(qmp_socket, process, timeout=timeout)
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(timeout)
        client.connect(str(qmp_socket))
        greeting = read_qmp(client)
        if "QMP" not in greeting:
            raise SmokeFailure(f"missing QMP greeting: {greeting!r}")
        send_qmp(client, {"execute": "qmp_capabilities"})
        return client
    except Exception:
        client.close()
        raise


def machine_inventory_names(machines: Any) -> set[str]:
    if not isinstance(machines, list):
        raise SmokeFailure(f"query-machines returned malformed payload: {machines!r}")
    names: set[str] = set()
    for machine in machines:
        if not isinstance(machine, dict):
            raise SmokeFailure(f"query-machines returned malformed machine entry: {machine!r}")
        for key in ("name", "alias"):
            value = machine.get(key)
            if isinstance(value, str):
                names.add(value)
    return names


def has_machine_name(names: set[str], marker: str) -> bool:
    return marker in names or any(name.startswith(f"{marker}-") or name.endswith(f"-{marker}") for name in names)


def check_qmp_launch(binary: pathlib.Path, markers: tuple[str, ...], timeout: float) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="symfit-system-") as tmpdir:
        qmp_socket = pathlib.Path(tmpdir) / "qmp.sock"
        command = [
            str(binary),
            "-machine",
            "none",
            "-nodefaults",
            "-display",
            "none",
            "-monitor",
            "none",
            "-serial",
            "none",
            "-parallel",
            "none",
            "-S",
            "-qmp",
            f"unix:{qmp_socket},server,nowait",
        ]
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            with qmp_connect(qmp_socket, process, timeout=timeout) as client:
                status_response = send_qmp(client, {"execute": "query-status"})
                status = status_response.get("return")
                if not isinstance(status, dict):
                    raise SmokeFailure(f"query-status returned malformed payload: {status_response!r}")
                if status.get("running") is not False:
                    raise SmokeFailure(f"{binary.name} did not honor -S paused startup: {status!r}")
                if status.get("status") not in {"prelaunch", "paused"}:
                    raise SmokeFailure(f"{binary.name} unexpected paused status: {status!r}")
                machine_response = send_qmp(client, {"execute": "query-machines"})
                machine_names = machine_inventory_names(machine_response.get("return"))
                missing = [marker for marker in markers if not has_machine_name(machine_names, marker)]
                if missing:
                    raise SmokeFailure(
                        f"{binary.name} QMP query-machines missing expected markers {missing}: "
                        f"{sorted(machine_names)}"
                    )
                send_qmp(client, {"execute": "quit"})
            returncode = process.wait(timeout=timeout)
            if returncode != 0:
                stdout, stderr = process.communicate(timeout=1.0)
                raise SmokeFailure(
                    f"{binary.name} quit with rc={returncode}\nstdout:\n{stdout}\nstderr:\n{stderr}"
                )
            return {"qmp_status": status, "machine_markers": list(markers), "returncode": returncode}
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1.0)


def read_file(path: pathlib.Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""


def terminate_process(process: subprocess.Popen[str]) -> int:
    if process.poll() is None:
        process.terminate()
        try:
            return process.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            process.kill()
            return process.wait(timeout=1.0)
    return int(process.returncode)


def wait_for_serial_marker(
    process: subprocess.Popen[str],
    serial_path: pathlib.Path,
    marker: str,
    timeout: float,
    *,
    terminate_on_marker: bool,
) -> tuple[int, str]:
    deadline = time.monotonic() + timeout
    last_output = ""
    while time.monotonic() < deadline:
        last_output = read_file(serial_path)
        if marker in last_output:
            if terminate_on_marker:
                return terminate_process(process), last_output
            try:
                return process.wait(timeout=timeout), last_output
            except subprocess.TimeoutExpired as exc:
                raise SmokeFailure(f"guest printed marker but system binary did not exit:\n{last_output}") from exc
        returncode = process.poll()
        if returncode is not None:
            last_output = read_file(serial_path)
            if marker in last_output:
                return int(returncode), last_output
            raise SmokeFailure(
                f"system binary exited before guest marker {marker!r}: rc={returncode}\n"
                f"serial:\n{last_output}"
            )
        time.sleep(0.05)
    last_output = read_file(serial_path)
    raise SmokeFailure(f"timed out waiting for guest marker {marker!r}; serial output:\n{last_output}")


def wait_until_serial_marker(
    process: subprocess.Popen[str],
    serial_path: pathlib.Path,
    marker: str,
    timeout: float,
) -> str:
    deadline = time.monotonic() + timeout
    last_output = ""
    while time.monotonic() < deadline:
        last_output = read_file(serial_path)
        if marker in last_output:
            return last_output
        returncode = process.poll()
        if returncode is not None:
            raise SmokeFailure(
                f"system binary exited before guest marker {marker!r}: rc={returncode}\n"
                f"serial:\n{last_output}"
            )
        time.sleep(0.05)
    last_output = read_file(serial_path)
    raise SmokeFailure(f"timed out waiting for guest marker {marker!r}; serial output:\n{last_output}")


def assert_qmp_paused(client: socket.socket, binary: pathlib.Path) -> dict[str, Any]:
    status_response = send_qmp(client, {"execute": "query-status"})
    status = status_response.get("return")
    if not isinstance(status, dict):
        raise SmokeFailure(f"query-status returned malformed payload: {status_response!r}")
    if status.get("running") is not False:
        raise SmokeFailure(f"{binary.name} did not honor -S paused startup: {status!r}")
    if status.get("status") not in {"prelaunch", "paused"}:
        raise SmokeFailure(f"{binary.name} unexpected paused status: {status!r}")
    return status


def x86_boot_command(
    binary: pathlib.Path,
    image: pathlib.Path,
    serial: pathlib.Path,
    *,
    qmp_socket: pathlib.Path | None = None,
    paused: bool = False,
) -> list[str]:
    command = [
        str(binary),
        "-machine",
        "pc",
        "-display",
        "none",
        "-monitor",
        "none",
        "-parallel",
        "none",
        "-no-reboot",
        "-boot",
        "a",
        "-drive",
        f"file={image},format=raw,if=floppy,readonly=on",
        "-serial",
        f"file:{serial}",
        "-device",
        "isa-debug-exit,iobase=0xf4,iosize=0x04",
    ]
    if paused:
        command.append("-S")
    if qmp_socket is not None:
        command.extend(["-qmp", f"unix:{qmp_socket},server,nowait"])
    return command


def aarch64_boot_command(
    binary: pathlib.Path,
    image: pathlib.Path,
    serial: pathlib.Path,
    *,
    qmp_socket: pathlib.Path | None = None,
    paused: bool = False,
) -> list[str]:
    command = [
        str(binary),
        "-machine",
        "virt",
        "-cpu",
        "cortex-a57",
        "-m",
        "64M",
        "-display",
        "none",
        "-monitor",
        "none",
        "-parallel",
        "none",
        "-no-reboot",
        "-kernel",
        str(image),
        "-serial",
        f"file:{serial}",
    ]
    if paused:
        command.append("-S")
    if qmp_socket is not None:
        command.extend(["-qmp", f"unix:{qmp_socket},server,nowait"])
    return command


def check_x86_boot_image(binary: pathlib.Path, marker: str, timeout: float) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="symfit-x86-vm-") as tmpdir:
        tmp = pathlib.Path(tmpdir)
        image = tmp / "boot.img"
        serial = tmp / "serial.log"
        write_x86_boot_sector(image, marker)
        command = x86_boot_command(binary, image, serial)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            returncode, serial_output = wait_for_serial_marker(
                process,
                serial,
                marker,
                timeout,
                terminate_on_marker=False,
            )
            if returncode != 1:
                stdout, stderr = process.communicate(timeout=1.0)
                raise SmokeFailure(
                    f"{binary.name} x86 boot image returned rc={returncode}, expected 1 from isa-debug-exit\n"
                    f"serial:\n{serial_output}\nstdout:\n{stdout}\nstderr:\n{stderr}"
                )
            return {"image": "x86_boot_sector", "marker": marker, "returncode": returncode}
        finally:
            terminate_process(process)


def check_aarch64_boot_image(binary: pathlib.Path, marker: str, timeout: float) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="symfit-aarch64-vm-") as tmpdir:
        tmp = pathlib.Path(tmpdir)
        image = tmp / "kernel.img"
        serial = tmp / "serial.log"
        write_aarch64_kernel(image, marker)
        command = aarch64_boot_command(binary, image, serial)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            returncode, _serial_output = wait_for_serial_marker(
                process,
                serial,
                marker,
                timeout,
                terminate_on_marker=True,
            )
            return {"image": "aarch64_raw_kernel", "marker": marker, "returncode": returncode}
        finally:
            terminate_process(process)


def check_x86_qmp_boot_image(binary: pathlib.Path, marker: str, timeout: float) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="symfit-x86-qmp-vm-") as tmpdir:
        tmp = pathlib.Path(tmpdir)
        image = tmp / "boot.img"
        serial = tmp / "serial.log"
        qmp_socket = tmp / "qmp.sock"
        write_x86_boot_sector(image, marker)
        command = x86_boot_command(binary, image, serial, qmp_socket=qmp_socket, paused=True)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with qmp_connect(qmp_socket, process, timeout=timeout) as client:
                paused_status = assert_qmp_paused(client, binary)
                if marker in read_file(serial):
                    raise SmokeFailure(f"{binary.name} x86 guest ran before QMP cont")
                send_qmp_nowait(client, {"execute": "cont"})
                returncode, serial_output = wait_for_serial_marker(
                    process,
                    serial,
                    marker,
                    timeout,
                    terminate_on_marker=False,
                )
                if returncode != 1:
                    stdout, stderr = process.communicate(timeout=1.0)
                    raise SmokeFailure(
                        f"{binary.name} QMP-resumed x86 image returned rc={returncode}, expected 1\n"
                        f"serial:\n{serial_output}\nstdout:\n{stdout}\nstderr:\n{stderr}"
                    )
                return {
                    "image": "x86_boot_sector",
                    "marker": marker,
                    "paused_status": paused_status,
                    "returncode": returncode,
                }
        finally:
            terminate_process(process)


def check_aarch64_qmp_boot_image(binary: pathlib.Path, marker: str, timeout: float) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="symfit-aarch64-qmp-vm-") as tmpdir:
        tmp = pathlib.Path(tmpdir)
        image = tmp / "kernel.img"
        serial = tmp / "serial.log"
        qmp_socket = tmp / "qmp.sock"
        write_aarch64_kernel(image, marker)
        command = aarch64_boot_command(binary, image, serial, qmp_socket=qmp_socket, paused=True)
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            with qmp_connect(qmp_socket, process, timeout=timeout) as client:
                paused_status = assert_qmp_paused(client, binary)
                if marker in read_file(serial):
                    raise SmokeFailure(f"{binary.name} AArch64 guest ran before QMP cont")
                send_qmp(client, {"execute": "cont"})
                wait_until_serial_marker(process, serial, marker, timeout)
                running_response = send_qmp(client, {"execute": "query-status"})
                running_status = running_response.get("return")
                if not isinstance(running_status, dict):
                    raise SmokeFailure(f"query-status returned malformed payload: {running_response!r}")
                if running_status.get("running") is not True:
                    raise SmokeFailure(f"{binary.name} did not run after QMP cont: {running_status!r}")
                send_qmp(client, {"execute": "quit"})
            returncode = process.wait(timeout=timeout)
            if returncode != 0:
                stdout, stderr = process.communicate(timeout=1.0)
                raise SmokeFailure(
                    f"{binary.name} QMP quit after AArch64 boot returned rc={returncode}\n"
                    f"stdout:\n{stdout}\nstderr:\n{stderr}"
                )
            return {
                "image": "aarch64_raw_kernel",
                "marker": marker,
                "paused_status": paused_status,
                "running_status": running_status,
                "returncode": returncode,
            }
        finally:
            terminate_process(process)


def check_x86_ia_rpc_boot_image(binary: pathlib.Path, marker: str, timeout: float) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="symfit-x86-ia-vm-") as tmpdir:
        tmp = pathlib.Path(tmpdir)
        image = tmp / "boot.img"
        serial = tmp / "serial.log"
        rpc_socket = tmp / "ia.sock"
        write_x86_boot_sector(image, marker)
        command = x86_boot_command(binary, image, serial)
        env = os.environ.copy()
        env["IA_RPC_SOCKET"] = str(rpc_socket)
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        try:
            with ia_rpc_connect(rpc_socket, process, timeout=timeout) as client:
                req_id = 1
                capabilities = send_ia_rpc(client, req_id, "capabilities")
                req_id += 1
                caps = capabilities.get("capabilities")
                if not isinstance(caps, dict):
                    raise SmokeFailure(f"IA/RPC capabilities malformed: {capabilities!r}")
                for key in (
                    "pause_resume",
                    "read_registers",
                    "read_memory",
                    "read_symbolic_expression",
                    "read_path_constraints",
                    "read_recent_path_constraints",
                    "symbolize_register",
                ):
                    if caps.get(key) is not True:
                        raise SmokeFailure(f"IA/RPC missing expected capability {key!r}: {caps!r}")

                status = send_ia_rpc(client, req_id, "query_status")
                req_id += 1
                if status.get("status") != "paused":
                    raise SmokeFailure(f"IA/RPC did not start paused: {status!r}")
                if marker in read_file(serial):
                    raise SmokeFailure(f"{binary.name} x86 guest ran before IA/RPC resume")

                registers = send_ia_rpc(
                    client,
                    req_id,
                    "get_registers",
                    {"names": ["rip", "rsp", "rax"]},
                )
                req_id += 1
                if "registers" not in registers:
                    raise SmokeFailure(f"IA/RPC get_registers malformed: {registers!r}")

                symbolic_register = send_ia_rpc(
                    client,
                    req_id,
                    "symbolize_register",
                    {"register": "rax"},
                )
                req_id += 1
                label = symbolic_register.get("label")
                if not isinstance(label, str) or not label.startswith("0x"):
                    raise SmokeFailure(f"IA/RPC symbolize_register malformed: {symbolic_register!r}")
                expression = send_ia_rpc(client, req_id, "get_symbolic_expression", {"label": label})
                req_id += 1
                if expression.get("label") != label:
                    raise SmokeFailure(f"IA/RPC symbolic expression mismatch: {expression!r}")

                memory = send_ia_rpc(
                    client,
                    req_id,
                    "read_memory",
                    {"address": "0x7c00", "size": 4, "address_space": "physical"},
                )
                req_id += 1
                if not isinstance(memory.get("bytes"), str) or len(memory["bytes"]) != 8:
                    raise SmokeFailure(f"IA/RPC physical read malformed: {memory!r}")

                recent = send_ia_rpc(client, req_id, "get_recent_path_constraints", {"limit": 4})
                req_id += 1
                if not isinstance(recent.get("constraints"), list):
                    raise SmokeFailure(f"IA/RPC recent path constraints malformed: {recent!r}")

                send_ia_rpc(client, req_id, "close")
            returncode = process.wait(timeout=timeout)
            return {
                "image": "x86_boot_sector",
                "status": status["status"],
                "memory_bytes": memory["bytes"],
                "returncode": returncode,
            }
        finally:
            terminate_process(process)


def check_aarch64_ia_rpc_boot_image(binary: pathlib.Path, marker: str, timeout: float) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="symfit-aarch64-ia-vm-") as tmpdir:
        tmp = pathlib.Path(tmpdir)
        image = tmp / "kernel.img"
        serial = tmp / "serial.log"
        rpc_socket = tmp / "ia.sock"
        write_aarch64_kernel(image, marker)
        image_prefix = image.read_bytes()[:4].hex()
        command = aarch64_boot_command(binary, image, serial)
        env = os.environ.copy()
        env["IA_RPC_SOCKET"] = str(rpc_socket)
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        try:
            with ia_rpc_connect(rpc_socket, process, timeout=timeout) as client:
                req_id = 1
                capabilities = send_ia_rpc(client, req_id, "capabilities")
                req_id += 1
                caps = capabilities.get("capabilities")
                if not isinstance(caps, dict):
                    raise SmokeFailure(f"IA/RPC capabilities malformed: {capabilities!r}")
                for key in (
                    "pause_resume",
                    "read_registers",
                    "read_memory",
                    "read_symbolic_expression",
                    "read_path_constraints",
                    "read_recent_path_constraints",
                    "symbolize_register",
                ):
                    if caps.get(key) is not True:
                        raise SmokeFailure(f"IA/RPC missing expected capability {key!r}: {caps!r}")

                status = send_ia_rpc(client, req_id, "query_status")
                req_id += 1
                if status.get("status") != "paused":
                    raise SmokeFailure(f"IA/RPC did not start paused: {status!r}")
                if marker in read_file(serial):
                    raise SmokeFailure(f"{binary.name} AArch64 guest ran before IA/RPC resume")

                registers = send_ia_rpc(
                    client,
                    req_id,
                    "get_registers",
                    {"names": ["pc", "sp", "x0"]},
                )
                req_id += 1
                if "registers" not in registers:
                    raise SmokeFailure(f"IA/RPC get_registers malformed: {registers!r}")

                symbolic_register = send_ia_rpc(
                    client,
                    req_id,
                    "symbolize_register",
                    {"register": "x0"},
                )
                req_id += 1
                label = symbolic_register.get("label")
                if not isinstance(label, str) or not label.startswith("0x"):
                    raise SmokeFailure(f"IA/RPC symbolize_register malformed: {symbolic_register!r}")
                expression = send_ia_rpc(client, req_id, "get_symbolic_expression", {"label": label})
                req_id += 1
                if expression.get("label") != label:
                    raise SmokeFailure(f"IA/RPC symbolic expression mismatch: {expression!r}")

                memory = send_ia_rpc(
                    client,
                    req_id,
                    "read_memory",
                    {"address": "0x40080000", "size": 4, "address_space": "physical"},
                )
                req_id += 1
                if memory.get("bytes") != image_prefix:
                    raise SmokeFailure(f"IA/RPC physical read mismatch: expected {image_prefix}, got {memory!r}")

                recent = send_ia_rpc(client, req_id, "get_recent_path_constraints", {"limit": 4})
                req_id += 1
                if not isinstance(recent.get("constraints"), list):
                    raise SmokeFailure(f"IA/RPC recent path constraints malformed: {recent!r}")

                send_ia_rpc(client, req_id, "close")
            returncode = process.wait(timeout=timeout)
            return {
                "image": "aarch64_raw_kernel",
                "status": status["status"],
                "memory_prefix": image_prefix,
                "returncode": returncode,
            }
        finally:
            terminate_process(process)


def check_boot_image(arch: str, binary: pathlib.Path, marker: str, timeout: float) -> dict[str, Any]:
    if arch == "x86_64":
        return check_x86_boot_image(binary, marker=marker, timeout=timeout)
    if arch == "aarch64":
        return check_aarch64_boot_image(binary, marker=marker, timeout=timeout)
    raise SmokeFailure(f"unsupported system boot-image arch: {arch}")


def check_qmp_boot_image(arch: str, binary: pathlib.Path, marker: str, timeout: float) -> dict[str, Any]:
    if arch == "x86_64":
        return check_x86_qmp_boot_image(binary, marker=marker, timeout=timeout)
    if arch == "aarch64":
        return check_aarch64_qmp_boot_image(binary, marker=marker, timeout=timeout)
    raise SmokeFailure(f"unsupported system QMP boot-image arch: {arch}")


def check_ia_rpc_boot_image(arch: str, binary: pathlib.Path, marker: str, timeout: float) -> dict[str, Any]:
    if arch == "x86_64":
        return check_x86_ia_rpc_boot_image(binary, marker=marker, timeout=timeout)
    if arch == "aarch64":
        return check_aarch64_ia_rpc_boot_image(binary, marker=marker, timeout=timeout)
    raise SmokeFailure(f"unsupported system IA/RPC boot-image arch: {arch}")


def run_target(arch: str, build_dir: pathlib.Path, timeout: float) -> dict[str, Any]:
    spec = SYSTEM_TARGETS[arch]
    binary = build_dir / str(spec["target_dir"]) / str(spec["binary"])
    require_executable(binary)
    markers = tuple(str(item) for item in spec["machine_markers"])
    boot_marker = str(spec["boot_marker"])
    return {
        "arch": arch,
        "binary": str(binary),
        "version": run_step(f"{arch} version", lambda: check_version(binary, timeout=timeout)),
        "machine_help": run_step(
            f"{arch} machine help",
            lambda: check_machine_help(binary, markers=markers, timeout=timeout),
        ),
        "qmp_launch": run_step(
            f"{arch} QMP launch",
            lambda: check_qmp_launch(binary, markers=markers, timeout=timeout),
        ),
        "boot_image": run_step(
            f"{arch} direct boot image",
            lambda: check_boot_image(arch, binary, marker=boot_marker, timeout=timeout),
        ),
        "qmp_boot_image": run_step(
            f"{arch} QMP boot image",
            lambda: check_qmp_boot_image(arch, binary, marker=boot_marker, timeout=timeout),
        ),
        "ia_rpc_boot_image": run_step(
            f"{arch} IA/RPC boot image",
            lambda: check_ia_rpc_boot_image(arch, binary, marker=boot_marker, timeout=timeout),
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="SymFit system-mode smoke test")
    parser.add_argument(
        "--build-dir",
        default=str(DEFAULT_BUILD_DIR),
        help="Path to the SymFit build directory containing *-softmmu outputs",
    )
    parser.add_argument(
        "--arch",
        action="append",
        choices=sorted(SYSTEM_TARGETS),
        help="Architecture to test. May be specified multiple times. Defaults to all system targets.",
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="Per-operation timeout in seconds")
    parser.add_argument("--json", action="store_true", help="Print JSON summary")
    args = parser.parse_args()

    build_dir = pathlib.Path(args.build_dir).resolve()
    arches = args.arch or sorted(SYSTEM_TARGETS)

    try:
        summaries = [run_target(arch, build_dir=build_dir, timeout=args.timeout) for arch in arches]
    except Exception as exc:
        print(f"SymFit system-mode smoke test failed: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps({"targets": summaries}, indent=2, sort_keys=True))
    else:
        for summary in summaries:
            status = summary["qmp_launch"]["qmp_status"]["status"]
            image = summary["boot_image"]["image"]
            qmp_image = summary["qmp_boot_image"]["image"]
            ia_image = summary["ia_rpc_boot_image"]["image"]
            print(
                f"{summary['arch']}: {pathlib.Path(summary['binary']).name} ok "
                f"(QMP status={status}, boot={image}, qmp_boot={qmp_image}, ia_rpc={ia_image})"
            )
        print("SymFit system-mode smoke test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
