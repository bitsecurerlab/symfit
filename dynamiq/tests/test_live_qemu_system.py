from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

from dynamiq.script_api import ScriptSession


def _load_system_smoke_module():
    path = Path(__file__).resolve().parents[2] / "tests" / "symfit" / "system" / "symfit_system_smoke.py"
    spec = importlib.util.spec_from_file_location("symfit_system_smoke", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load system smoke helpers from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.live_qemu
def test_live_qemu_system_backend_reads_physical_boot_memory(tmp_path: Path) -> None:
    if os.environ.get("RUN_LIVE_QEMU") != "1":
        pytest.skip("set RUN_LIVE_QEMU=1 to run live qemu-system integration tests")

    qemu_system_path = Path(
        os.environ.get(
            "IA_LIVE_QEMU_SYSTEM_X86_64_PATH",
            Path(__file__).resolve().parents[2] / "build" / "symfit" / "x86_64-softmmu" / "symfit-system-x86_64",
        )
    )
    if not qemu_system_path.exists():
        pytest.skip(f"instrumented qemu-system binary does not exist: {qemu_system_path}")

    smoke = _load_system_smoke_module()
    image = tmp_path / "boot.img"
    serial = tmp_path / "serial.log"
    smoke.write_x86_boot_sector(image, "DYNAMIQ_SYSTEM_VM_OK")
    qemu_args = smoke.x86_boot_command(qemu_system_path, image, serial)[1:]

    with ScriptSession.system(
        qemu_system_path=str(qemu_system_path),
        qemu_args=qemu_args,
        arch="x86_64",
    ) as session:
        state = session.get_state()["state"]
        memory = session.read_memory("0x7c00", 4, address_space="physical")["result"]
        regs = session.get_registers(["rip", "rsp"])["result"]["registers"]

        assert state["qemu_mode"] == "system"
        assert state["session_status"] == "paused"
        assert memory["address"] == "0x7c00"
        assert memory["size"] == 4
        assert isinstance(memory["bytes"], str) and len(memory["bytes"]) == 8
        assert isinstance(regs, dict)
