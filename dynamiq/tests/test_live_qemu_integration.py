from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import pytest

from dynamiq.backends.qemu_user_instrumented import QemuUserInstrumentedBackend


def _lookup_symbol(path: Path, symbol: str) -> str:
    proc = subprocess.run(
        ["nm", "-n", str(path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == symbol:
            return "0x" + parts[0].lower()
    raise AssertionError(f"missing symbol {symbol} in {path}")


def _distinct_labels(constraints: list[dict[str, object]]) -> list[str]:
    labels: list[str] = []
    seen: set[str] = set()
    for entry in constraints:
        label = str(entry["label"]).lower()
        if label in seen:
            continue
        seen.add(label)
        labels.append(str(entry["label"]))
    return labels


@pytest.mark.live_qemu
def test_live_qemu_backend_rpc_run_until_address(live_qemu_start_kwargs: dict[str, object]) -> None:
    backend = QemuUserInstrumentedBackend()
    backend.start(**live_qemu_start_kwargs)
    try:
        caps = backend.capabilities()
        regs = backend.get_registers(["rip"])
        rip = regs["result"]["registers"]["rip"]
        disassembly = backend.disassemble(rip, count=8)
        instructions = disassembly["result"]["instructions"]
        assert len(instructions) >= 2
        target_address = str(instructions[min(3, len(instructions) - 1)]["address"])

        stop = backend.run_until_address(target_address, timeout=5.0)
        regs_after = backend.get_registers(["rip"])
        state = backend.get_state()

        assert caps["read_registers"] is True
        assert caps["disassemble"] is True
        assert caps["run_until_address"] is True
        assert state["rpc_protocol_version"] == 1
        assert state["rpc_capabilities"]["read_registers"] is True
        assert state["rpc_capabilities"]["run_until_address"] is True
        assert stop["result"]["matched"] is True
        assert stop["result"]["matched_pc"] == target_address
        assert regs_after["result"]["registers"]["rip"] == stop["result"]["pc"]
        assert state["pc"] == stop["result"]["pc"]
        assert state["backend"] == "qemu_user_instrumented"
    finally:
        backend.close()


@pytest.mark.live_qemu
def test_live_qemu_backend_list_memory_maps_schema(live_qemu_start_kwargs: dict[str, object]) -> None:
    backend = QemuUserInstrumentedBackend()
    backend.start(**live_qemu_start_kwargs)
    try:
        result = backend.list_memory_maps()
        maps = result["result"]["maps"]
        regions = maps["regions"]

        assert isinstance(regions, list)
        assert len(regions) > 0
        first = regions[0]
        assert {"start", "end", "perm", "name"} <= set(first.keys())
        assert isinstance(first["start"], str) and first["start"].startswith("0x")
        assert isinstance(first["end"], str) and first["end"].startswith("0x")
        assert isinstance(first["perm"], str) and len(first["perm"]) == 3
        assert first["name"] is None or isinstance(first["name"], str)

        target = str(Path(live_qemu_start_kwargs["target"]).resolve())
        names = {region.get("name") for region in regions if isinstance(region.get("name"), str)}
        assert target in names or "[stack]" in names
    finally:
        backend.close()


@pytest.mark.live_qemu
def test_live_qemu_backend_single_step(live_qemu_start_kwargs: dict[str, object]) -> None:
    backend = QemuUserInstrumentedBackend()
    backend.start(**live_qemu_start_kwargs)
    try:
        caps = backend.capabilities()
        assert caps["single_step"] is True

        rip = backend.get_registers(["rip"])["result"]["registers"]["rip"]
        disassembly = backend.disassemble(rip, count=2)
        instructions = disassembly["result"]["instructions"]
        assert len(instructions) >= 2
        next_pc = str(instructions[1]["address"])

        step = backend.step(1, timeout=5.0)
        regs_after = backend.get_registers(["rip"])

        assert step["result"]["status"] == "paused"
        assert step["result"]["executed"] == 1
        assert step["result"]["pc"] != rip
        assert regs_after["result"]["registers"]["rip"] == step["result"]["pc"]
    finally:
        backend.close()


@pytest.mark.live_qemu
def test_live_qemu_backend_rpc_trace_lifecycle(live_qemu_start_kwargs: dict[str, object]) -> None:
    backend = QemuUserInstrumentedBackend()
    backend.start(**live_qemu_start_kwargs)
    try:
        caps = backend.capabilities()
        assert caps["trace_basic_block"] is True

        started = backend.trace_start(event_types=["basic_block"], address_ranges=None)
        trace_file = started["result"]["trace_file"]
        assert started["result"]["trace_active"] is True
        assert started["result"]["trace_kind"] == "basic_block"
        assert isinstance(trace_file, str) and trace_file != ""

        status = backend.trace_status()
        assert status["result"]["trace_active"] is True
        assert status["result"]["trace_kind"] == "basic_block"
        assert status["result"]["trace_file"] == trace_file

        backend.step(1, timeout=5.0)

        deadline = time.time() + 2.0
        trace_entries: list[dict[str, object]] = []
        while time.time() < deadline:
            trace_entries = backend.get_trace(limit=32)["result"]["trace"]
            if any(isinstance(item, dict) and item.get("type") == "basic_block" for item in trace_entries):
                break
            time.sleep(0.05)

        assert any(isinstance(item, dict) and item.get("type") == "basic_block" for item in trace_entries)
        assert Path(trace_file).exists()

        stopped = backend.trace_stop()
        assert stopped["result"]["trace_active"] is False
        assert stopped["result"]["trace_file"] == trace_file
    finally:
        backend.close()


@pytest.mark.live_qemu
def test_live_qemu_backend_get_symbolic_expression(live_qemu_start_kwargs: dict[str, object]) -> None:
    backend = QemuUserInstrumentedBackend()
    backend.start(**live_qemu_start_kwargs)
    try:
        sym_reg = backend.symbolize_register("rax", name="expr_probe")
        label = sym_reg["result"]["label"]

        expression = backend.get_symbolic_expression(label)

        assert expression["result"]["label"] == label
        assert expression["result"]["op"] == "Input"
        assert expression["result"]["size"] >= 1
        assert "input(" in expression["result"]["expression"]
    finally:
        backend.close()


@pytest.mark.live_qemu
def test_live_qemu_backend_symbolize_register_and_memory(live_qemu_start_kwargs: dict[str, object]) -> None:
    backend = QemuUserInstrumentedBackend()
    backend.start(**live_qemu_start_kwargs)
    try:
        regs_before = backend.get_registers(["rax", "rsp"])
        sym_regs_before = regs_before["result"]["symbolic_registers"]
        rsp = regs_before["result"]["registers"]["rsp"]

        mem_before = backend.read_memory(rsp, 8)
        symbolic_before = mem_before["result"]["symbolic_bytes"]

        assert sym_regs_before["rax"]["symbolic"] is False
        assert sym_regs_before["rax"]["label"] == "0x0"
        assert sym_regs_before["rsp"]["symbolic"] is False
        assert all(entry["symbolic"] is False for entry in symbolic_before)

        sym_mem = backend.symbolize_memory(rsp, 8, name="stack_probe")
        sym_reg = backend.symbolize_register("rax", name="acc_probe")
        regs_after = backend.get_registers(["rax"])
        mem_after = backend.read_memory(rsp, 8)

        assert sym_mem["result"]["address"] == rsp
        assert sym_mem["result"]["size"] == 8
        assert all(entry["symbolic"] is True for entry in sym_mem["result"]["bytes"])

        assert sym_reg["result"]["register"] == "rax"
        assert sym_reg["result"]["symbolic"] is True
        assert sym_reg["result"]["label"] != "0x0"

        rax_after = regs_after["result"]["symbolic_registers"]["rax"]
        assert rax_after["symbolic"] is True
        assert rax_after["label"] == sym_reg["result"]["label"]

        symbolic_after = mem_after["result"]["symbolic_bytes"]
        assert len(symbolic_after) == 8
        assert all(entry["symbolic"] is True for entry in symbolic_after)
    finally:
        backend.close()


@pytest.mark.live_qemu
def test_live_qemu_backend_path_constraint_queries() -> None:
    target = Path("/home/heng/git/symfit/tests/symfit/interactive/path_constraints_target")
    rpc_socket = Path("/tmp/dynamiq-live-path-constraints.sock")
    qemu_user_path = Path(
        os.environ.get(
            "IA_LIVE_QEMU_USER_PATH",
            "/home/heng/git/symfit/build/symfit/x86_64-linux-user/symfit-x86_64",
        )
    )
    if not target.exists():
        pytest.skip(f"path-constraint target does not exist: {target}")
    if not qemu_user_path.exists():
        pytest.skip(f"instrumented qemu user binary does not exist: {qemu_user_path}")

    backend = QemuUserInstrumentedBackend()
    backend.start(
        target=str(target),
        args=[],
        cwd=None,
        qemu_config={
            "launch": True,
            "qemu_user_path": str(qemu_user_path),
            "target": str(target),
            "target_args": [],
            "instrumentation_rpc_socket_path": str(rpc_socket),
        },
    )
    try:
        data_addr = _lookup_symbol(target, "data_byte")
        branch2_taken_addr = _lookup_symbol(target, "branch2_taken")

        sym = backend.symbolize_memory(data_addr, 1, name="path_seed")
        stop = backend.run_until_address(branch2_taken_addr, timeout=5.0)
        recent = backend.recent_path_constraints(limit=4)
        labels = _distinct_labels(recent["result"]["constraints"])
        assert sym["result"]["bytes"][0]["symbolic"] is True
        assert stop["result"]["matched"] is True
        assert len(labels) >= 2

        closure = backend.path_constraint_closure(labels[0])

        assert recent["result"]["count"] >= 2
        assert recent["result"]["constraints"][0]["op"] == "ICmp"
        assert recent["result"]["constraints"][0]["taken"] is True
        assert closure["result"]["root"]["label"].lower() == labels[0].lower()
        assert closure["result"]["root"]["taken"] is True
        assert labels[1].lower() in {
            str(entry["label"]).lower() for entry in closure["result"]["constraints"]
        }
        assert all(entry["taken"] is True for entry in closure["result"]["constraints"])
    finally:
        backend.close()
