from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from dynamiq.backends.qemu_user_instrumented import QemuUserInstrumentedBackend
from dynamiq.session import AnalysisSession


ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"
TARGET_SRC = EXAMPLES / "sample_target.c"
TARGET_BIN = EXAMPLES / "sample_target"


def compile_target() -> None:
    gcc = shutil.which("gcc")
    if gcc is None:
        raise SystemExit("gcc is required to build examples/sample_target.c")
    subprocess.run(
        [gcc, "-g", "-O0", "-fno-omit-frame-pointer", "-fno-pie", "-no-pie", "-o", str(TARGET_BIN), str(TARGET_SRC)],
        check=True,
    )


def resolve_qemu() -> str:
    local_cache = ROOT / "tools" / "qemu" / "qemu-x86_64-instrumented"
    if local_cache.exists():
        return str(local_cache)
    qemu = shutil.which("qemu-x86_64")
    if qemu is not None:
        return qemu
    raise SystemExit(
        "qemu-x86_64 not found; populate tools/qemu with "
        "./scripts/build_qemu_toolchain.sh or install qemu-user"
    )


def wait_for_socket(path: Path, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return
        time.sleep(0.05)
    raise SystemExit(f"timed out waiting for RPC socket: {path}")


def require_pc_match(result: dict, expected_address: str) -> None:
    state_pc = result["state"].get("pc")
    if not isinstance(state_pc, str) or state_pc.lower() != expected_address.lower():
        raise SystemExit(
            f"run_until_address did not stop at {expected_address}: "
            f"backend reported state.pc={state_pc!r}"
        )


def choose_future_instruction(disassembly: dict) -> str:
    instructions = disassembly["result"]["instructions"]
    if len(instructions) < 2:
        raise SystemExit("disassembly did not return enough instructions to choose a future stop address")
    return str(instructions[min(3, len(instructions) - 1)]["address"])


def main() -> int:
    compile_target()
    qemu_user_path = resolve_qemu()

    with tempfile.TemporaryDirectory(prefix="ia-qemu-rpc-") as tmp:
        rpc_socket = Path(tmp) / "rpc.sock"

        session = AnalysisSession(backend=QemuUserInstrumentedBackend())
        session.start(
            target=str(TARGET_BIN),
            args=["demo"],
            cwd=str(ROOT),
            qemu_config={
                "launch": True,
                "qemu_user_path": qemu_user_path,
                "instrumentation_rpc_socket_path": str(rpc_socket),
                "launch_connect_timeout": 10.0,
                "capabilities_override": {
                    "disassemble": True,
                    "run_until_address": True,
                },
            },
        )

        try:
            wait_for_socket(rpc_socket)

            print("== capabilities ==")
            print(session.capabilities())

            print("== state ==")
            print(session.get_state())

            print("== registers ==")
            print(session.get_registers(["rip", "rsp", "rbp", "rax"]))

            print("== advance basic block ==")
            print(session.advance_basic_blocks(1))

            print("== registers after advance ==")
            print(session.get_registers(["rip", "rsp", "rbp", "rax"]))

            rip = session.get_registers(["rip"])["result"]["registers"]["rip"]
            print("== disassemble ==")
            disassembly = session.disassemble(rip, count=8)
            print(disassembly)

            target_address = choose_future_instruction(disassembly)
            print("== run until future instruction ==")
            print({"address": target_address})
            run_result = session.run_until_address(target_address)
            print(run_result)
            require_pc_match(run_result, target_address)

            print("== memory maps ==")
            print(session.list_memory_maps())

            print("== memory ==")
            rip = session.get_registers(["rip"])["result"]["registers"]["rip"]
            print(session.read_memory(rip, 16))

            print("== close ==")
            print(session.close())
        finally:
            session.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
