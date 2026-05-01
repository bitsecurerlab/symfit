from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from dynamiq.errors import SessionTimeoutError
from dynamiq.script_api import ScriptSession
from dynamiq.script_helpers import BytesReplayAdapter, solve_for


def _compile_branch_target(workdir: Path) -> Path:
    gcc = shutil.which("gcc")
    if gcc is None:
        pytest.skip("gcc is required for live solve_for test")
    source = workdir / "solve_for_branch.c"
    binary = workdir / "solve_for_branch"
    source.write_text(
        (
            "#include <unistd.h>\n"
            "\n"
            "volatile unsigned char sink;\n"
            "\n"
            "int main(void) {\n"
            "    unsigned char c = 0;\n"
            "    if (read(STDIN_FILENO, &c, 1) != 1) {\n"
            "        return 3;\n"
            "    }\n"
            "    if (c == 'Z') {\n"
            "        asm volatile(\".global target_hit\\n\"\n"
            "                     \"target_hit:\\n\");\n"
            "        sink = c;\n"
            "        return 0;\n"
            "    }\n"
            "    asm volatile(\".global target_miss\\n\"\n"
            "                 \"target_miss:\\n\");\n"
            "    sink = c;\n"
            "    return 1;\n"
            "}\n"
        ),
        encoding="utf-8",
    )
    subprocess.run(
        [gcc, str(source), "-O0", "-g", "-fno-pie", "-no-pie", "-o", str(binary)],
        check=True,
    )
    return binary


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


def _normalize_hex(value: str) -> str:
    return f"0x{int(value, 16):x}"


def _resolve_symfit_x86_64() -> str:
    env_path = os.environ.get("IA_LIVE_QEMU_USER_PATH")
    if env_path:
        path = Path(env_path)
        if not path.exists():
            pytest.skip(f"IA_LIVE_QEMU_USER_PATH does not exist: {path}")
        return str(path)

    repo_root = Path(__file__).resolve().parents[2]
    candidates = [
        repo_root / "build" / "symfit-symsan-ext" / "x86_64-linux-user" / "symfit-x86_64",
        repo_root / "build" / "symfit-symsan" / "x86_64-linux-user" / "symfit-x86_64",
        repo_root / "build" / "symfit" / "x86_64-linux-user" / "symfit-x86_64",
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    discovered = shutil.which("qemu-x86_64")
    if discovered is None:
        pytest.skip("no x86_64 qemu-user binary found")
    return discovered


def _session(binary: Path, qemu_user_path: str) -> ScriptSession:
    return ScriptSession(
        target=str(binary),
        qemu_config={
            "launch": True,
            "qemu_user_path": qemu_user_path,
            "launch_connect_timeout": 5.0,
        },
    )


@pytest.mark.live_qemu
def test_live_solve_for_replays_stdin_candidate_to_target_pc(tmp_path: Path) -> None:
    binary = _compile_branch_target(tmp_path)
    qemu_user_path = _resolve_symfit_x86_64()
    target_hit = _lookup_symbol(binary, "target_hit")
    target_miss = _lookup_symbol(binary, "target_miss")

    with _session(binary, qemu_user_path) as session:
        try:
            session.write_stdin(b"A", symbolic=True)
            miss = session.run_until_address(target_miss, timeout=5.0)
        except SessionTimeoutError:
            pytest.skip("live qemu RPC socket unavailable in this environment")

        assert miss["result"]["matched"] is True

        def runner(candidate: bytes, target_pc: str, timeout: float) -> dict[str, Any]:
            with _session(binary, qemu_user_path) as replay_session:
                replay_session.write_stdin(candidate[:1], symbolic=False)
                verdict = replay_session.run_until_address(target_pc, timeout=timeout)
                return {
                    "reached": verdict["result"].get("matched") is True,
                    "stop": verdict["result"],
                }

        result = solve_for(
            session,
            target_hit,
            BytesReplayAdapter(seed=b"A", runner=runner),
            limit=8,
            timeout=5.0,
        )

        assert result["status"] == "reached"
        assert result["candidate"][:1] == b"Z"
        assert result["verdict"]["reached"] is True
        assert result["verdict"]["stop"]["matched"] is True
        assert _normalize_hex(result["verdict"]["stop"]["matched_address"]) == _normalize_hex(target_hit)
