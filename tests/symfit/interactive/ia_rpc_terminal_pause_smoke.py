#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

from ia_rpc_common import connect_rpc_socket, launch_backend, read_process_logs, rpc_call, wait_for_socket


def ensure_target(script_dir: pathlib.Path) -> str:
    cc = shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        raise RuntimeError("gcc or clang is required to build terminal_pause_target")

    source = script_dir / "terminal_pause_target.c"
    target = script_dir / "terminal_pause_target"
    if (not target.exists()) or source.stat().st_mtime_ns > target.stat().st_mtime_ns:
        subprocess.run(
            [cc, "-g", "-O0", "-fno-pie", "-no-pie", "-o", str(target), str(source)],
            check=True,
        )
    return str(target)


def run_case(args, target_path: str, mode: str, final_method: str):
    socket_path = args.socket_prefix + "-" + mode + ".sock"
    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass

    launch_args = argparse.Namespace(**vars(args))
    launch_args.target = target_path
    launch_args.target_args = [] if mode == "exit" else ["crash"]

    proc = None
    fgtest_tmp = None
    client = None
    stream = None
    req_id = 1

    try:
        proc, fgtest_tmp = launch_backend(launch_args, socket_path)
        wait_for_socket(socket_path, args.startup_timeout)
        client, stream = connect_rpc_socket(socket_path)

        summary = {}
        summary["capabilities"] = rpc_call(stream, req_id, "capabilities")
        req_id += 1
        summary["resume"] = rpc_call(stream, req_id, "resume")
        req_id += 1

        deadline = time.time() + args.pause_timeout
        terminal_status = None
        while time.time() < deadline:
            terminal_status = rpc_call(stream, req_id, "query_status")
            req_id += 1
            if terminal_status.get("status") == "paused" and terminal_status.get("pending_termination"):
                break
            time.sleep(0.05)
        summary["terminal_status"] = terminal_status
        if not terminal_status or not terminal_status.get("pending_termination"):
            raise RuntimeError(f"{mode}: expected pending terminal pause, got {terminal_status}")

        summary["registers"] = rpc_call(stream, req_id, "get_registers", {"names": ["rip", "rsp", "rax"]})
        req_id += 1

        summary[final_method] = rpc_call(stream, req_id, final_method)
        req_id += 1

        if stream is not None:
            stream.close()
            stream = None
        if client is not None:
            client.close()
            client = None

        rc = proc.wait(timeout=max(1.0, args.exit_timeout))
        summary["returncode"] = rc

        if mode == "exit":
            if terminal_status.get("termination_kind") not in {"exit", "exit_group"}:
                raise RuntimeError(f"exit: expected exit or exit_group, got {terminal_status}")
            if terminal_status.get("exit_code") != 0x42:
                raise RuntimeError(f"exit: expected exit_code 66, got {terminal_status}")
            if rc != 0x42:
                raise RuntimeError(f"exit: expected process returncode 66, got {rc}")
        else:
            if terminal_status.get("termination_kind") != "signal":
                raise RuntimeError(f"crash: expected termination_kind=signal, got {terminal_status}")
            if terminal_status.get("termination_signal") != 11:
                raise RuntimeError(f"crash: expected SIGSEGV(11), got {terminal_status}")
            if terminal_status.get("termination_fault_address") != "0x0":
                raise RuntimeError(f"crash: expected fault addr 0x0, got {terminal_status}")
            if rc not in {-11, 128 + 11}:
                raise RuntimeError(f"crash: expected SIGSEGV termination, got returncode {rc}")

        return summary

    finally:
        if stream is not None:
            stream.close()
        if client is not None:
            client.close()
        if proc is not None and proc.poll() is None:
            out, err = read_process_logs(proc)
            raise RuntimeError(
                f"{mode}: backend still running\nstdout:\n{out}\nstderr:\n{err}"
            )
        if fgtest_tmp is not None:
            fgtest_tmp.cleanup()
        try:
            os.unlink(socket_path)
        except FileNotFoundError:
            pass


def main():
    parser = argparse.ArgumentParser(description="SymFit IA/RPC terminal-pause smoke test")
    parser.add_argument("--symfit", required=True, help="Path to symfit-x86_64")
    parser.add_argument("--fgtest", help="Path to fgtest (required if --runner=fgtest)")
    parser.add_argument("--runner", choices=["direct", "fgtest"], default="direct")
    parser.add_argument("--target", help="Optional target program path")
    parser.add_argument("--socket-prefix", default="/tmp/symfit-ia-terminal")
    parser.add_argument("--startup-timeout", type=float, default=5.0)
    parser.add_argument("--pause-timeout", type=float, default=5.0)
    parser.add_argument("--exit-timeout", type=float, default=5.0)
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    target_path = args.target or ensure_target(script_dir)

    try:
        summary = {
            "exit_case": run_case(args, target_path, "exit", "close"),
            "crash_case": run_case(args, target_path, "crash", "resume"),
        }
        print("IA/RPC terminal-pause smoke test passed")
        print(json.dumps(summary, indent=2))
        return 0
    except Exception as exc:
        print(f"IA/RPC terminal-pause smoke test failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
