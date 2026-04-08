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
        raise RuntimeError("gcc or clang is required to build symbolic_address_load_target")

    source = script_dir / "symbolic_address_load_target.S"
    target = script_dir / "symbolic_address_load_target"
    if (not target.exists()) or source.stat().st_mtime_ns > target.stat().st_mtime_ns:
        subprocess.run(
            [cc, "-nostdlib", "-no-pie", "-Wl,-z,noexecstack", "-o", str(target), str(source)],
            check=True,
        )
    return str(target)


def main():
    parser = argparse.ArgumentParser(description="SymFit IA/RPC symbolic-address load smoke test")
    parser.add_argument("--symfit", required=True, help="Path to symfit-x86_64")
    parser.add_argument("--fgtest", help="Path to fgtest (required if --runner=fgtest)")
    parser.add_argument("--runner", choices=["direct", "fgtest"], default="direct")
    parser.add_argument("--target", help="Optional target program path")
    parser.add_argument("--socket", default="/tmp/symfit-ia-symbolic-address-load.sock")
    parser.add_argument("--startup-timeout", type=float, default=5.0)
    parser.add_argument("--exit-timeout", type=float, default=5.0)
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    socket_path = args.socket
    target_path = args.target or ensure_target(script_dir)

    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass

    proc = None
    fgtest_tmp = None
    req_id = 1

    try:
        launch_args = argparse.Namespace(**vars(args))
        launch_args.target = target_path
        launch_args.target_args = []

        proc, fgtest_tmp = launch_backend(launch_args, socket_path)
        wait_for_socket(socket_path, args.startup_timeout)

        client, stream = connect_rpc_socket(socket_path)
        summary = {}

        summary["registers_before"] = rpc_call(stream, req_id, "get_registers", {"names": ["rax", "rbx", "rcx", "rip"]})
        req_id += 1

        summary["resume_until_basic_block_1"] = rpc_call(
            stream,
            req_id,
            "resume_until_basic_block",
            {"count": 1},
        )
        req_id += 1

        summary["registers_after_bb1"] = rpc_call(
            stream,
            req_id,
            "get_registers",
            {"names": ["rax", "rbx", "rcx", "rip"]},
        )
        req_id += 1

        data_addr = summary["registers_after_bb1"]["registers"]["rbx"]
        summary["symbolize_memory"] = rpc_call(
            stream,
            req_id,
            "symbolize_memory",
            {"address": data_addr, "size": 8, "name": "loaded_bytes"},
        )
        req_id += 1

        summary["symbolize_register"] = rpc_call(
            stream,
            req_id,
            "symbolize_register",
            {"register": "rax", "name": "addr_index"},
        )
        req_id += 1

        summary["resume_until_basic_block_2"] = rpc_call(
            stream,
            req_id,
            "resume_until_basic_block",
            {"count": 1},
        )
        req_id += 1

        summary["resume_until_basic_block_3"] = rpc_call(
            stream,
            req_id,
            "resume_until_basic_block",
            {"count": 1},
        )
        req_id += 1

        summary["registers_after"] = rpc_call(stream, req_id, "get_registers", {"names": ["rax", "rbx", "rcx", "rip"]})
        req_id += 1

        load_label = summary["registers_after"]["symbolic_registers"]["rcx"]["label"]
        summary["get_symbolic_expression"] = rpc_call(
            stream,
            req_id,
            "get_symbolic_expression",
            {"label": load_label},
        )
        req_id += 1

        try:
            summary["recent_path_constraints"] = rpc_call(
                stream,
                req_id,
                "get_recent_path_constraints",
                {"limit": 4},
            )
            req_id += 1
        except RuntimeError as exc:
            summary["recent_path_constraints_error"] = str(exc)

        summary["resume"] = rpc_call(stream, req_id, "resume")
        req_id += 1

        final_status = None
        deadline = time.time() + args.exit_timeout
        while time.time() < deadline:
            try:
                final_status = rpc_call(stream, req_id, "query_status")
                req_id += 1
            except RuntimeError:
                rc = proc.poll()
                if rc in (0, 51):
                    final_status = {"status": "exited"}
                    break
                if rc is None:
                    time.sleep(0.05)
                    rc = proc.poll()
                    if rc in (0, 51):
                        final_status = {"status": "exited"}
                        break
                if rc is not None:
                    raise RuntimeError(f"backend exited unexpectedly with status {rc}")
                raise
            if final_status.get("status") == "exited":
                break
            if (final_status.get("status") == "paused" and
                    final_status.get("pending_termination")):
                break
            time.sleep(0.05)
        summary["query_status_final"] = final_status

        print("IA/RPC symbolic-address load reproduction completed")
        print(json.dumps(summary, indent=2))

        stream.close()
        client.close()

        if summary["registers_after"]["symbolic_registers"]["rcx"]["symbolic"] is not True:
            print("Expected symbolic-address load result to remain symbolic in rcx", file=sys.stderr)
            return 1
        if summary["get_symbolic_expression"]["label"] == "0x0":
            print("Expected symbolic-address load reproduction to yield a non-zero load label", file=sys.stderr)
            return 1
        expr = summary["get_symbolic_expression"].get("expression", "")
        if "load" not in expr:
            print("Expected display-side load rendering to mention a load expression", file=sys.stderr)
            return 1
        final = summary["query_status_final"] or {}
        if not ((final.get("status") == "exited") or
                (final.get("status") == "paused" and final.get("pending_termination"))):
            print("Expected helper target to reach exited or terminal-pause state after resume", file=sys.stderr)
            return 1

        if proc.poll() not in (None, 0):
            out, err = read_process_logs(proc)
            print("backend exited non-zero", file=sys.stderr)
            print(f"exit_code={proc.returncode}", file=sys.stderr)
            print("stdout:\n" + out, file=sys.stderr)
            print("stderr:\n" + err, file=sys.stderr)
            return 1

        return 0

    except Exception as exc:
        print(f"IA/RPC symbolic-address load smoke test failed: {exc}", file=sys.stderr)
        if proc is not None:
            out, err = read_process_logs(proc)
            print(f"backend_exit={proc.returncode}", file=sys.stderr)
            print("stdout:\n" + out, file=sys.stderr)
            print("stderr:\n" + err, file=sys.stderr)
        return 1
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1.0)
        if fgtest_tmp is not None:
            fgtest_tmp.cleanup()
        try:
            os.unlink(socket_path)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
