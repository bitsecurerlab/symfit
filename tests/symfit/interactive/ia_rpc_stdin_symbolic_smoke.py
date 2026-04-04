#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

from ia_rpc_common import connect_rpc_socket, read_process_logs, rpc_call, wait_for_socket


def ensure_target(script_dir: pathlib.Path) -> str:
    cc = shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        raise RuntimeError("gcc or clang is required to build stdin_symbolic_target")

    source = script_dir / "stdin_symbolic_target.c"
    target = script_dir / "stdin_symbolic_target"
    if (not target.exists()) or source.stat().st_mtime_ns > target.stat().st_mtime_ns:
        subprocess.run(
            [cc, "-g", "-O0", "-fno-pie", "-no-pie", "-o", str(target), str(source)],
            check=True,
        )
    return str(target)


def lookup_symbol(target_path: str, symbol: str) -> str:
    proc = subprocess.run(
        ["nm", "-n", target_path],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == symbol:
            return "0x" + parts[0].lower()
    raise RuntimeError(f"symbol not found: {symbol}")


def normalize_hex(value: str) -> str:
    return f"0x{int(value, 16):x}"


def main():
    parser = argparse.ArgumentParser(description="SymFit IA/RPC symbolic stdin smoke test")
    parser.add_argument("--symfit", required=True, help="Path to symfit-x86_64")
    parser.add_argument("--target", help="Optional target program path")
    parser.add_argument("--socket", default="/tmp/symfit-ia-stdin.sock")
    parser.add_argument("--startup-timeout", type=float, default=5.0)
    parser.add_argument("--exit-timeout", type=float, default=5.0)
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    socket_path = args.socket
    target_path = args.target or ensure_target(script_dir)
    buffer_addr = lookup_symbol(target_path, "stdin_buffer")
    after_read_addr = lookup_symbol(target_path, "after_read_label")

    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass

    proc = None
    req_id = 1

    try:
        env = dict(os.environ)
        env["IA_RPC_SOCKET"] = socket_path
        proc = subprocess.Popen(
            [args.symfit, target_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            text=False,
        )
        wait_for_socket(socket_path, args.startup_timeout)

        client, stream = connect_rpc_socket(socket_path)
        summary = {}

        summary["capabilities"] = rpc_call(stream, req_id, "capabilities")
        req_id += 1

        summary["status_initial"] = rpc_call(stream, req_id, "query_status")
        req_id += 1

        summary["queue_concrete"] = rpc_call(
            stream,
            req_id,
            "queue_stdin_chunk",
            {"size": 2, "symbolic": False},
        )
        req_id += 1

        summary["queue_symbolic"] = rpc_call(
            stream,
            req_id,
            "queue_stdin_chunk",
            {"size": 3, "symbolic": True},
        )
        req_id += 1

        if proc.stdin is None:
            raise RuntimeError("child stdin pipe is unavailable")
        proc.stdin.write(b"hello")
        proc.stdin.flush()
        proc.stdin.close()

        summary["resume_until_address"] = rpc_call(
            stream,
            req_id,
            "resume_until_address",
            {"address": after_read_addr},
        )
        req_id += 1

        summary["status_after_read"] = rpc_call(stream, req_id, "query_status")
        req_id += 1

        summary["memory"] = rpc_call(
            stream,
            req_id,
            "read_memory",
            {"address": buffer_addr, "size": 5},
        )
        req_id += 1

        symbolic_bytes = summary["memory"]["symbolic_bytes"]
        symbolic_labels = [entry["label"] for entry in symbolic_bytes if entry["symbolic"]]
        if len(symbolic_labels) != 3:
            raise RuntimeError(f"expected 3 symbolic bytes, got {symbolic_bytes}")

        summary["expr_first_symbolic"] = rpc_call(
            stream,
            req_id,
            "get_symbolic_expression",
            {"label": symbolic_labels[0]},
        )
        req_id += 1

        summary["expr_last_symbolic"] = rpc_call(
            stream,
            req_id,
            "get_symbolic_expression",
            {"label": symbolic_labels[-1]},
        )
        req_id += 1

        summary["resume"] = rpc_call(stream, req_id, "resume")
        req_id += 1

        deadline = time.time() + args.exit_timeout
        final_status = None
        while time.time() < deadline:
            try:
                final_status = rpc_call(stream, req_id, "query_status")
                req_id += 1
            except RuntimeError:
                rc = proc.poll()
                if rc == 0:
                    final_status = {"status": "exited"}
                    break
                if rc is None:
                    time.sleep(0.05)
                    continue
                raise RuntimeError(f"backend exited unexpectedly with status {rc}")
            if final_status.get("status") == "exited":
                break
            time.sleep(0.05)
        summary["status_final"] = final_status

        print("IA/RPC symbolic stdin smoke test passed")
        print(json.dumps(summary, indent=2))

        stream.close()
        client.close()

        rc = proc.wait(timeout=max(1.0, args.exit_timeout))
        if rc != 0:
            out, err = read_process_logs(proc)
            print("backend exited non-zero", file=sys.stderr)
            print(f"exit_code={rc}", file=sys.stderr)
            print("stdout:\n" + out.decode(errors="replace"), file=sys.stderr)
            print("stderr:\n" + err.decode(errors="replace"), file=sys.stderr)
            return 1

        if summary["capabilities"]["capabilities"].get("queue_stdin_chunk") is not True:
            print("Expected queue_stdin_chunk capability", file=sys.stderr)
            return 1
        if summary["status_initial"].get("pending_stdin_bytes") != 0:
            print("Expected no pending stdin bytes initially", file=sys.stderr)
            return 1
        if summary["queue_concrete"].get("pending_stdin_bytes") != 2:
            print("Expected 2 pending stdin bytes after concrete queue", file=sys.stderr)
            return 1
        if summary["queue_symbolic"].get("pending_stdin_bytes") != 5:
            print("Expected 5 pending stdin bytes after symbolic queue", file=sys.stderr)
            return 1
        if summary["queue_symbolic"].get("pending_symbolic_stdin_bytes") != 3:
            print("Expected 3 pending symbolic stdin bytes after symbolic queue", file=sys.stderr)
            return 1
        if summary["queue_symbolic"].get("stream_offset") != "0x0":
            print("Expected first symbolic chunk to start at stream offset 0x0", file=sys.stderr)
            return 1
        if summary["resume_until_address"].get("matched") is not True:
            print("Expected after_read address to be matched", file=sys.stderr)
            return 1
        if summary["status_after_read"].get("pending_stdin_bytes") != 0:
            print("Expected all queued stdin bytes to be consumed", file=sys.stderr)
            return 1
        if summary["status_after_read"].get("pending_symbolic_stdin_bytes") != 0:
            print("Expected all queued symbolic stdin bytes to be consumed", file=sys.stderr)
            return 1
        if normalize_hex(summary["memory"]["address"]) != normalize_hex(buffer_addr):
            print("Expected read_memory to target stdin_buffer", file=sys.stderr)
            return 1
        if summary["memory"]["bytes"] != "68656c6c6f":
            print(f"Expected stdin_buffer to contain 'hello', got {summary['memory']['bytes']}", file=sys.stderr)
            return 1

        for index in (0, 1):
            if symbolic_bytes[index]["symbolic"]:
                print("Expected concrete stdin prefix bytes to remain concrete", file=sys.stderr)
                return 1
        for index in (2, 3, 4):
            if not symbolic_bytes[index]["symbolic"]:
                print("Expected symbolic stdin suffix bytes to become symbolic", file=sys.stderr)
                return 1
            if symbolic_bytes[index]["label"] == "0x0":
                print("Expected symbolic stdin suffix bytes to have non-zero labels", file=sys.stderr)
                return 1

        if "input(0)" not in summary["expr_first_symbolic"]["expression"]:
            print("Expected first symbolic stdin byte to use input(0)", file=sys.stderr)
            return 1
        if "input(2)" not in summary["expr_last_symbolic"]["expression"]:
            print("Expected last symbolic stdin byte to use input(2)", file=sys.stderr)
            return 1
        if summary["status_final"].get("status") != "exited":
            print("Expected helper target to exit after resume", file=sys.stderr)
            return 1

        return 0

    except Exception as exc:
        print(f"IA/RPC symbolic stdin smoke test failed: {exc}", file=sys.stderr)
        if proc is not None:
            out, err = read_process_logs(proc)
            print(f"backend_exit={proc.returncode}", file=sys.stderr)
            print("stdout:\n" + out.decode(errors="replace"), file=sys.stderr)
            print("stderr:\n" + err.decode(errors="replace"), file=sys.stderr)
        return 1
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=1.0)
        try:
            os.unlink(socket_path)
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
