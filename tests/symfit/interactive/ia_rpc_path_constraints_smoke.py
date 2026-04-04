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


def ensure_path_constraints_target(script_dir: pathlib.Path) -> str:
    cc = shutil.which("gcc") or shutil.which("clang")
    if cc is None:
        raise RuntimeError("gcc or clang is required to build path_constraints_target")

    source = script_dir / "path_constraints_target.S"
    target = script_dir / "path_constraints_target"
    if (not target.exists()) or source.stat().st_mtime_ns > target.stat().st_mtime_ns:
        subprocess.run(
            [cc, "-nostdlib", "-no-pie", "-Wl,-z,noexecstack", "-o", str(target), str(source)],
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


def rpc_request_expect_ok(stream, req_id: int, method: str, params=None):
    return rpc_call(stream, req_id, method, params)


def main():
    parser = argparse.ArgumentParser(description="SymFit IA/RPC path-constraints smoke test")
    parser.add_argument("--symfit", required=True, help="Path to symfit-x86_64")
    parser.add_argument("--fgtest", help="Path to fgtest (required if --runner=fgtest)")
    parser.add_argument("--runner", choices=["direct", "fgtest"], default="direct")
    parser.add_argument("--target", help="Optional target program path")
    parser.add_argument("--socket", default="/tmp/symfit-ia-path-constraints.sock")
    parser.add_argument("--startup-timeout", type=float, default=5.0)
    parser.add_argument("--exit-timeout", type=float, default=5.0)
    args = parser.parse_args()

    script_dir = pathlib.Path(__file__).resolve().parent
    socket_path = args.socket
    target_path = args.target or ensure_path_constraints_target(script_dir)
    data_addr = lookup_symbol(target_path, "data_byte")
    branch2_taken_addr = lookup_symbol(target_path, "branch2_taken")

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

        summary["capabilities"] = rpc_request_expect_ok(stream, req_id, "capabilities")
        req_id += 1

        summary["symbolize_memory"] = rpc_request_expect_ok(
            stream,
            req_id,
            "symbolize_memory",
            {"address": data_addr, "size": 1, "name": "path_seed"},
        )
        req_id += 1

        summary["resume_until_address"] = rpc_request_expect_ok(
            stream,
            req_id,
            "resume_until_address",
            {"address": branch2_taken_addr},
        )
        req_id += 1

        summary["registers"] = rpc_request_expect_ok(
            stream,
            req_id,
            "get_registers",
            {"names": ["rbx", "rcx", "rip"]},
        )
        req_id += 1

        summary["recent_path_constraints"] = rpc_request_expect_ok(
            stream,
            req_id,
            "get_recent_path_constraints",
            {"limit": 4},
        )
        req_id += 1

        recent = summary["recent_path_constraints"]["constraints"]
        if len(recent) < 2:
            raise RuntimeError(f"expected at least 2 recent path constraints, got {recent}")

        distinct_labels = []
        seen_labels = set()
        for entry in recent:
            label = entry["label"].lower()
            if label in seen_labels:
                continue
            seen_labels.add(label)
            distinct_labels.append(entry["label"])

        if len(distinct_labels) < 2:
            raise RuntimeError(
                f"expected at least 2 distinct recent path constraint labels, got {recent}"
            )

        newest_label = distinct_labels[0]
        older_label = distinct_labels[1]

        summary["path_constraints"] = rpc_request_expect_ok(
            stream,
            req_id,
            "get_path_constraints",
            {"label": newest_label},
        )
        req_id += 1

        summary["resume"] = rpc_request_expect_ok(stream, req_id, "resume")
        req_id += 1

        final_status = None
        deadline = time.time() + args.exit_timeout
        while time.time() < deadline:
            try:
                final_status = rpc_request_expect_ok(stream, req_id, "query_status")
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
        summary["query_status_final"] = final_status

        print("IA/RPC path-constraints smoke test passed")
        print(json.dumps(summary, indent=2))

        stream.close()
        client.close()

        rc = proc.wait(timeout=max(1.0, args.exit_timeout))
        if rc != 0:
            out, err = read_process_logs(proc)
            print("backend exited non-zero", file=sys.stderr)
            print(f"exit_code={rc}", file=sys.stderr)
            print("stdout:\n" + out, file=sys.stderr)
            print("stderr:\n" + err, file=sys.stderr)
            return 1

        if summary["capabilities"]["capabilities"].get("read_path_constraints") is not True:
            print("Expected read_path_constraints capability", file=sys.stderr)
            return 1
        if summary["resume_until_address"].get("matched") is not True:
            print("Expected branch2_taken address to be matched", file=sys.stderr)
            return 1
        if normalize_hex(summary["registers"]["registers"]["rip"]) != normalize_hex(branch2_taken_addr):
            print(
                f"Expected RIP to stop at {branch2_taken_addr}, got {summary['registers']['registers']['rip']}",
                file=sys.stderr,
            )
            return 1
        if summary["registers"]["symbolic_registers"]["rbx"]["symbolic"] is not True:
            print("Expected first branch condition register rbx to be symbolic", file=sys.stderr)
            return 1
        if summary["registers"]["symbolic_registers"]["rcx"]["symbolic"] is not True:
            print("Expected second branch condition register rcx to be symbolic", file=sys.stderr)
            return 1

        root = summary["path_constraints"]["root"]
        nested = summary["path_constraints"]["constraints"]
        if summary["recent_path_constraints"]["count"] < 2:
            print("Expected at least two recent path constraints", file=sys.stderr)
            return 1
        if root["label"].lower() != newest_label.lower():
            print("Expected root label to match newest recent path constraint", file=sys.stderr)
            return 1
        if root["op"] != "ICmp":
            print(f"Expected root path-constraint op to be ICmp, got {root['op']}", file=sys.stderr)
            return 1
        if summary["path_constraints"]["count"] < 1:
            print("Expected at least one nested path constraint", file=sys.stderr)
            return 1
        if older_label.lower() not in {entry["label"].lower() for entry in nested}:
            print(
                f"Expected nested constraints to include older path constraint {older_label}",
                file=sys.stderr,
            )
            return 1
        if summary["query_status_final"].get("status") != "exited":
            print("Expected helper target to exit after resume", file=sys.stderr)
            return 1

        return 0

    except Exception as exc:
        print(f"IA/RPC path-constraints smoke test failed: {exc}", file=sys.stderr)
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
