#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import time

from ia_rpc_common import connect_rpc_socket, launch_backend, read_process_logs, rpc_call, wait_for_socket


def main():
    parser = argparse.ArgumentParser(description="SymFit IA/RPC smoke test")
    parser.add_argument("--symfit", required=True, help="Path to symfit-x86_64")
    parser.add_argument("--fgtest", help="Path to fgtest (required if --runner=fgtest)")
    parser.add_argument("--runner", choices=["direct", "fgtest"], default="direct")
    parser.add_argument("--target", default="/bin/sleep", help="Target program path")
    parser.add_argument("--socket", default="/tmp/symfit-ia-smoke.sock")
    parser.add_argument("--startup-timeout", type=float, default=5.0)
    parser.add_argument("--exit-timeout", type=float, default=5.0)
    parser.add_argument("target_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    # Make the default target live long enough for interactive run-control calls.
    if args.target == "/bin/sleep" and not args.target_args:
        args.target_args = ["2"]

    socket_path = args.socket
    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass

    proc = None
    fgtest_tmp = None
    req_id = 1

    try:
        proc, fgtest_tmp = launch_backend(args, socket_path)
        wait_for_socket(socket_path, args.startup_timeout)

        client, stream = connect_rpc_socket(socket_path)

        summary = {}

        summary["capabilities"] = rpc_call(stream, req_id, "capabilities")
        req_id += 1

        summary["query_status_initial"] = rpc_call(stream, req_id, "query_status")
        req_id += 1

        summary["start_trace"] = rpc_call(
            stream,
            req_id,
            "start_trace",
            {"basic_block": True},
        )
        req_id += 1

        regs = rpc_call(stream, req_id, "get_registers", {"names": ["rip", "rsp", "rax"]})
        req_id += 1
        summary["registers"] = regs

        rip = regs["registers"]["rip"]
        rsp = regs["registers"]["rsp"]
        summary["resume_until_address"] = rpc_call(
            stream,
            req_id,
            "resume_until_address",
            {"address": rip},
        )
        req_id += 1

        # Re-sample PC after run-control so the next command targets
        # an address that is still reachable in the current paused state.
        regs_after_run_until = rpc_call(stream, req_id, "get_registers", {"names": ["rip"]})
        req_id += 1
        rip_after_run_until = regs_after_run_until["registers"]["rip"]
        summary["registers_after_run_until_address"] = regs_after_run_until

        summary["resume_until_any_address"] = rpc_call(
            stream,
            req_id,
            "resume_until_any_address",
            {"addresses": [rip_after_run_until]},
        )
        req_id += 1

        summary["read_memory"] = rpc_call(
            stream,
            req_id,
            "read_memory",
            {"address": rip, "size": 16},
        )
        req_id += 1

        summary["read_memory_rsp_before"] = rpc_call(
            stream,
            req_id,
            "read_memory",
            {"address": rsp, "size": 8},
        )
        req_id += 1

        summary["symbolize_memory"] = rpc_call(
            stream,
            req_id,
            "symbolize_memory",
            {"address": rsp, "size": 8, "name": "stack_probe"},
        )
        req_id += 1

        rax_before = summary["registers"]["symbolic_registers"]["rax"]
        summary["symbolize_register"] = rpc_call(
            stream,
            req_id,
            "symbolize_register",
            {"register": "rax", "name": "acc_probe"},
        )
        req_id += 1

        summary["registers_after_symbolize_register"] = rpc_call(
            stream,
            req_id,
            "get_registers",
            {"names": ["rax"]},
        )
        req_id += 1

        summary["get_symbolic_expression"] = rpc_call(
            stream,
            req_id,
            "get_symbolic_expression",
            {"label": summary["symbolize_register"]["label"]},
        )
        req_id += 1

        summary["query_status_after_symbolize"] = rpc_call(stream, req_id, "query_status")
        req_id += 1

        summary["read_memory_rsp_after"] = rpc_call(
            stream,
            req_id,
            "read_memory",
            {"address": rsp, "size": 8},
        )
        req_id += 1

        summary["disassemble"] = rpc_call(
            stream,
            req_id,
            "disassemble",
            {"address": rip, "count": 3},
        )
        req_id += 1

        summary["list_memory_maps"] = rpc_call(stream, req_id, "list_memory_maps")
        req_id += 1

        summary["single_step"] = rpc_call(stream, req_id, "single_step", {"count": 1})
        req_id += 1

        summary["resume_until_basic_block"] = rpc_call(
            stream,
            req_id,
            "resume_until_basic_block",
            {"count": 1},
        )
        req_id += 1

        summary["resume"] = rpc_call(stream, req_id, "resume")
        req_id += 1

        summary["pause"] = rpc_call(stream, req_id, "pause")
        req_id += 1

        summary["query_status_after_pause"] = rpc_call(stream, req_id, "query_status")
        req_id += 1

        summary["stop_trace"] = rpc_call(stream, req_id, "stop_trace")
        req_id += 1

        summary["resume_after_pause"] = rpc_call(stream, req_id, "resume")
        req_id += 1

        deadline = time.time() + args.exit_timeout
        status = None
        while time.time() < deadline:
            try:
                status = rpc_call(stream, req_id, "query_status")
                req_id += 1
            except RuntimeError:
                # Backend may exit and close RPC socket immediately after resume.
                rc = proc.poll()
                if rc == 0:
                    status = {"status": "exited"}
                    break
                if rc is None:
                    time.sleep(0.05)
                    rc = proc.poll()
                    if rc == 0:
                        status = {"status": "exited"}
                        break
                if rc is not None:
                    raise RuntimeError(f"backend exited unexpectedly with status {rc}")
                raise
            if status.get("status") == "exited":
                break
            time.sleep(0.05)
        summary["query_status_final"] = status

        print("IA/RPC smoke test passed")
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

        if summary["query_status_final"].get("status") != "exited":
            print("Timed out waiting for exited status", file=sys.stderr)
            return 1

        rsp_reg = summary["registers"]["symbolic_registers"]["rsp"]
        if rsp_reg.get("symbolic"):
            print("Expected rsp to start concrete in symbolic view", file=sys.stderr)
            return 1

        before_bytes = summary["read_memory_rsp_before"]["symbolic_bytes"]
        after_bytes = summary["read_memory_rsp_after"]["symbolic_bytes"]
        if any(entry.get("symbolic") for entry in before_bytes):
            print("Expected stack probe bytes to start concrete", file=sys.stderr)
            return 1
        if not all(entry.get("symbolic") for entry in after_bytes):
            print("Expected stack probe bytes to become symbolic", file=sys.stderr)
            return 1

        rax_after = summary["registers_after_symbolize_register"]["symbolic_registers"]["rax"]
        if rax_before.get("symbolic"):
            print("Expected rax to start concrete in symbolic view", file=sys.stderr)
            return 1

        if not rax_after.get("symbolic"):
            print("Expected rax to become symbolic", file=sys.stderr)
            return 1
        if rax_after.get("label") == "0x0":
            print("Expected rax to receive a non-zero symbolic label", file=sys.stderr)
            return 1
        expression = summary["get_symbolic_expression"].get("expression", "")
        if not expression:
            print("Expected a non-empty symbolic expression", file=sys.stderr)
            return 1
        if summary["query_status_initial"].get("execution_mode") != "concrete":
            print("Expected initial paused state to start in concrete mode", file=sys.stderr)
            return 1
        if summary["query_status_after_symbolize"].get("execution_mode") != "symbolic":
            print("Expected symbolization to switch execution mode to symbolic", file=sys.stderr)
            return 1

        return 0

    except Exception as exc:
        print(f"IA/RPC smoke test failed: {exc}", file=sys.stderr)
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
