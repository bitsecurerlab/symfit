#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys
import time

from ia_rpc_common import connect_rpc_socket, launch_backend, read_process_logs, rpc_call, wait_for_socket


def main():
    parser = argparse.ArgumentParser(description="SymFit IA/RPC trace smoke test")
    parser.add_argument("--symfit", required=True, help="Path to symfit-x86_64")
    parser.add_argument("--fgtest", help="Path to fgtest (required if --runner=fgtest)")
    parser.add_argument("--runner", choices=["direct", "fgtest"], default="direct")
    parser.add_argument("--target", default="/bin/sleep", help="Target program path")
    parser.add_argument("--socket", default="/tmp/symfit-ia-trace-smoke.sock")
    parser.add_argument("--startup-timeout", type=float, default=5.0)
    parser.add_argument("--trace-wait-ms", type=int, default=200)
    parser.add_argument("target_args", nargs=argparse.REMAINDER)
    args = parser.parse_args()

    if args.target == "/bin/sleep" and not args.target_args:
        args.target_args = ["2"]

    socket_path = args.socket
    try:
        os.unlink(socket_path)
    except FileNotFoundError:
        pass

    proc = None
    fgtest_tmp = None
    client = None
    stream = None

    try:
        proc, fgtest_tmp = launch_backend(args, socket_path)
        wait_for_socket(socket_path, args.startup_timeout)
        client, stream = connect_rpc_socket(socket_path)

        summary = {}
        req_id = 1

        summary["capabilities"] = rpc_call(stream, req_id, "capabilities")
        req_id += 1

        summary["query_status_initial"] = rpc_call(stream, req_id, "query_status")
        req_id += 1

        start_trace = rpc_call(stream, req_id, "start_trace", {"basic_block": True})
        req_id += 1
        summary["start_trace"] = start_trace

        trace_file = start_trace.get("trace_file")
        if not trace_file:
            print("start_trace did not return trace_file", file=sys.stderr)
            return 1

        summary["resume"] = rpc_call(stream, req_id, "resume")
        req_id += 1

        time.sleep(args.trace_wait_ms / 1000.0)

        summary["pause"] = rpc_call(stream, req_id, "pause")
        req_id += 1

        summary["query_status_after_pause"] = rpc_call(stream, req_id, "query_status")
        req_id += 1

        stop_trace = rpc_call(stream, req_id, "stop_trace")
        req_id += 1
        summary["stop_trace"] = stop_trace

        stop_trace_file = stop_trace.get("trace_file")
        if stop_trace_file != trace_file:
            print("trace_file changed between start_trace and stop_trace", file=sys.stderr)
            return 1

        if not os.path.exists(trace_file):
            print(f"trace artifact not found: {trace_file}", file=sys.stderr)
            return 1

        trace_size = os.path.getsize(trace_file)
        if trace_size <= 0:
            print(f"trace artifact is empty: {trace_file}", file=sys.stderr)
            return 1

        with open(trace_file, "r", encoding="utf-8") as f:
            lines = [line.rstrip("\n") for line in f if line.strip()]
        if not lines:
            print(f"trace artifact has no events: {trace_file}", file=sys.stderr)
            return 1

        summary["trace_artifact"] = {
            "path": trace_file,
            "size": trace_size,
            "events": len(lines),
            "first_line": json.loads(lines[0]),
        }

        print("IA/RPC trace smoke test passed")
        print(json.dumps(summary, indent=2))
        return 0

    except Exception as exc:
        print(f"IA/RPC trace smoke test failed: {exc}", file=sys.stderr)
        if proc is not None:
            out, err = read_process_logs(proc)
            print(f"backend_exit={proc.returncode}", file=sys.stderr)
            print("stdout:\n" + out, file=sys.stderr)
            print("stderr:\n" + err, file=sys.stderr)
        return 1
    finally:
        if stream is not None:
            stream.close()
        if client is not None:
            client.close()
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
