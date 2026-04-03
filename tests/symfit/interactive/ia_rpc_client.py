#!/usr/bin/env python3
import argparse
import json
import os
import sys
from ia_rpc_common import connect_rpc_socket, launch_backend, read_process_logs, rpc_call, wait_for_socket


def parse_args():
    parser = argparse.ArgumentParser(description="Reference IA/RPC client for SymFit")
    parser.add_argument("--socket", help="Path to an existing IA/RPC Unix socket")
    parser.add_argument("--startup-timeout", type=float, default=5.0)
    parser.add_argument("--method", help="RPC method to invoke")
    parser.add_argument(
        "--params-json",
        help="JSON object for method params, for example '{\"names\": [\"rip\", \"rax\"]}'",
    )
    parser.add_argument(
        "--sequence-json",
        help="JSON array of calls, for example "
             "'[{\"method\":\"capabilities\"},{\"method\":\"query_status\"}]'",
    )
    parser.add_argument("--pretty", action="store_true", help="Pretty-print the JSON result")

    parser.add_argument("--spawn", action="store_true", help="Spawn SymFit before invoking the method")
    parser.add_argument("--symfit", help="Path to symfit-x86_64 when using --spawn")
    parser.add_argument("--fgtest", help="Path to fgtest when using --runner=fgtest")
    parser.add_argument("--runner", choices=["direct", "fgtest"], default="direct")
    parser.add_argument("--target", default="/bin/sleep", help="Target program path for --spawn")
    parser.add_argument("--trace-file", help="Optional IA_TRACE_FILE path when using --spawn")
    parser.add_argument("target_args", nargs=argparse.REMAINDER)
    return parser.parse_args()


def parse_call_sequence(args):
    if args.sequence_json:
        if args.method or args.params_json:
            raise SystemExit("--sequence-json cannot be combined with --method or --params-json")
        try:
            sequence = json.loads(args.sequence_json)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Invalid --sequence-json: {exc}") from exc
        if not isinstance(sequence, list) or not sequence:
            raise SystemExit("--sequence-json must be a non-empty JSON array")

        parsed = []
        for index, item in enumerate(sequence, start=1):
            if not isinstance(item, dict):
                raise SystemExit(f"Sequence item {index} must be an object")
            method = item.get("method")
            params = item.get("params")
            if not isinstance(method, str) or not method:
                raise SystemExit(f"Sequence item {index} is missing a valid 'method'")
            parsed.append({"method": method, "params": params})
        return parsed

    if not args.method:
        raise SystemExit("Either --method or --sequence-json is required")

    params = None
    if args.params_json:
        try:
            params = json.loads(args.params_json)
        except json.JSONDecodeError as exc:
            raise SystemExit(f"Invalid --params-json: {exc}") from exc
    return [{"method": args.method, "params": params}]


def main():
    args = parse_args()
    calls = parse_call_sequence(args)

    if args.spawn:
        if not args.symfit:
            raise SystemExit("--symfit is required with --spawn")
        socket_path = args.socket or f"/tmp/symfit-ia-client-{os.getpid()}.sock"
    else:
        if not args.socket:
            raise SystemExit("--socket is required unless --spawn is used")
        socket_path = args.socket

    proc = None
    fgtest_tmp = None
    client = None
    stream = None

    try:
        if args.spawn:
            try:
                os.unlink(socket_path)
            except FileNotFoundError:
                pass
            proc, fgtest_tmp = launch_backend(args, socket_path)
            wait_for_socket(socket_path, args.startup_timeout)

        client, stream = connect_rpc_socket(socket_path)

        results = []
        for request_id, call in enumerate(calls, start=1):
            results.append({
                "method": call["method"],
                "result": rpc_call(stream, request_id, call["method"], call["params"]),
            })
        result = results[0]["result"] if len(results) == 1 else results
        if args.pretty:
            print(json.dumps(result, indent=2))
        else:
            print(json.dumps(result))

        return 0
    except Exception as exc:
        print(f"IA/RPC client failed: {exc}", file=sys.stderr)
        if proc is not None:
            stdout, stderr = read_process_logs(proc)
            print(f"backend_exit={proc.returncode}", file=sys.stderr)
            if stdout:
                print("stdout:\n" + stdout, file=sys.stderr)
            if stderr:
                print("stderr:\n" + stderr, file=sys.stderr)
        return 1
    finally:
        if stream is not None:
            stream.close()
        if client is not None:
            client.close()
        if fgtest_tmp is not None:
            fgtest_tmp.cleanup()
        if args.spawn and proc is not None and proc.poll() is None:
            read_process_logs(proc)
        if args.spawn:
            try:
                os.unlink(socket_path)
            except FileNotFoundError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
