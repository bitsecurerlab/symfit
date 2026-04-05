#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import subprocess
import sys
import time

from ia_rpc_common import connect_rpc_socket, read_process_logs, rpc_call, wait_for_socket


def encode_int(n: int) -> bytes:
    if n < 0:
        n = -n
        sign_bit = 0x40
    else:
        sign_bit = 0
    if n < 64:
        return bytes([n | sign_bit])
    out = []
    while n > 0:
        byte = n & 0x7F
        n >>= 7
        if n > 0:
            out.append(byte | 0x80)
        else:
            out.append(byte | sign_bit)
    return bytes(out)


def main():
    parser = argparse.ArgumentParser(description="SymFit IA/RPC anagram_game smoke test")
    parser.add_argument("--symfit", required=True, help="Path to symfit-i386")
    parser.add_argument("--target", default="/home/heng/work2/anagram_game",
                        help="Path to anagram_game")
    parser.add_argument("--socket", default="/tmp/symfit-ia-anagram.sock")
    parser.add_argument("--startup-timeout", type=float, default=5.0)
    parser.add_argument("--run-timeout", type=float, default=10.0)
    args = parser.parse_args()

    socket_path = args.socket
    target_path = pathlib.Path(args.target)
    if not target_path.exists():
      print(f"missing target: {target_path}", file=sys.stderr)
      return 1

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
            [args.symfit, str(target_path)],
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

        summary["resume_menu"] = rpc_call(stream, req_id, "resume")
        req_id += 1

        if proc.stdin is None:
            raise RuntimeError("child stdin pipe is unavailable")

        proc.stdin.write(encode_int(0))
        proc.stdin.flush()
        summary["resume_skip"] = rpc_call(stream, req_id, "resume")
        req_id += 1

        proc.stdin.write(encode_int(1))
        proc.stdin.flush()
        summary["resume_choice"] = rpc_call(stream, req_id, "resume")
        req_id += 1

        word_payload = encode_int(4) + b"AAAA"
        summary["queue_symbolic"] = rpc_call(
            stream,
            req_id,
            "queue_stdin_chunk",
            {"size": len(word_payload), "symbolic": True},
        )
        req_id += 1

        proc.stdin.write(word_payload)
        proc.stdin.flush()
        summary["resume_word"] = rpc_call(stream, req_id, "resume")
        req_id += 1

        deadline = time.time() + args.run_timeout
        status_after_run = None
        while time.time() < deadline:
            status_after_run = rpc_call(stream, req_id, "query_status")
            req_id += 1
            if status_after_run.get("status") != "running":
                break
            time.sleep(0.05)
        summary["status_after_run"] = status_after_run

        summary["recent_path_constraints"] = rpc_call(
            stream,
            req_id,
            "get_recent_path_constraints",
            {"limit": 10},
        )
        req_id += 1

        print("IA/RPC anagram smoke test passed")
        print(json.dumps(summary, indent=2))

        stream.close()
        client.close()
        if summary["recent_path_constraints"].get("count", 0) < 1:
            print("expected at least one recent path constraint", file=sys.stderr)
            return 1
        if summary["status_after_run"].get("status") != "paused":
            print("expected backend to be paused after run", file=sys.stderr)
            return 1

        if proc.poll() is None:
            proc.terminate()
        out, err = read_process_logs(proc)
        stderr_text = err.decode(errors="replace")
        if "FATAL: Exhausted labels" in stderr_text:
            print("unexpected label exhaustion", file=sys.stderr)
            print(stderr_text, file=sys.stderr)
            return 1
        if "index out of bounds" in stderr_text:
            print("unexpected Z3 index-out-of-bounds warning", file=sys.stderr)
            print(stderr_text, file=sys.stderr)
            return 1
        return 0

    except Exception as exc:
        print(f"IA/RPC anagram smoke test failed: {exc}", file=sys.stderr)
        if proc is not None:
            out, err = read_process_logs(proc)
            print(f"backend_exit={proc.returncode}", file=sys.stderr)
            print("stdout:\n" + out.decode(errors="replace"), file=sys.stderr)
            print("stderr:\n" + err.decode(errors="replace"), file=sys.stderr)
        return 1
    finally:
        if proc is not None and proc.poll() is None:
            try:
                proc.terminate()
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
