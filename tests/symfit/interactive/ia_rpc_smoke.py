#!/usr/bin/env python3
import argparse
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time


def wait_for_socket(path: str, timeout_s: float) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if os.path.exists(path):
            try:
                st = os.stat(path)
                if stat_is_socket(st.st_mode):
                    return
            except FileNotFoundError:
                pass
        time.sleep(0.05)
    raise TimeoutError(f"RPC socket was not ready in {timeout_s:.1f}s: {path}")


def stat_is_socket(mode: int) -> bool:
    # Avoid importing stat just for one check.
    return (mode & 0o170000) == 0o140000


def rpc_call(stream, req_id: int, method: str, params=None):
    request = {"id": req_id, "method": method}
    if params is not None:
        request["params"] = params
    try:
        stream.write((json.dumps(request) + "\n").encode())
        stream.flush()
    except BrokenPipeError as exc:
        raise RuntimeError(f"Broken pipe while sending method '{method}'") from exc

    line = stream.readline()
    if not line:
        raise RuntimeError(f"No response for method '{method}'")
    resp = json.loads(line.decode())
    if not resp.get("ok", False):
        raise RuntimeError(f"RPC error for '{method}': {resp.get('error')}")
    return resp["result"]


def make_fgtest_env(base_env, target: str):
    env = dict(base_env)
    tmpdir = tempfile.TemporaryDirectory(prefix="symfit-ia-smoke-")
    tpath = pathlib.Path(tmpdir.name)
    in_file = tpath / "seed"
    out_dir = tpath / "out"
    cov_map = tpath / "cov"
    in_file.write_bytes(b"A")
    out_dir.mkdir(parents=True, exist_ok=True)

    env["SYMCC_INPUT_FILE"] = str(in_file)
    env["SYMCC_OUTPUT_DIR"] = str(out_dir)
    env["SYMCC_AFL_COVERAGE_MAP"] = str(cov_map)
    env["TAINT_OPTIONS"] = f"taint_file={in_file}"
    return env, tmpdir


def launch_backend(args, socket_path: str):
    env = dict(os.environ)
    env["IA_RPC_SOCKET"] = socket_path

    fgtest_tmp = None
    if args.runner == "fgtest":
        if not args.fgtest:
            raise ValueError("--fgtest is required when --runner=fgtest")
        probe = subprocess.run(
            [args.fgtest],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        probe_text = (probe.stdout or "") + (probe.stderr or "")
        if "Usage:" in probe_text and "target input" in probe_text:
            raise RuntimeError(
                "This fgtest build expects 'fgtest target input' and does not "
                "support wrapping SymFit as 'fgtest <symfit> <target>'. "
                "Use --runner=direct for IA/RPC smoke tests."
            )
        env, fgtest_tmp = make_fgtest_env(env, args.target)
        cmd = [args.fgtest, args.symfit, args.target] + args.target_args
    else:
        cmd = [args.symfit, args.target] + args.target_args

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        text=True,
    )
    return proc, fgtest_tmp


def read_process_logs(proc: subprocess.Popen):
    try:
        out, err = proc.communicate(timeout=1.0)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate(timeout=1.0)
    return out, err


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

        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(socket_path)
        stream = client.makefile("rwb", buffering=0)

        summary = {}

        summary["capabilities"] = rpc_call(stream, req_id, "capabilities")
        req_id += 1

        summary["query_status_initial"] = rpc_call(stream, req_id, "query_status")
        req_id += 1

        regs = rpc_call(stream, req_id, "get_registers", {"names": ["rip", "rsp", "rax"]})
        req_id += 1
        summary["registers"] = regs

        rip = regs["registers"]["rip"]
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

        deadline = time.time() + args.exit_timeout
        status = None
        while time.time() < deadline:
            try:
                status = rpc_call(stream, req_id, "query_status")
                req_id += 1
            except RuntimeError:
                # Backend may exit and close RPC socket immediately after resume.
                if proc.poll() == 0:
                    status = {"status": "exited"}
                    break
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
