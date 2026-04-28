from __future__ import annotations

import json
import sys
import time


def qmp_main() -> int:
    sys.stdout.write('{"QMP":{"version":{"qemu":{"major":8}}}}\n')
    sys.stdout.flush()
    for line in sys.stdin:
        message = json.loads(line)
        command = message["execute"]
        if command == "qmp_capabilities":
            response = {"return": {}}
        elif command == "query-status":
            response = {"return": {"status": "paused"}}
        else:
            response = {"return": {}}
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()
    return 0


def rpc_main() -> int:
    for line in sys.stdin:
        message = json.loads(line)
        request_id = message["id"]
        method = message["method"]
        params = message.get("params") or {}
        if method == "resume":
            result = {}
        elif method == "capabilities":
            result = {
                "protocol_version": 1,
                "capabilities": {
                    "pause_resume": True,
                    "read_registers": True,
                    "read_memory": True,
                    "disassemble": True,
                    "list_memory_maps": True,
                    "take_snapshot": False,
                    "restore_snapshot": False,
                    "trace_basic_block": False,
                    "trace_branch": False,
                    "trace_memory": False,
                    "trace_syscall": False,
                    "run_until_address": True,
                    "single_step": True,
                },
            }
        elif method == "single_step":
            result = {
                "status": "paused",
                "count": params["count"],
                "executed": params["count"],
                "pc": "0x401004",
            }
        elif method == "resume_until_address":
            result = {
                "status": "paused",
                "pc": params["address"],
                "matched": True,
                "matched_pc": params["address"],
            }
        elif method == "resume_until_any_address":
            matched = params["addresses"][0]
            result = {
                "status": "paused",
                "pc": matched,
                "matched": True,
                "matched_pc": matched,
            }
        elif method == "pause":
            result = {}
        elif method == "query_status":
            result = {"status": "paused"}
        elif method == "get_registers":
            result = {"registers": {"rax": "0x1", "rip": "0x401000"}}
        elif method == "read_memory":
            result = {"address": params["address"], "size": params["size"], "bytes": "0102"}
        elif method == "list_memory_maps":
            result = {"regions": [{"start": "0x400000", "end": "0x401000", "perm": "r-x"}]}
        else:
            result = {"error": {"message": f"unknown method: {method}"}}
        if "error" in result:
            response = {"id": request_id, "error": result["error"]}
        else:
            response = {"id": request_id, "result": result}
        sys.stdout.write(json.dumps(response) + "\n")
        sys.stdout.flush()
    return 0


def events_main() -> int:
    events = [
        {
            "event_id": "e-1",
            "seq": 1,
            "type": "backend_ready",
            "timestamp": 0.5,
            "pc": None,
            "thread_id": None,
            "cpu_id": None,
            "payload": {"status": "attached"},
        },
        {
            "event_id": "e-pause-1",
            "seq": 2,
            "type": "execution_paused",
            "timestamp": 0.75,
            "pc": None,
            "thread_id": None,
            "cpu_id": None,
            "payload": {"reason": "user"},
        },
        {
            "event_id": "e-2",
            "seq": 3,
            "type": "branch",
            "timestamp": 1.0,
            "pc": "0x401000",
            "thread_id": "1",
            "cpu_id": 0,
            "payload": {"target": "0x401010", "taken": True},
        },
        {
            "event_id": "e-pause-2",
            "seq": 4,
            "type": "execution_paused",
            "timestamp": 1.5,
            "pc": "0x401000",
            "thread_id": "1",
            "cpu_id": 0,
            "payload": {"reason": "user"},
        },
        {
            "event_id": "e-3",
            "seq": 5,
            "type": "basic_block",
            "timestamp": 2.0,
            "pc": "0x401020",
            "thread_id": "1",
            "cpu_id": 0,
            "payload": {"start": "0x401020", "end": "0x401024", "instruction_count": 1},
        },
    ]
    for event in events:
        sys.stdout.write(json.dumps(event) + "\n")
        sys.stdout.flush()
        time.sleep(0.02)
    return 0


def main() -> int:
    mode = sys.argv[1]
    if mode == "qmp":
        return qmp_main()
    if mode == "rpc":
        return rpc_main()
    if mode == "events":
        return events_main()
    raise SystemExit(f"unknown mode: {mode}")


if __name__ == "__main__":
    raise SystemExit(main())
