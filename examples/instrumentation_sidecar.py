from __future__ import annotations

import json
import os
import socket
import threading
import time
from dataclasses import dataclass, field


EVENT_SOCKET = os.environ.get("IA_EVENT_SOCKET")
RPC_SOCKET = os.environ.get("IA_RPC_SOCKET")


@dataclass
class SidecarState:
    status: str = "paused"
    pc: int = 0x401000
    rsp: int = 0x7FFFFFFFE000
    rax: int = 0x1
    seq: int = 1
    event_id: int = 1
    running: bool = True
    pause_ack_pending: bool = False
    cond: threading.Condition = field(default_factory=threading.Condition)

    def next_event_id(self) -> str:
        value = f"e-{self.event_id}"
        self.event_id += 1
        return value

    def next_seq(self) -> int:
        value = self.seq
        self.seq += 1
        return value


STATE = SidecarState()


def _bind_listener(path: str) -> socket.socket:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(1)
    return listener


def _emit_event(conn: socket.socket, event_type: str, pc: int | None, payload: dict) -> None:
    event = {
        "event_id": STATE.next_event_id(),
        "seq": STATE.next_seq(),
        "type": event_type,
        "timestamp": time.time(),
        "pc": None if pc is None else hex(pc),
        "thread_id": None if pc is None else "1",
        "cpu_id": None,
        "payload": payload,
    }
    conn.sendall((json.dumps(event) + "\n").encode("utf-8"))


def _memory_bytes(address: int, size: int) -> str:
    return "".join(f"{(address + offset) & 0xFF:02x}" for offset in range(size))


def serve_events(path: str) -> None:
    listener = _bind_listener(path)
    conn, _ = listener.accept()
    with listener, conn:
        _emit_event(conn, "backend_ready", None, {"status": "attached"})
        while STATE.running:
            with STATE.cond:
                STATE.cond.wait_for(lambda: STATE.status == "running" or not STATE.running, timeout=0.25)
                if not STATE.running:
                    break
                if STATE.pause_ack_pending and STATE.status == "paused":
                    _emit_event(conn, "execution_paused", STATE.pc, {"reason": "user"})
                    STATE.pause_ack_pending = False
                    continue
                if STATE.status != "running":
                    continue
                current_pc = STATE.pc
                target_pc = current_pc + 0x20
                _emit_event(conn, "branch", current_pc, {"target": hex(target_pc), "taken": True})
                STATE.cond.wait(timeout=0.1)
                if not STATE.running:
                    break
                if STATE.pause_ack_pending and STATE.status == "paused":
                    _emit_event(conn, "execution_paused", STATE.pc, {"reason": "user"})
                    STATE.pause_ack_pending = False
                    continue
                if STATE.status != "running":
                    continue
                STATE.pc = target_pc
                _emit_event(conn, "basic_block", STATE.pc, {"start": hex(STATE.pc), "end": hex(STATE.pc + 0x4), "instruction_count": 1})
                STATE.pc += 0x4
                STATE.rax = (STATE.rax + 1) & 0xFFFFFFFFFFFFFFFF


def serve_rpc(path: str) -> None:
    listener = _bind_listener(path)
    conn, _ = listener.accept()
    with listener, conn, conn.makefile("r", encoding="utf-8") as reader:
        for line in reader:
            request = json.loads(line)
            method = request["method"]
            request_id = request["id"]
            params = request.get("params") or {}
            if method == "resume":
                with STATE.cond:
                    STATE.status = "running"
                    STATE.cond.notify_all()
                result = {}
            elif method == "pause":
                with STATE.cond:
                    STATE.status = "paused"
                    STATE.pause_ack_pending = True
                    STATE.cond.notify_all()
                result = {}
            elif method == "query_status":
                result = {"status": STATE.status}
            elif method == "get_registers":
                registers = {
                    "rip": hex(STATE.pc),
                    "rsp": hex(STATE.rsp),
                    "rax": hex(STATE.rax),
                }
                names = params.get("names") or []
                if names:
                    registers = {name: registers[name] for name in names if name in registers}
                result = {"registers": registers}
            elif method == "read_memory":
                address = int(params["address"], 16)
                size = int(params["size"])
                result = {"address": hex(address), "size": size, "bytes": _memory_bytes(address, size)}
            elif method == "list_memory_maps":
                result = {
                    "regions": [
                        {
                            "start": "0x400000",
                            "end": "0x402000",
                            "perm": "r-x",
                            "name": "sample_target",
                        }
                    ]
                }
            else:
                response = {"id": request_id, "error": {"message": f"unsupported method: {method}"}}
                conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
                continue
            response = {"id": request_id, "result": result}
            conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
    with STATE.cond:
        STATE.running = False
        STATE.cond.notify_all()


def main() -> int:
    if not EVENT_SOCKET or not RPC_SOCKET:
        raise SystemExit("IA_EVENT_SOCKET and IA_RPC_SOCKET are required")
    event_thread = threading.Thread(target=serve_events, args=(EVENT_SOCKET,), daemon=True)
    event_thread.start()
    serve_rpc(RPC_SOCKET)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
