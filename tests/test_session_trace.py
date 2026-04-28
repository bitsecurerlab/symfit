from __future__ import annotations

from dynamiq.session import AnalysisSession


class FakeTraceBackend:
    def __init__(self) -> None:
        self.trace_entries = [
            {"index": 0, "event_id": "e-0", "type": "backend_ready"},
            {"index": 1, "event_id": "e-1", "type": "branch"},
            {"index": 2, "event_id": "e-2", "type": "basic_block"},
            {"index": 3, "event_id": "e-3", "type": "branch"},
        ]

    def start(self, target, args, cwd, qemu_config=None):  # noqa: ANN001
        del target, args, cwd, qemu_config

    def resume(self, timeout):  # noqa: ANN001
        del timeout
        return {"state": {"session_status": "running"}, "result": {}}

    def pause(self, timeout):  # noqa: ANN001
        del timeout
        return {"state": {"session_status": "paused"}, "result": {}}

    def run_until_event(self, event_types, timeout):  # noqa: ANN001
        del event_types, timeout
        return {"state": {}, "result": {}}

    def run_until_address(self, address, timeout):  # noqa: ANN001
        del address, timeout
        return {"state": {}, "result": {}}

    def step(self, count, timeout):  # noqa: ANN001
        del count, timeout
        return {"state": {}, "result": {}}

    def advance_basic_blocks(self, count, timeout):  # noqa: ANN001
        del count, timeout
        return {"state": {}, "result": {}}

    def write_stdin(self, data):  # noqa: ANN001
        del data
        return {"state": {}, "result": {"written": 0}}

    def read_stdout(self, cursor=0, max_chars=4096):  # noqa: ANN001
        del cursor, max_chars
        return {"state": {}, "result": {"data": "", "cursor": 0, "eof": False}}

    def read_stderr(self, cursor=0, max_chars=4096):  # noqa: ANN001
        del cursor, max_chars
        return {"state": {}, "result": {"data": "", "cursor": 0, "eof": False}}

    def get_registers(self, names=None):  # noqa: ANN001
        del names
        return {"state": {}, "result": {"registers": {"rip": "0x401000"}}}

    def read_memory(self, address, size):  # noqa: ANN001
        del address, size
        return {"state": {}, "result": {"bytes": ""}}

    def disassemble(self, address, count):  # noqa: ANN001
        del address, count
        return {"state": {}, "result": {"instructions": []}}

    def list_memory_maps(self):
        return {"state": {}, "result": {"maps": {"regions": []}}}

    def take_snapshot(self, name=None):  # noqa: ANN001
        del name
        return {"state": {}, "result": {}}

    def restore_snapshot(self, snapshot_id):  # noqa: ANN001
        del snapshot_id
        return {"state": {}, "result": {}}

    def diff_snapshots(self, left_id, right_id):  # noqa: ANN001
        del left_id, right_id
        return {"state": {}, "result": {}}

    def get_recent_events(self, limit=100, event_types=None):  # noqa: ANN001
        del limit, event_types
        return {"state": {}, "result": {"events": []}}

    def get_trace(self, limit):  # noqa: ANN001
        return {"state": {"trace_head": len(self.trace_entries)}, "result": {"trace": self.trace_entries[-limit:]}}

    def configure_event_filters(self, event_types=None, address_ranges=None):  # noqa: ANN001
        return {
            "state": {},
            "result": {
                "filters": {
                    "event_types": list(event_types or []),
                    "address_ranges": list(address_ranges or []),
                }
            },
        }

    def get_state(self):
        return {"session_status": "paused", "capabilities": self.capabilities(), "trace_head": len(self.trace_entries)}

    def capabilities(self):
        return {
            "pause_resume": True,
            "read_registers": True,
            "read_memory": True,
            "disassemble": True,
            "list_memory_maps": True,
            "take_snapshot": False,
            "restore_snapshot": False,
            "trace_basic_block": True,
            "trace_branch": True,
            "trace_memory": True,
            "trace_syscall": True,
            "run_until_address": True,
            "single_step": True,
        }

    def close(self):
        return None


def test_session_trace_start_and_get_since_start() -> None:
    session = AnalysisSession(backend=FakeTraceBackend())
    session.start(target="/tmp/a.out")

    started = session.trace_start(event_types=["branch"])
    assert started["result"]["trace_active"] is True
    assert started["result"]["filters"]["event_types"] == ["branch"]

    trace = session.trace_get(limit=10, since_start=True)
    assert trace["result"]["since_start"] is True
    assert trace["result"]["trace"] == []


def test_session_trace_get_without_since_start_returns_tail() -> None:
    session = AnalysisSession(backend=FakeTraceBackend())
    session.start(target="/tmp/a.out")

    trace = session.trace_get(limit=2, since_start=False)
    assert [item["event_id"] for item in trace["result"]["trace"]] == ["e-2", "e-3"]

