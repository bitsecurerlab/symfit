from __future__ import annotations

import pytest

from dynamiq.errors import InvalidStateError
from dynamiq.session import AnalysisSession, SessionConfig


class MemorySearchBackend:
    def __init__(self, base: int, data: bytes) -> None:
        self.base = base
        self.data = data
        self.reads: list[tuple[str, int]] = []

    def read_memory(self, address, size):  # noqa: ANN001
        self.reads.append((address, size))
        start = int(address, 0) - self.base
        if start < 0 or start >= len(self.data):
            raise RuntimeError("unmapped")
        chunk = self.data[start : start + size]
        return {"state": {}, "result": {"address": address, "size": len(chunk), "bytes": chunk.hex()}}

    def list_memory_maps(self):
        return {
            "state": {},
            "result": {
                "maps": {
                    "regions": [
                        {
                            "start": hex(self.base),
                            "end": hex(self.base + len(self.data)),
                            "perm": "rw-",
                            "path": "[heap]",
                        },
                        {
                            "start": hex(self.base + 0x1000),
                            "end": hex(self.base + 0x1100),
                            "perm": "---",
                            "path": None,
                        },
                    ]
                }
            },
        }

    def get_state(self):
        return {}

    def capabilities(self):
        return {"read_memory": True, "list_memory_maps": True}


def test_mem_search_finds_matches_across_chunk_boundaries() -> None:
    backend = MemorySearchBackend(0x4000, b"aaaJP2!bbbbJP2!cccc")
    session = AnalysisSession(backend=backend, config=SessionConfig(max_memory_read=5))

    result = session.mem_search(b"JP2!", start="0x4000", end="0x4012", chunk_size=5)

    assert result["result"]["matches"] == ["0x4003", "0x400b"]
    assert result["result"]["count"] == 2
    assert result["result"]["truncated"] is False
    assert backend.reads[0] == ("0x4000", 5)


def test_mem_search_uses_readable_maps_when_range_is_omitted() -> None:
    backend = MemorySearchBackend(0x7000, b"\x00\x00\x00\x0cjP  tail")
    session = AnalysisSession(backend=backend, config=SessionConfig(max_memory_read=8))

    result = session.mem_search(b"\x00\x00\x00\x0cjP  ")

    assert result["result"]["matches"] == ["0x7000"]
    assert result["result"]["ranges_scanned"] == 1


def test_mem_search_enforces_chunk_size_limit() -> None:
    backend = MemorySearchBackend(0x4000, b"abcdef")
    session = AnalysisSession(backend=backend, config=SessionConfig(max_memory_read=4))

    with pytest.raises(InvalidStateError, match="chunk size"):
        session.mem_search(b"abcde", start="0x4000", end="0x4006")

