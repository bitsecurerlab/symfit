import pytest

from dynamiq.models import MemoryMapSnapshot, MemoryReadResult, RegisterSnapshot


def test_register_snapshot_parses_rpc_result() -> None:
    snapshot = RegisterSnapshot.from_rpc_result({"registers": {"rax": "0X1", "rip": "0x401000"}})
    assert snapshot.to_dict() == {"registers": {"rax": "0x1", "rip": "0x401000"}}


def test_memory_read_result_normalizes_payload() -> None:
    result = MemoryReadResult.from_rpc_result({"address": "0X401000", "size": 2, "bytes": "A0B1"})
    assert result.to_dict() == {"address": "0x401000", "size": 2, "bytes": "a0b1"}


def test_memory_map_snapshot_requires_regions_list() -> None:
    with pytest.raises(Exception):
        MemoryMapSnapshot.from_rpc_result({"regions": "bad"})
