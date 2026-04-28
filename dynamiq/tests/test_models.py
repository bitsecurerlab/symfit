from dynamiq.events import Event, EventType


def test_event_normalizes_hex_addresses() -> None:
    event = Event(
        event_id="e-1",
        seq=1,
        type=EventType.BRANCH,
        timestamp=1.0,
        pc="0X401000",
        thread_id="1",
        cpu_id=0,
        payload={"target": "0X401010", "taken": True},
    )

    assert event.pc == "0x401000"
    assert event.payload["target"] == "0x401010"


def test_event_to_dict_uses_enum_value() -> None:
    event = Event(
        event_id="e-2",
        seq=2,
        type=EventType.EXECUTION_PAUSED,
        timestamp=2.0,
        pc=None,
        thread_id=None,
        cpu_id=None,
        payload={"reason": "user"},
    )

    assert event.to_dict()["type"] == "execution_paused"


def test_backend_ready_event_is_valid() -> None:
    event = Event(
        event_id="e-ready",
        seq=0,
        type=EventType.BACKEND_READY,
        timestamp=0.0,
        pc=None,
        thread_id=None,
        cpu_id=None,
        payload={"status": "attached"},
    )

    assert event.to_dict()["type"] == "backend_ready"
