from dynamiq.events import Event, EventType
from dynamiq.instrumentation import AddressRange, event_matches_filters, trace_entry_from_event


def test_address_range_contains_normalized_address() -> None:
    rng = AddressRange("0x401000", "0x401100")
    assert rng.contains("0X401050")
    assert not rng.contains("0x401200")


def test_event_matches_filters_checks_type_and_range() -> None:
    event = Event(
        event_id="e-1",
        seq=1,
        type=EventType.BRANCH,
        timestamp=1.0,
        pc="0x401050",
        thread_id="1",
        cpu_id=0,
        payload={"target": "0x401060", "taken": True},
    )
    assert event_matches_filters(event, {EventType.BRANCH}, [AddressRange("0x401000", "0x401100")])
    assert not event_matches_filters(event, {EventType.CALL}, [AddressRange("0x401000", "0x401100")])


def test_trace_entry_from_event_uses_expected_shape() -> None:
    event = Event(
        event_id="e-1",
        seq=1,
        type=EventType.BRANCH,
        timestamp=1.0,
        pc="0x401050",
        thread_id="1",
        cpu_id=0,
        payload={"target": "0x401060", "taken": True},
    )

    entry = trace_entry_from_event(3, event)

    assert entry == {
        "index": 3,
        "event_id": "e-1",
        "type": "branch",
        "pc": "0x401050",
        "thread_id": "1",
    }
