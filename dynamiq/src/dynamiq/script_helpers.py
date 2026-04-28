"""
Helper utilities for autonomous program analysis scripts.

Provides context managers and utility functions for common analysis patterns
like managing temporary breakpoint sets, memory watches, and tracing regions.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Callable, Generator

from .script_api import ScriptSession


class MemoryWatch:
    """Watch memory region for changes during execution."""

    def __init__(
        self,
        session: ScriptSession,
        address: str,
        size: int,
        on_change: Callable[[str, bytes, bytes], None] | None = None,
    ):
        """
        Initialize memory watcher.

        Args:
            session: ScriptSession instance
            address: Memory address to watch
            size: Number of bytes to monitor
            on_change: Callback fn(address, old_bytes, new_bytes) on change
        """
        self.session = session
        self.address = address
        self.size = size
        self.on_change = on_change
        self.initial_value: bytes | None = None
        self.current_value: bytes | None = None

    def capture(self) -> bytes:
        """Capture current memory value."""
        result = self.session.read_memory(self.address, self.size)
        mem_bytes = result.get("result", {}).get("bytes", "")
        # Convert hex string to bytes
        if isinstance(mem_bytes, str):
            self.current_value = bytes.fromhex(mem_bytes)
        else:
            self.current_value = mem_bytes
        return self.current_value

    def check(self) -> bool:
        """
        Check if memory changed since last capture.

        Returns:
            True if changed, False otherwise.
        """
        old_value = self.current_value
        new_value = self.capture()

        if old_value is not None and old_value != new_value:
            if self.on_change and old_value:
                self.on_change(self.address, old_value, new_value)
            return True

        return False

    def __enter__(self) -> MemoryWatch:
        """Context manager entry: capture initial value."""
        self.capture()
        self.initial_value = self.current_value
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        pass


@contextmanager
def breakpoint_group(
    session: ScriptSession,
    addresses: list[str],
) -> Generator[list[str], None, None]:
    """
    Context manager for temporary breakpoint group.

    Adds breakpoints on entry, removes on exit. Useful for temporary
    analysis patterns.

    Args:
        session: ScriptSession instance
        addresses: List of addresses to add as breakpoints

    Yields:
        List of addresses added

    Example:
        with breakpoint_group(session, ["0x401000", "0x401010"]) as bps:
            session.bp_run(timeout=10.0)
            print("Hit a breakpoint")
    """
    # Add all breakpoints
    for addr in addresses:
        session.bp_add(addr)

    try:
        yield addresses
    finally:
        # Remove all breakpoints
        for addr in addresses:
            session.bp_del(addr)


@contextmanager
def trace_region_context(
    session: ScriptSession,
    start_address: str,
    end_address: str,
    event_types: list[str] | None = None,
) -> Generator[None, None, None]:
    """
    Context manager for tracing specific address range.

    Starts trace on entry with address filter, stops on exit.

    Args:
        session: ScriptSession instance
        start_address: Start of region to trace
        end_address: End of region to trace
        event_types: Event types to capture (default: all)

    Yields:
        None

    Example:
        with trace_region_context(session, "0x401000", "0x401100"):
            session.run()
            events = session.get_trace(limit=1000)
    """
    session.trace_start(
        event_types=event_types,
        address_ranges=[(start_address, end_address)],
    )

    try:
        yield
    finally:
        session.trace_stop()


def run_until_event(
    session: ScriptSession,
    event_types: list[str],
    timeout: float = 5.0,
    max_iterations: int = 1000,
) -> dict[str, Any] | None:
    """
    Execute until one of specified event types occurs.

    Polls get_recent_events() after each step.

    Args:
        session: ScriptSession instance
        event_types: Event types to watch for
        timeout: Time per step in seconds (default: 5.0)
        max_iterations: Maximum steps before timeout (default: 1000)

    Returns:
        First matching event dict, or None if not found.

    Example:
        event = run_until_event(session, ["syscall"], timeout=2.0)
        if event:
            print(f"Caught syscall: {event}")
    """
    for _ in range(max_iterations):
        session.step(count=1, timeout=timeout)
        events = session.get_recent_events(limit=1, event_types=event_types)
        recent = events.get("result", {}).get("events", [])

        if recent:
            return recent[0]

    return None


def run_until_instruction(
    session: ScriptSession,
    mnemonic: str,
    timeout: float = 5.0,
    max_steps: int = 10000,
) -> bool:
    """
    Execute until specific instruction mnemonic appears at PC.

    Disassembles at each PC to check for mnemonic match.

    Args:
        session: ScriptSession instance
        mnemonic: Instruction mnemonic to match (e.g., "call", "syscall")
        timeout: Time per step in seconds (default: 5.0)
        max_steps: Maximum steps before timeout (default: 10000)

    Returns:
        True if instruction found, False if max_steps exceeded.

    Example:
        if run_until_instruction(session, "syscall"):
            print("Hit syscall instruction")
    """
    for _ in range(max_steps):
        state = session.get_state()
        pc = state.get("state", {}).get("pc")

        if pc:
            disasm = session.disassemble(pc, count=1)
            instructions = disasm.get("result", {}).get("instructions", [])

            if instructions:
                instr_text = instructions[0].get("mnemonic", "").lower()
                if mnemonic.lower() in instr_text:
                    return True

        session.step(count=1, timeout=timeout)

    return False


def collect_trace_between_addresses(
    session: ScriptSession,
    start_addr: str,
    end_addr: str,
    timeout: float = 5.0,
    max_steps: int = 10000,
) -> list[dict[str, Any]]:
    """
    Execute and collect trace from start_addr to end_addr.

    Convenience function combining address breakpoints and trace capture.

    Args:
        session: ScriptSession instance
        start_addr: Starting address
        end_addr: Ending address
        timeout: Time per step in seconds (default: 5.0)
        max_steps: Maximum steps before timeout (default: 10000)

    Returns:
        List of trace entries between addresses.

    Example:
        trace = collect_trace_between_addresses(session, "0x401000", "0x401100")
        for entry in trace:
            print(f"Event: {entry}")
    """
    with trace_region_context(session, start_addr, end_addr):
        session.break_at_addresses([end_addr], timeout=timeout, max_steps=max_steps)

    trace = session.trace_get(limit=10000, since_start=True)
    return trace.get("result", {}).get("trace", [])


def inspect_function_with_trace(
    session: ScriptSession,
    address: str,
    max_disasm: int = 64,
    capture_trace: bool = True,
) -> dict[str, Any]:
    """
    Inspect function: disassemble + optionally trace execution.

    Args:
        session: ScriptSession instance
        address: Function address
        max_disasm: Max instructions to disassemble (default: 64)
        capture_trace: If True, run function and collect trace (default: True)

    Returns:
        Dict with 'disassembly' and optional 'trace' keys.

    Example:
        info = inspect_function_with_trace(session, "0x401000")
        print(f"Disasm: {info['disassembly']}")
        print(f"Trace events: {len(info.get('trace', []))}")
    """
    result = {
        "disassembly": session.disassemble(address, count=max_disasm),
    }

    if capture_trace:
        # Find function end (heuristic: find return or end of disasm)
        disasm_result = result["disassembly"].get("result", {})
        instructions = disasm_result.get("instructions", [])

        if instructions:
            last_addr = instructions[-1].get("address", address)
            result["trace"] = collect_trace_between_addresses(
                session,
                address,
                last_addr,
                max_steps=1000,
            )
        else:
            result["trace"] = []

    return result


def checkpoint_restore_test(
    session: ScriptSession,
    test_fn: Callable[[ScriptSession], Any],
    num_iterations: int = 3,
) -> list[Any]:
    """
    Execute test function multiple times by checkpointing and restoring.

    Useful for autonomous system testing: take snapshot before test, restore
    after each iteration to re-run test in same initial state.

    Args:
        session: ScriptSession instance
        test_fn: Callable(session) -> result to repeat
        num_iterations: Number of repetitions (default: 3)

    Returns:
        List of test function results.

    Example:
        def test_func(s):
            s.step(5)
            return s.get_registers(["rax"])

        results = checkpoint_restore_test(session, test_func, num_iterations=3)
    """
    results = []

    # Take initial checkpoint
    snapshot = session.take_snapshot(name="test_checkpoint")
    snapshot_id = snapshot.get("result", {}).get("snapshot_id")

    if not snapshot_id:
        raise RuntimeError("Failed to create checkpoint snapshot")

    try:
        for i in range(num_iterations):
            result = test_fn(session)
            results.append(result)

            # Restore checkpoint for next iteration (except last)
            if i < num_iterations - 1:
                session.restore_snapshot(snapshot_id)

    finally:
        # Restore to clean state
        session.restore_snapshot(snapshot_id)

    return results


def assert_memory_pattern(
    session: ScriptSession,
    address: str,
    pattern: bytes,
    label: str = "",
) -> bool:
    """
    Assert memory matches expected pattern.

    Args:
        session: ScriptSession instance
        address: Memory address to check
        pattern: Expected bytes pattern
        label: Human-readable label for assertion (default: "")

    Returns:
        True if pattern matches.

    Raises:
        AssertionError: If pattern does not match.

    Example:
        assert_memory_pattern(session, "0x401000", b"\\x55\\x48\\x89", "function prologue")
    """
    result = session.read_memory(address, len(pattern))
    mem_hex = result.get("result", {}).get("bytes", "")

    if isinstance(mem_hex, str):
        actual = bytes.fromhex(mem_hex)
    else:
        actual = mem_hex

    if actual != pattern:
        msg = f"Memory pattern mismatch"
        if label:
            msg += f" ({label})"
        msg += f": expected {pattern.hex()} got {actual.hex()}"
        raise AssertionError(msg)

    return True


def assert_register_value(
    session: ScriptSession,
    register: str,
    expected_value: str | int,
    label: str = "",
) -> bool:
    """
    Assert CPU register has expected value.

    Args:
        session: ScriptSession instance
        register: Register name (e.g., "rax", "rip")
        expected_value: Expected value (hex/decimal string or int)
        label: Human-readable label (default: "")

    Returns:
        True if value matches.

    Raises:
        AssertionError: If value does not match.

    Example:
        assert_register_value(session, "rax", "0x42", "return value")
    """
    result = session.get_registers([register])
    registers = result.get("result", {}).get("registers", {})
    actual = registers.get(register)

    if isinstance(expected_value, int):
        expected_str = hex(expected_value)
    else:
        expected_str = str(expected_value)

    if actual != expected_str and actual != hex(int(expected_str, 0)):
        msg = f"Register {register} mismatch"
        if label:
            msg += f" ({label})"
        msg += f": expected {expected_str} got {actual}"
        raise AssertionError(msg)

    return True
