#!/usr/bin/env python3
"""
Automated testing with ScriptSession.

Demonstrates:
- Breakpoints + state assertions
- Checkpoint/restore workflow for repeatable tests
- Test harness patterns
- Memory and register inspections
- Autonomous testing without human interaction
"""

from pathlib import Path

from dynamiq.script_api import ScriptSession
from dynamiq.script_helpers import (
    assert_register_value,
    checkpoint_restore_test,
    collect_trace_between_addresses,
)

SAMPLE_TARGET = Path(__file__).parent / "sample_target"


def test_function_prologue():
    """Test that function has proper prologue (push rbp; mov rsp, rbp)."""
    with ScriptSession(target=str(SAMPLE_TARGET), auto_start=True) as session:
        # Get 'main' symbol
        symbols = session.symbols(max_count=50, name_filter="main")
        main_addrs = [
            s.get("loaded_address")
            for s in symbols["result"].get("symbols", [])
            if s.get("name") == "main"
        ]

        if not main_addrs:
            print("⚠ Could not find 'main' symbol")
            return False

        main_addr = main_addrs[0]
        print(f"Testing function prologue at {main_addr}")

        # Run to main
        session.bp_add(main_addr)
        session.bp_run(timeout=2.0)

        # Check prologue pattern
        # x86-64: 55 48 89 e5 = push rbp; mov rsp rbp
        prologue_bytes = bytes([0x55, 0x48, 0x89, 0xe5])
        memory = session.read_memory(main_addr, len(prologue_bytes))
        mem_hex = memory["result"].get("bytes", "")

        if isinstance(mem_hex, str):
            actual = bytes.fromhex(mem_hex)
        else:
            actual = mem_hex

        if actual == prologue_bytes:
            print("✓ PASS: Function prologue correct")
            return True
        else:
            print(f"✗ FAIL: Expected prologue {prologue_bytes.hex()}, got {actual.hex()}")
            return False


def test_register_initialization():
    """Test that registers are properly initialized."""
    with ScriptSession(target=str(SAMPLE_TARGET), auto_start=True) as session:
        print("Testing register initialization...")

        # Step to first libc code
        for _ in range(20):
            session.step(count=1, timeout=1.0)

        # Check RSP is valid (non-zero, in stack range)
        regs = session.get_registers(["rsp", "rbp"])
        rsp = regs["result"].get("registers", {}).get("rsp")

        if rsp and rsp != "0x0" and rsp != "0":
            print(f"✓ PASS: RSP initialized to {rsp}")
            return True
        else:
            print(f"✗ FAIL: RSP not initialized properly: {rsp}")
            return False


def test_stepping_consistency():
    """Test that stepping is deterministic (same trace, checkpoint/restore)."""
    with ScriptSession(target=str(SAMPLE_TARGET), auto_start=True) as session:
        print("Testing stepping consistency...")

        # Take snapshot
        snap = session.take_snapshot(name="test_step")
        snap_id = snap["result"].get("snapshot_id")

        # Collect trace 1
        for _ in range(10):
            session.step(count=1, timeout=1.0)

        state_1 = session.get_state()
        pc_1 = state_1["state"].get("pc")

        # Restore and trace again
        session.restore_snapshot(snap_id)

        for _ in range(10):
            session.step(count=1, timeout=1.0)

        state_2 = session.get_state()
        pc_2 = state_2["state"].get("pc")

        if pc_1 == pc_2:
            print(f"✓ PASS: Stepping deterministic, both reach {pc_1}")
            return True
        else:
            print(f"✗ FAIL: Different PCs after identical steps: {pc_1} vs {pc_2}")
            return False


def test_multiple_iterations():
    """Test checkpoint/restore for repeated test scenarios."""

    def run_test_iteration(s):
        """Step 5 times and read RAX."""
        for _ in range(5):
            s.step(count=1, timeout=1.0)
        regs = s.get_registers(["rax"])
        return regs["result"].get("registers", {}).get("rax")

    with ScriptSession(target=str(SAMPLE_TARGET), auto_start=True) as session:
        print("Testing multiple iterations with checkpoint/restore...")

        try:
            results = checkpoint_restore_test(session, run_test_iteration, num_iterations=3)

            # All iterations should see same RAX (deterministic execution)
            all_same = all(r == results[0] for r in results)
            if all_same:
                print(f"✓ PASS: All iterations saw RAX={results[0]}")
                return True
            else:
                print(f"✗ FAIL: Different RAX values across iterations: {results}")
                return False
        except Exception as e:
            print(f"✗ ERROR: {e}")
            return False


def test_breakpoint_hit():
    """Test breakpoint hit detection."""
    with ScriptSession(target=str(SAMPLE_TARGET), auto_start=True) as session:
        print("Testing breakpoint hit...")

        symbols = session.symbols(max_count=50)
        sym_addrs = [
            s.get("loaded_address")
            for s in symbols["result"].get("symbols", [])
            if s.get("name") in ("main", "puts", "exit")
        ]

        if not sym_addrs:
            print("⚠ Could not find target symbols")
            return False

        target_addr = sym_addrs[0]
        print(f"Setting breakpoint at {target_addr}")

        session.bp_add(target_addr)
        session.bp_clear()  # Actually clear prior to testing

        # Re-add
        session.bp_add(target_addr)

        try:
            result = session.bp_run(timeout=3.0, max_steps=10000)
            matched = result["result"].get("matched_address")
            steps = result["result"].get("steps", 0)

            if matched == target_addr:
                print(f"✓ PASS: Hit breakpoint at {matched} after {steps} steps")
                return True
            else:
                print(f"✗ FAIL: Expected breakpoint {target_addr}, got {matched}")
                return False
        except Exception as e:
            print(f"✗ FAIL: Breakpoint execution failed: {e}")
            return False


class TestSuite:
    """Autonomous test suite harness."""

    def __init__(self, target: str):
        self.target = target
        self.tests: list[tuple[str, callable]] = []
        self.results: dict[str, bool] = {}

    def add_test(self, name: str, test_fn: callable) -> None:
        """Register a test."""
        self.tests.append((name, test_fn))

    def run_all(self) -> int:
        """Run all tests, return pass count."""
        print("\n" + "=" * 60)
        print("AUTOMATED TEST SUITE")
        print("=" * 60 + "\n")

        for i, (name, test_fn) in enumerate(self.tests, 1):
            try:
                print(f"[{i}/{len(self.tests)}] {name}")
                result = test_fn()
                self.results[name] = result
            except Exception as e:
                print(f"✗ ERROR: {e}")
                self.results[name] = False

            print()

        # Summary
        print("=" * 60)
        passed = sum(1 for v in self.results.values() if v)
        total = len(self.results)
        print(f"RESULTS: {passed}/{total} tests passed")

        for name, result in self.results.items():
            status = "✓ PASS" if result else "✗ FAIL"
            print(f"  {status}: {name}")

        print("=" * 60 + "\n")

        return passed


def main():
    if not SAMPLE_TARGET.exists():
        print(f"Error: sample target not found at {SAMPLE_TARGET}")
        print("Make sure to build the sample target first: gcc -o sample_target sample_target.c")
        return

    suite = TestSuite(str(SAMPLE_TARGET))

    # Register tests
    suite.add_test("Function Prologue", test_function_prologue)
    suite.add_test("Register Initialization", test_register_initialization)
    suite.add_test("Stepping Consistency", test_stepping_consistency)
    suite.add_test("Breakpoint Hit", test_breakpoint_hit)
    suite.add_test("Multiple Iterations", test_multiple_iterations)

    # Run all
    passed = suite.run_all()

    # Exit with appropriate code
    exit(0 if passed == len(suite.tests) else 1)


if __name__ == "__main__":
    main()
