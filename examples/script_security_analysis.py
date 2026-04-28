#!/usr/bin/env python3
"""
Security analysis automation with ScriptSession.

Demonstrates:
- Syscall tracing
- Memory region inspection
- Event capture and analysis
- Automated vulnerability detection patterns
- Integration with autonomous security tools
"""

from pathlib import Path

from dynamiq.script_api import ScriptSession
from dynamiq.script_helpers import (
    MemoryWatch,
    run_until_event,
    run_until_instruction,
)

SAMPLE_TARGET = Path(__file__).parent / "sample_target"


def trace_syscalls():
    """Trace all syscalls made by target."""
    with ScriptSession(target=str(SAMPLE_TARGET), auto_start=True) as session:
        print("=== Syscall Tracing ===\n")

        # Start tracing syscall events
        session.trace_start(event_types=["syscall"])

        # Run for a while
        for i in range(100):
            session.step(count=10, timeout=1.0)

        # Get trace
        trace = session.trace_get(limit=1000)
        syscalls = trace["result"].get("trace", [])

        print(f"Captured {len(syscalls)} syscall events\n")

        # Analyze syscalls
        syscall_counts = {}
        for event in syscalls:
            name = event.get("name", "unknown")
            syscall_counts[name] = syscall_counts.get(name, 0) + 1

        print("Syscall summary:")
        for name, count in sorted(syscall_counts.items(), key=lambda x: -x[1]):
            print(f"  {name}: {count} calls")

        return syscalls


def analyze_memory_regions():
    """Analyze target memory layout and identify interesting regions."""
    with ScriptSession(target=str(SAMPLE_TARGET), auto_start=True) as session:
        print("\n=== Memory Region Analysis ===\n")

        # Get memory maps
        maps = session.list_memory_maps()
        regions = maps["result"].get("maps", {}).get("regions", [])

        print(f"Found {len(regions)} memory regions:\n")

        for i, region in enumerate(regions[:10]):  # Show first 10
            start = region.get("start")
            end = region.get("end")
            perms = region.get("perms", "----")
            path = region.get("path", "[anon]")

            # Calculate size
            if isinstance(start, str) and isinstance(end, str):
                size = int(end, 16) - int(start, 16)
            else:
                size = 0

            print(f"  [{i}] {start}-{end} [{perms}] {size:8d} bytes  {path}")

            # Flag suspicious regions
            if "x" in perms and "w" in perms:
                print(f"       ⚠ WARNING: Writable executable region!")

            if size > 10 * 1024 * 1024:  # > 10MB
                print(f"       ⚠ WARNING: Large region (> 10MB)")

        return regions


def detect_potential_buffer_overflow():
    """Heuristic check for potential stack-based buffer overflow."""
    with ScriptSession(target=str(SAMPLE_TARGET), auto_start=True) as session:
        print("\n=== Buffer Overflow Detection ===\n")

        # Get current registers
        regs = session.get_registers(["rsp", "rbp", "rax"])
        rsp = regs["result"].get("registers", {}).get("rsp")

        if not rsp:
            print("Could not read stack pointer")
            return False

        # Monitor RSP for large changes (potential overflow)
        print(f"Initial RSP: {rsp}")
        print("Monitoring for abnormal stack changes...\n")

        rsp_values = [rsp]

        for iteration in range(50):
            session.step(count=5, timeout=1.0)

            regs = session.get_registers(["rsp"])
            new_rsp = regs["result"].get("registers", {}).get("rsp")
            rsp_values.append(new_rsp)

            # Check for large stack pointer change
            if new_rsp and isinstance(new_rsp, str) and isinstance(rsp, str):
                old_val = int(rsp, 16) if rsp.startswith("0x") else int(rsp, 10)
                new_val = int(new_rsp, 16) if new_rsp.startswith("0x") else int(new_rsp, 10)
                delta = abs(old_val - new_val)

                if delta > 0x4000:  # >16KB jump
                    print(f"⚠ Abnormal stack change at iteration {iteration}: delta={hex(delta)}")
                    print(f"  Old RSP: {rsp}")
                    print(f"  New RSP: {new_rsp}")

        print("\nStack pointer trace:")
        for i, val in enumerate(rsp_values[-5:]):
            print(f"  [{i}] {val}")

        return True


def detect_function_calls():
    """Detect and log function calls (call instructions)."""
    with ScriptSession(target=str(SAMPLE_TARGET), auto_start=True) as session:
        print("\n=== Function Call Detection ===\n")

        # Trace branching events
        session.trace_start(event_types=["branch"])

        max_steps = 200
        calls_found = 0

        for i in range(max_steps):
            session.step(count=1, timeout=1.0)

            # Check if current instruction is 'call'
            pc = session.pc
            if pc:
                disasm = session.disassemble(pc, count=1)
                instructions = disasm["result"].get("instructions", [])

                if instructions:
                    mnemonic = instructions[0].get("mnemonic", "").lower()

                    if "call" in mnemonic:
                        operand = instructions[0].get("operands", "???")
                        print(f"  [{i:3d}] {pc}: call {operand}")
                        calls_found += 1

                        if calls_found >= 10:
                            break

        print(f"\nFound {calls_found} function calls")
        return calls_found > 0


def analyze_sensitive_library_calls():
    """Detect calls to sensitive libc functions (malloc, strcpy, etc)."""
    with ScriptSession(target=str(SAMPLE_TARGET), auto_start=True) as session:
        print("\n=== Sensitive Library Call Analysis ===\n")

        sensitive_functions = {
            "malloc": "Memory allocation",
            "strcpy": "Unsafe string copy (overflow risk!)",
            "sprintf": "Unsafe string format",
            "gets": "Unsafe input (overflow risk!)",
            "setuid": "Privilege change",
            "system": "Command execution",
            "exec": "Process execution",
        }

        print("Monitoring for sensitive function calls:\n")
        for func_name in sensitive_functions.keys():
            print(f"  • {func_name}")

        print("\nSearching for calls...\n")

        detected = {}

        # Run and monitor for call instructions
        for iteration in range(100):
            session.step(count=5, timeout=1.0)

            pc = session.pc
            if pc:
                disasm = session.disassemble(pc, count=1)
                instructions = disasm["result"].get("instructions", [])

                if instructions:
                    instr = instructions[0]
                    mnemonic = instr.get("mnemonic", "").lower()

                    if "call" in mnemonic:
                        operand = instr.get("operands", "")

                        # Check if it matches sensitive function
                        for func_name, description in sensitive_functions.items():
                            if func_name in operand.lower():
                                if func_name not in detected:
                                    detected[func_name] = []

                                detected[func_name].append({
                                    "address": pc,
                                    "instruction": f"{mnemonic} {operand}",
                                })

                                print(f"⚠ Found {func_name} call at {pc}: {operand}")
                                print(f"  Description: {description}\n")

        print(f"\n--- Summary ---")
        if detected:
            for func_name, calls in detected.items():
                print(f"{func_name}: {len(calls)} call(s)")
        else:
            print("No sensitive calls detected")

        return detected


def watch_memory_region(address: str, size: int):
    """Watch specific memory region for changes during execution."""
    with ScriptSession(target=str(SAMPLE_TARGET), auto_start=True) as session:
        print(f"\n=== Memory Watch ({address}, {size} bytes) ===\n")

        def on_change(addr, old, new):
            print(f"⚠ Memory changed at {addr}:")
            print(f"  Old: {old.hex()}")
            print(f"  New: {new.hex()}")

        watch = MemoryWatch(session, address, size, on_change=on_change)

        with watch:
            # Step through execution while watching
            for i in range(100):
                session.step(count=1, timeout=1.0)

                if watch.check():
                    # Memory changed!
                    pass

                if i % 20 == 0:
                    print(f"... iteration {i}")

        print("\nMemory watch complete")


def main():
    if not SAMPLE_TARGET.exists():
        print(f"Error: sample target not found at {SAMPLE_TARGET}")
        print("Make sure to build the sample target first: gcc -o sample_target sample_target.c")
        return

    print("=" * 60)
    print("SECURITY ANALYSIS AUTOMATION")
    print("=" * 60)

    # Run analyses
    syscalls = trace_syscalls()
    regions = analyze_memory_regions()
    detect_potential_buffer_overflow()
    detect_function_calls()
    detected_calls = analyze_sensitive_library_calls()

    # Print summary
    print("\n" + "=" * 60)
    print("ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"• Syscalls traced: {len(syscalls)}")
    print(f"• Memory regions: {len(regions)}")
    print(f"• Sensitive calls detected: {len(detected_calls)}")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
