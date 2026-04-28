#!/usr/bin/env python3
"""
Basic ScriptSession usage example.

Demonstrates:
- Starting a session
- Stepping through execution
- Inspecting registers and memory
- Context manager for cleanup
- Querying status
"""

from pathlib import Path

from dynamiq.script_api import ScriptSession

# Use the sample target from the repo
SAMPLE_TARGET = Path(__file__).parent / "sample_target"


def main():
    if not SAMPLE_TARGET.exists():
        print(f"Error: sample target not found at {SAMPLE_TARGET}")
        print("Make sure to build the sample target first: gcc -o sample_target sample_target.c")
        return

    print("=== Basic Script Session Example ===\n")

    # Method 1: Manual start/stop with minimal config
    print("Method 1: Manual start/stop (RPC auto-configured)")
    print("-" * 40)
    # Note: QEMU RPC socket is auto-detected from target
    session = ScriptSession(target=str(SAMPLE_TARGET), args=["demo"])

    result = session.start()
    print(f"Started session: status={session.status}")
    print(f"Target: {session.target}")
    print(f"QEMU launched with RPC\n")

    # Get initial state
    state = session.get_state()
    print(f"Initial PC: {state['state'].get('pc')}\n")

    # Step a few times
    print("Stepping 5 instructions...")
    for i in range(5):
        session.step(count=1, timeout=2.0)
        pc = session.pc
        print(f"  Step {i+1}: PC={pc}")

    print()

    # Read some registers
    print("Reading registers...")
    regs = session.get_registers(["rip", "rax", "rbx"])
    for name, value in regs["result"].get("registers", {}).items():
        print(f"  {name} = {value}")

    print()

    # Disassemble current instructions
    print("Disassembling current location...")
    if session.pc:
        disasm = session.disassemble(session.pc, count=3)
        for instr in disasm["result"].get("instructions", []):
            print(f"  {instr.get('address')}: {instr.get('mnemonic')} {instr.get('operands', '')}")

    print()

    # Check status
    print(f"Session status: {session.status}")
    print(f"Is paused: {session.is_paused}")
    print(f"Is running: {session.is_running}")

    session.close()
    print("Session closed\n")

    # Method 2: Using context manager
    print("Method 2: Context manager (auto-cleanup)")
    print("-" * 40)

    with ScriptSession(target=str(SAMPLE_TARGET), args=["demo"], auto_start=True) as session:
        print(f"Session auto-started: {session.is_started}")
        print(f"Status: {session.status}\n")

        # Step through a few instructions
        for i in range(3):
            session.step(count=2, timeout=2.0)
            print(f"After step {i+1}: PC={session.pc}")

        # Get memory maps
        print("\nMemory maps:")
        maps = session.list_memory_maps()
        regions = maps["result"].get("maps", {}).get("regions", [])
        for region in regions[:3]:  # Show first 3 regions
            print(f"  {region.get('start')} - {region.get('end')} [{region.get('perms')}]")

    # Context manager automatically calls close()
    print("\nContext manager exited - session automatically closed")

    # Method 3: Working with breakpoints
    print("\n" + "=" * 40)
    print("Method 3: Breakpoint usage (RPC commands)")
    print("-" * 40)

    with ScriptSession(target=str(SAMPLE_TARGET), auto_start=True) as session:
        # Get entry point or main symbol
        print("Querying symbols...")
        symbols = session.symbols(max_count=10, name_filter="main")
        main_bps = [
            s.get("loaded_address")
            for s in symbols["result"].get("symbols", [])
            if s.get("name") == "main"
        ]

        if main_bps:
            main_addr = main_bps[0]
            print(f"Found main at: {main_addr}")
            print(f"Adding breakpoint at main...")

            session.bp_add(main_addr)
            bps = session.bp_list()
            print(f"Active breakpoints: {bps['result'].get('breakpoints', [])}")

            # Run until breakpoint (if we haven't hit main yet)
            print("Running until breakpoint...")
            try:
                result = session.bp_run(timeout=2.0, max_steps=5000)
                print(f"Breakpoint hit: {result['result'].get('matched_address')}")
            except Exception as e:
                print(f"Breakpoint run result: {e}")

    print("\nExample complete!")


if __name__ == "__main__":
    main()
