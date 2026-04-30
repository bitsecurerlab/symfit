"""
Scripting API for autonomous program analysis.

ScriptSession provides a pythonic interface for autonomous systems to control
and analyze target programs. It wraps AnalysisSession with context manager support,
convenience methods, and transparent error handling.

Example:
    with ScriptSession(target="/bin/ls", args=["--help"]) as session:
        session.bp_add("0x401000")
        result = session.step(5)
        regs = session.get_registers(["rip", "rax"])
        print(f"Registers: {regs['result']}")
"""

from __future__ import annotations

from typing import Any

from .backends.base import BackendAdapter
from .backends.qemu_user_instrumented import QemuUserInstrumentedBackend
from .errors import InvalidStateError
from .session import AnalysisSession, SessionConfig


class ScriptSession:
    """
    Pythonic wrapper around AnalysisSession for autonomous program analysis.

    Provides:
    - Context manager support for automatic cleanup
    - Simplified initialization with sensible defaults
    - AnalysisSession methods exposed as transparent delegates
    - Convenience methods for common autonomous workflows
    - Standardized error handling and responses

    Attributes:
        target: Path to target binary
        args: Command-line arguments for target
        session: Underlying AnalysisSession instance (access for advanced use)
    """

    def __init__(
        self,
        target: str,
        args: list[str] | None = None,
        backend: BackendAdapter | None = None,
        config: SessionConfig | None = None,
        cwd: str | None = None,
        qemu_config: dict[str, Any] | None = None,
        auto_start: bool = False,
    ):
        """
        Initialize ScriptSession.

        Automatically configures QEMU for autonomous RPC-based analysis:
        - Auto-detects QEMU binary path (tries: repo build, system qemu, then guesses)
        - Creates RPC socket for command/control communication
        - Creates trace file for event capture
        - Auto-configures socket paths in system temp directory
        - Enables launch by default for convenient standalone usage
        - All auto-detection can be overridden via qemu_config parameter

        Args:
            target: Path to target binary to analyze
            args: Command-line arguments for target (default: None)
            backend: Backend adapter (default: QemuUserInstrumentedBackend)
            config: Session configuration (default: SessionConfig with defaults)
            cwd: Working directory for target (default: None)
            qemu_config: QEMU-specific configuration to override defaults (default: None)
                - Uses RPC mode by default for all communication
                - Keys: 'launch', 'qemu_user_path', 'instrumentation_rpc_socket_path',
                        'instrumentation_trace_file_path'
                - All missing keys are auto-detected
            auto_start: If True, start session immediately (default: False)

        Raises:
            ValueError: If target is empty or None

        Example:
            # Simplest usage - RPC auto-configured
            with ScriptSession(target="/bin/ls", args=["--help"]) as session:
                session.step(5)  # RPC command

            # Override specific settings
            with ScriptSession(
                target="/bin/ls",
                qemu_config={"qemu_user_path": "/custom/qemu-x86_64"}
            ) as session:
                pass
        """
        if not target:
            raise ValueError("target must be non-empty")

        self.target = target
        self.args = args or []
        self.cwd = cwd
        
        # Merge user-provided qemu_config with defaults that enable RPC auto-detection
        # Setting 'launch': True enables QEMU path auto-detection and RPC socket creation
        default_qemu_config = {"launch": True}
        self.qemu_config = {**default_qemu_config, **(qemu_config or {})}

        # Initialize backend and config
        self._backend = backend or QemuUserInstrumentedBackend()
        self._config = config or SessionConfig()
        self._session = AnalysisSession(backend=self._backend, config=self._config)

        if auto_start:
            self.start()

    # Context Manager Support
    # =======================

    def __enter__(self) -> ScriptSession:
        """Enter context manager: start session if not already started."""
        if self._session.state.session_status == "not_started":
            self.start()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        """Exit context manager: close session and cleanup."""
        try:
            self.close()
        except Exception:
            pass  # Suppress cleanup errors
        return False

    # Session Lifecycle (3 methods)
    # =============================

    def start(self) -> dict[str, Any]:
        """
        Start the analysis session and launch target program.

        Automatically:
        - Detects target architecture (32-bit vs 64-bit) from ELF header
        - Selects appropriate QEMU binary (qemu-i386 or qemu-x86_64)
        - Searches for QEMU in: merged SymFit build artifacts, then system PATH
        - Creates RPC socket in system temp directory
        - Creates trace file for event capture
        - Launches QEMU with instrumentation enabled
        - All communication with QEMU uses RPC

        No manual configuration needed - all auto-detected from target binary.

        Returns:
            Response dict with session state and result.

        Raises:
            InvalidStateError: If session already started or QEMU not found
        """
        return self._session.start(
            target=self.target,
            args=self.args,
            cwd=self.cwd,
            qemu_config=self.qemu_config,
        )

    def close(self) -> dict[str, Any]:
        """
        Close the analysis session and cleanup resources.

        Returns:
            Response dict with session state.
        """
        return self._session.close()

    def capabilities(self) -> dict[str, Any]:
        """
        Get backend capabilities.

        Returns:
            Response dict containing capability information.
        """
        return self._session.capabilities()

    # Execution Control (8 methods)
    # =============================

    def run(self, timeout: float = 5.0) -> dict[str, Any]:
        """
        Resume target execution until timeout or event.

        Args:
            timeout: Time in seconds to execute (default: 5.0)

        Returns:
            Response dict with execution result.

        Raises:
            InvalidStateError: If session not started
        """
        return self._session.resume(timeout=timeout)

    def pause(self, timeout: float = 5.0) -> dict[str, Any]:
        """
        Pause target execution.

        Args:
            timeout: Time in seconds to wait for pause (default: 5.0)

        Returns:
            Response dict with paused state.
        """
        return self._session.pause(timeout=timeout)

    def step(self, count: int = 1, timeout: float = 5.0) -> dict[str, Any]:
        """
        Step target execution N instructions.

        Args:
            count: Number of instructions to step (default: 1)
            timeout: Time in seconds for step (default: 5.0)

        Returns:
            Response dict with execution result.

        Raises:
            InvalidStateError: If session not started
        """
        return self._session.step(count=count, timeout=timeout)

    def advance(self, mode: str, count: int | None = None, timeout: float = 5.0) -> dict[str, Any]:
        """
        Advance target execution using the unified execution-control API.

        Args:
            mode: One of ``continue``, ``insn``, ``bb``, or ``return``
            count: Optional count for ``insn`` and ``bb`` modes
            timeout: Time in seconds for execution (default: 5.0)

        Returns:
            Response dict with execution result.

        Raises:
            InvalidStateError: If session not started or arguments are invalid
        """
        return self._session.advance(mode=mode, count=count, timeout=timeout)

    def advance_basic_blocks(self, count: int = 1, timeout: float = 5.0) -> dict[str, Any]:
        """
        Advance target execution N basic blocks.

        Args:
            count: Number of basic blocks to advance (default: 1)
            timeout: Time in seconds for execution (default: 5.0)

        Returns:
            Response dict with execution result.

        Raises:
            InvalidStateError: If session not started
        """
        return self._session.advance_basic_blocks(count=count, timeout=timeout)

    def run_until_address(self, address: str, timeout: float = 5.0) -> dict[str, Any]:
        """
        Run until target reaches specific address.

        Args:
            address: Target address (hex or decimal string)
            timeout: Time in seconds to execute (default: 5.0)

        Returns:
            Response dict with execution result.

        Raises:
            InvalidStateError: If session not started or address invalid
        """
        return self._session.run_until_address(address=address, timeout=timeout)

    def break_at_addresses(
        self,
        addresses: list[str],
        timeout: float = 5.0,
        max_steps: int = 10000,
    ) -> dict[str, Any]:
        """
        Run until target hits any of specified addresses.

        Args:
            addresses: List of target addresses (hex or decimal strings)
            timeout: Time in seconds per step (default: 5.0)
            max_steps: Maximum steps before timeout (default: 10000)

        Returns:
            Response dict with matched address and steps taken.

        Raises:
            InvalidStateError: If session not started or no addresses provided
        """
        return self._session.break_at_addresses(addresses=addresses, timeout=timeout, max_steps=max_steps)

    def resume(self, timeout: float = 5.0) -> dict[str, Any]:
        """
        Alias for run() - resume target execution.

        Args:
            timeout: Time in seconds to execute (default: 5.0)

        Returns:
            Response dict with execution result.
        """
        return self.run(timeout=timeout)

    # Breakpoint Management (4 methods)
    # =================================

    def bp_add(self, address: str) -> dict[str, Any]:
        """
        Add breakpoint at address.

        Args:
            address: Address for breakpoint (hex or decimal string)

        Returns:
            Response dict with breakpoint list.

        Raises:
            InvalidStateError: If address is invalid
        """
        return self._session.bp_add(address=address)

    def bp_del(self, address: str) -> dict[str, Any]:
        """
        Remove breakpoint at address.

        Args:
            address: Address to remove (hex or decimal string)

        Returns:
            Response dict with updated breakpoint list.
        """
        return self._session.bp_del(address=address)

    def bp_list(self) -> dict[str, Any]:
        """
        List all active breakpoints.

        Returns:
            Response dict containing list of breakpoint addresses.
        """
        return self._session.bp_list()

    def bp_clear(self) -> dict[str, Any]:
        """
        Clear all breakpoints.

        Returns:
            Response dict with empty breakpoint list.
        """
        return self._session.bp_clear()

    def bp_run(self, timeout: float = 5.0, max_steps: int = 10000) -> dict[str, Any]:
        """
        Execute until hitting any configured breakpoint.

        Args:
            timeout: Time in seconds per step (default: 5.0)
            max_steps: Maximum steps before timeout (default: 10000)

        Returns:
            Response dict with result.

        Raises:
            InvalidStateError: If no breakpoints configured
        """
        return self._session.bp_run(timeout=timeout, max_steps=max_steps)

    # State Inspection (7 methods)
    # ============================

    def get_state(self) -> dict[str, Any]:
        """
        Get complete session state snapshot.

        The state view is the main summary surface for autonomous workflows. In
        addition to lifecycle and PC fields, it includes cached symbolic
        summaries such as:
        - ``symbolic_registers`` after ``get_registers()``
        - ``recent_symbolic_pcs`` after ``recent_path_constraints()``

        Returns:
            Response dict with full ExecutionState.
        """
        return self._session.get_state()

    def get_registers(self, names: list[str] | None = None) -> dict[str, Any]:
        """
        Read CPU registers.

        Args:
            names: List of register names to read (default: None = all)

        Returns:
            Response dict with register values.

        Raises:
            InvalidStateError: If session not started
        """
        return self._session.get_registers(names=names)

    def read_memory(self, address: str, size: int) -> dict[str, Any]:
        """
        Read memory from target.

        Args:
            address: Memory address (hex or decimal string)
            size: Number of bytes to read

        Returns:
            Response dict with memory bytes.

        Raises:
            InvalidStateError: If size exceeds max or address invalid
        """
        return self._session.read_memory(address=address, size=size)

    def backtrace(self, max_frames: int = 16) -> dict[str, Any]:
        """
        Build stack backtrace with symbol resolution.

        Args:
            max_frames: Maximum frames to trace (default: 16)

        Returns:
            Response dict with backtrace frames.

        Raises:
            InvalidStateError: If unable to determine instruction pointer
        """
        return self._session.backtrace(max_frames=max_frames)

    def disassemble(self, address: str, count: int = 16) -> dict[str, Any]:
        """
        Disassemble instructions from address.

        Args:
            address: Starting address (hex or decimal string)
            count: Number of instructions (default: 16)

        Returns:
            Response dict with disassembled instructions.

        Raises:
            InvalidStateError: If count exceeds max or address invalid
        """
        return self._session.disassemble(address=address, count=count)

    def list_memory_maps(self) -> dict[str, Any]:
        """
        Get process memory layout/maps.

        Returns:
            Response dict with memory regions.
        """
        return self._session.list_memory_maps()

    def symbols(self, max_count: int = 500, name_filter: str | None = None) -> dict[str, Any]:
        """
        Query ELF symbols with automatic PIE handling.

        Args:
            max_count: Maximum symbols to return (default: 500)
            name_filter: Filter symbols by name substring (default: None)

        Returns:
            Response dict with symbol table.

        Raises:
            InvalidStateError: If target binary not accessible
        """
        return self._session.symbols(max_count=max_count, name_filter=name_filter)

    def symbolize_memory(self, address: str, size: int, name: str | None = None) -> dict[str, Any]:
        """
        Mark a paused guest memory range symbolic.

        Args:
            address: Guest address to symbolize
            size: Number of bytes to symbolize
            name: Optional symbolic variable hint

        Returns:
            Response dict with symbolization result.
        """
        return self._session.symbolize_memory(address=address, size=size, name=name)

    def symbolize_register(self, register: str, name: str | None = None) -> dict[str, Any]:
        """
        Mark a paused guest register symbolic.

        Args:
            register: Register name
            name: Optional symbolic variable hint

        Returns:
            Response dict with symbolization result.
        """
        return self._session.symbolize_register(register=register, name=name)

    def get_symbolic_expression(self, label: str) -> dict[str, Any]:
        """
        Render a symbolic expression for one label.

        Args:
            label: Symbolic label as a hex string

        Returns:
            Response dict with expression details.
        """
        return self._session.get_symbolic_expression(label=label)

    def recent_path_constraints(self, limit: int = 16) -> dict[str, Any]:
        """
        Return recent path-condition events discovered during execution.

        Args:
            limit: Maximum number of recent entries to return

        Returns:
            Response dict with recent path constraints.
        """
        return self._session.recent_path_constraints(limit=limit)

    def path_constraint_closure(self, label: str) -> dict[str, Any]:
        """
        Return the nested path-constraint closure for one label.

        Args:
            label: Root path-constraint label

        Returns:
            Response dict with root and nested constraints.
        """
        return self._session.path_constraint_closure(label=label)

    # I/O Operations (4 methods)
    # ==========================

    def write_stdin(self, data: str | bytes, symbolic: bool = False) -> dict[str, Any]:
        """
        Write data to target's stdin.

        Args:
            data: String or bytes to write
            symbolic: Queue this stdin chunk for symbolic labeling when the guest consumes it

        Returns:
            Response dict with I/O result.

        Raises:
            InvalidStateError: If session not started
        """
        return self._session.write_stdin(data=data, symbolic=symbolic)

    def close_stdin(self) -> dict[str, Any]:
        """
        Close target stdin to signal EOF.

        Returns:
            Response dict with close result.

        Raises:
            InvalidStateError: If session not started
        """
        return self._session.close_stdin()

    def read_stdout(self, cursor: int = 0, max_chars: int = 4096) -> dict[str, Any]:
        """
        Read from target's stdout buffer.

        Args:
            cursor: Starting position in buffer (default: 0)
            max_chars: Maximum characters to read (default: 4096)

        Returns:
            Response dict with stdout content.
        """
        return self._session.read_stdout(cursor=cursor, max_chars=max_chars)

    def read_stderr(self, cursor: int = 0, max_chars: int = 4096) -> dict[str, Any]:
        """
        Read from target's stderr buffer.

        Args:
            cursor: Starting position in buffer (default: 0)
            max_chars: Maximum characters to read (default: 4096)

        Returns:
            Response dict with stderr content.
        """
        return self._session.read_stderr(cursor=cursor, max_chars=max_chars)

    # Execution Tracing (4 methods)
    # =============================

    def trace_start(
        self,
        event_types: list[str] | None = None,
        address_ranges: list[tuple[str, str]] | None = None,
    ) -> dict[str, Any]:
        """
        Start execution tracing with optional filters.

        Args:
            event_types: Event types to capture (e.g., ["basic_block", "branch"])
            address_ranges: Address ranges to trace (list of (start, end) tuples)

        Returns:
            Response dict with trace configuration.
        """
        return self._session.trace_start(event_types=event_types, address_ranges=address_ranges)

    def trace_stop(self) -> dict[str, Any]:
        """
        Stop execution tracing.

        Returns:
            Response dict with trace status.
        """
        return self._session.trace_stop()

    def trace_status(self) -> dict[str, Any]:
        """
        Get current tracing status and configuration.

        Returns:
            Response dict with trace state.
        """
        return self._session.trace_status()

    def trace_get(self, limit: int = 100, since_start: bool = True) -> dict[str, Any]:
        """
        Retrieve trace entries.

        Args:
            limit: Maximum entries to return (default: 100)
            since_start: If True, get entries since trace start (default: True)

        Returns:
            Response dict with trace entries.
        """
        return self._session.trace_get(limit=limit, since_start=since_start)

    # Event Inspection (2 methods)
    # ============================

    def get_recent_events(
        self,
        limit: int = 100,
        event_types: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Get recent execution events.

        Args:
            limit: Maximum events to return (default: 100)
            event_types: Filter by event types (default: None = all)

        Returns:
            Response dict with recent events.
        """
        return self._session.get_recent_events(limit=limit, event_types=event_types)

    def get_trace(self, limit: int = 100) -> dict[str, Any]:
        """
        Get trace entries (alias for trace_get).

        Args:
            limit: Maximum entries to return (default: 100)

        Returns:
            Response dict with trace entries.
        """
        return self._session.get_trace(limit=limit)

    # Snapshots (3 methods)
    # ====================

    def take_snapshot(self, name: str | None = None) -> dict[str, Any]:
        """
        Capture execution state snapshot.

        Args:
            name: Optional name for snapshot (default: None)

        Returns:
            Response dict with snapshot metadata.
        """
        return self._session.take_snapshot(name=name)

    def restore_snapshot(self, snapshot_id: str) -> dict[str, Any]:
        """
        Restore execution from snapshot.

        Args:
            snapshot_id: ID of snapshot to restore

        Returns:
            Response dict with restored state.
        """
        return self._session.restore_snapshot(snapshot_id=snapshot_id)

    def diff_snapshots(self, left_id: str, right_id: str) -> dict[str, Any]:
        """
        Compare two snapshots for differences.

        Args:
            left_id: First snapshot ID
            right_id: Second snapshot ID

        Returns:
            Response dict with differences.
        """
        return self._session.diff_snapshots(left_id=left_id, right_id=right_id)

    # Annotations (2 methods)
    # ======================

    def annotate(
        self,
        address: str,
        note: str,
        tags: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Add annotation at address.

        Args:
            address: Target address
            note: Annotation text
            tags: Optional tags for categorization

        Returns:
            Response dict with annotation metadata.
        """
        return self._session.annotate(address=address, note=note, tags=tags)

    def list_annotations(self, address: str | None = None) -> dict[str, Any]:
        """
        List annotations.

        Args:
            address: If specified, list annotations at this address (default: None = all)

        Returns:
            Response dict with annotations.
        """
        return self._session.list_annotations(address=address)

    # Convenience Methods for Autonomous Workflows
    # =============================================

    def run_until_breakpoint(
        self,
        timeout: float = 5.0,
        max_steps: int = 10000,
    ) -> dict[str, Any]:
        """
        Execute until hitting any configured breakpoint.

        Convenience wrapper around bp_run.

        Args:
            timeout: Time in seconds per step (default: 5.0)
            max_steps: Maximum steps before timeout (default: 10000)

        Returns:
            Response dict with result.

        Raises:
            InvalidStateError: If no breakpoints configured
        """
        return self.bp_run(timeout=timeout, max_steps=max_steps)

    def trace_region(
        self,
        start_address: str,
        end_address: str,
        event_types: list[str] | None = None,
    ) -> dict[str, Any]:
        """
        Start tracing specific address range.

        Args:
            start_address: Start of region
            end_address: End of region
            event_types: Event types to capture (default: None = all)

        Returns:
            Response dict with trace configuration.
        """
        address_ranges = [(start_address, end_address)]
        return self.trace_start(event_types=event_types, address_ranges=address_ranges)

    def inspect_function(self, address: str, max_instructions: int = 64) -> dict[str, Any]:
        """
        Inspect function at address: disassemble + get symbols.

        Args:
            address: Function address
            max_instructions: Max instructions to disassemble (default: 64)

        Returns:
            Response dict with disassembly result.
        """
        return self.disassemble(address=address, count=max_instructions)

    def wait_for_condition(
        self,
        condition_fn: callable,
        timeout: float = 5.0,
        step_size: int = 1,
        max_iterations: int = 1000,
    ) -> bool:
        """
        Execute until condition_fn(session.get_state()) returns True.

        Args:
            condition_fn: Callable that takes state dict, returns bool
            timeout: Time per step in seconds (default: 5.0)
            step_size: Instructions per iteration (default: 1)
            max_iterations: Maximum iterations before timeout (default: 1000)

        Returns:
            True if condition met, False if max_iterations exceeded.

        Example:
            session.wait_for_condition(
                lambda state: state.get('rip') == '0x401234'
            )
        """
        for _ in range(max_iterations):
            state = self.get_state()
            if condition_fn(state.get("state", {})):
                return True
            self.step(count=step_size, timeout=timeout)
        return False

    def assert_state(self, key: str, expected: Any) -> bool:
        """
        Assert that session state contains expected value.

        Args:
            key: State key (dot-notation supported for nested: "result.registers.rip")
            expected: Expected value

        Returns:
            True if assertion passes.

        Raises:
            AssertionError: If assertion fails.
        """
        state = self.get_state().get("state", {})
        keys = key.split(".")
        value = state
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
            else:
                raise AssertionError(f"Cannot traverse key {key}: {k} not found in {value}")

        if value != expected:
            raise AssertionError(f"State {key} = {value}, expected {expected}")
        return True

    # Property Accessors for Common State Values
    # ==========================================

    @property
    def session(self) -> AnalysisSession:
        """Access underlying AnalysisSession for advanced use."""
        return self._session

    @property
    def state(self) -> dict[str, Any]:
        """Get current ExecutionState as dict, including cached symbolic summaries."""
        return self._session.state.to_dict()

    @property
    def pc(self) -> str | None:
        """Get current program counter."""
        return self._session.state.pc

    @property
    def status(self) -> str:
        """Get session status (not_started|idle|paused|running|exited|closed)."""
        return self._session.state.session_status

    @property
    def is_running(self) -> bool:
        """Check if session is currently executing."""
        return self.status == "running"

    @property
    def is_paused(self) -> bool:
        """Check if session is paused."""
        return self.status == "paused"

    @property
    def is_started(self) -> bool:
        """Check if session has been started."""
        return self.status not in {"not_started", "closed"}
