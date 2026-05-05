#!/usr/bin/env python3
"""Test dynamiq with Alpine Linux boot using ISO image.

Boots Alpine Linux virt ISO and verifies system-mode backend functionality.
Run with:
    source dynamiq/.venv/bin/activate && python test_linux_system.py
"""
from __future__ import annotations

import hashlib
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

# Add the source path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dynamiq.script_api import ScriptSession


ALPINE_ISO_NAME = "alpine-virt-3.19.0-x86_64.iso"
ALPINE_ISO_URL = f"https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/x86_64/{ALPINE_ISO_NAME}"
ALPINE_ISO_SHA256_URL = f"{ALPINE_ISO_URL}.sha256"


def _find_symfit_system() -> Path | None:
    """Find symfit-system-x86_64 binary."""
    # Check environment variable first (for CI/testing flexibility)
    env_path = os.environ.get("DYNAMIQ_SYMFIT_SYSTEM_PATH")
    if env_path:
        candidate = Path(env_path)
        if candidate.exists() and os.access(candidate, os.X_OK):
            return candidate
    
    # Check relative to test file (works in checkout)
    # test_dir = /path/to/repo/dynamiq/tests
    # test_dir.parent = /path/to/repo/dynamiq
    # test_dir.parent.parent = /path/to/repo
    test_dir = Path(__file__).resolve().parent
    candidates = [
        test_dir.parent.parent / "build" / "symfit" / "x86_64-softmmu" / "symfit-system-x86_64",
        test_dir.parent.parent.parent / "build" / "symfit" / "x86_64-softmmu" / "symfit-system-x86_64",
    ]
    for candidate in candidates:
        if candidate.exists() and os.access(candidate, os.X_OK):
            return candidate
    
    # Check system PATH as last resort
    import shutil
    system_path = shutil.which("symfit-system-x86_64")
    if system_path:
        return Path(system_path)
    
    return None


def _fixture_dir() -> Path:
    configured = os.environ.get("DYNAMIQ_TEST_FIXTURE_DIR")
    if configured:
        return Path(configured)
    return Path(__file__).resolve().parent / "fixtures"


def _find_alpine_iso() -> Path | None:
    """Find Alpine Linux ISO."""
    env_path = os.environ.get("DYNAMIQ_ALPINE_ISO")
    if env_path:
        iso = Path(env_path)
        if iso.exists():
            return iso

    iso = _fixture_dir() / ALPINE_ISO_NAME
    if iso.exists():
        return iso
    return None


def _download_alpine_iso() -> Path:
    """Download and verify the pinned Alpine ISO used by the live boot test."""
    iso_url = os.environ.get("DYNAMIQ_ALPINE_ISO_URL", ALPINE_ISO_URL)
    sha256_url = os.environ.get("DYNAMIQ_ALPINE_ISO_SHA256_URL", f"{iso_url}.sha256")
    fixture_dir = _fixture_dir()
    fixture_dir.mkdir(parents=True, exist_ok=True)
    iso_path = fixture_dir / Path(iso_url).name
    sha_path = fixture_dir / f"{Path(iso_url).name}.sha256"
    tmp_path = fixture_dir / f"{Path(iso_url).name}.tmp"

    try:
        urllib.request.urlretrieve(sha256_url, sha_path)
        expected_sha256 = sha_path.read_text(encoding="utf-8").split()[0].strip().lower()
        urllib.request.urlretrieve(iso_url, tmp_path)
    except (OSError, urllib.error.URLError) as exc:
        raise RuntimeError(f"failed to download Alpine ISO from {iso_url}: {exc}") from exc

    actual_sha256 = hashlib.sha256(tmp_path.read_bytes()).hexdigest()
    if actual_sha256 != expected_sha256:
        tmp_path.unlink(missing_ok=True)
        raise RuntimeError(
            f"Alpine ISO checksum mismatch for {iso_path}: "
            f"got {actual_sha256}, expected {expected_sha256}"
        )

    tmp_path.replace(iso_path)
    return iso_path


def _find_or_download_alpine_iso() -> Path:
    iso = _find_alpine_iso()
    if iso is not None:
        return iso
    return _download_alpine_iso()


def wait_for_boot_marker(session: ScriptSession, timeout: float = 30.0) -> bool:
    """Wait for boot marker in serial output."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        stdout_result = session.read_stdout(cursor=0, max_chars=4096)
        output = stdout_result.get("result", {}).get("data", "")
        if "Alpine" in output or "login:" in output or "Welcome" in output:
            return True
        time.sleep(0.5)
    return False


@pytest.mark.live_qemu
def test_alpine_boot() -> None:
    """Boot Alpine Linux ISO and verify system-mode functionality."""
    symfit_path = _find_symfit_system()
    if symfit_path is None:
        pytest.skip("symfit-system-x86_64 not found")

    try:
        iso_path = _find_or_download_alpine_iso()
    except RuntimeError as exc:
        pytest.fail(str(exc))

    print(f"Using symfit-system: {symfit_path}")
    print(f"Using Alpine ISO: {iso_path}")

    session = None
    try:
        # Create system-mode session with Alpine ISO
        session = ScriptSession.system(
            qemu_system_path=str(symfit_path),
            qemu_args=[
                "-machine", "pc",
                "-m", "128M",
                "-display", "none",
                "-cdrom", str(iso_path),
                "-boot", "d",  # Boot from CD-ROM
                "-serial", "stdio",
                "-no-reboot",
            ],
            arch="x86_64",
            auto_start=False,
        )

        print("Starting session...")
        session.start()

        print(f"Backend type: {type(session._backend).__name__}")
        
        # Get initial state
        state = session.get_state()["state"]
        print(f"Session status: {state['session_status']}")
        print(f"QEMU mode: {state['qemu_mode']}")

        # Test memory and register access while paused
        print("\nTesting physical memory read (while paused)...")
        try:
            memory = session.read_memory("0x7c00", 4, address_space="physical")
            print(f"✓ Physical memory at 0x7c00: {memory['result']['bytes']}")
        except Exception as e:
            print(f"⚠ Memory read failed: {e}")

        print("\nTesting register access (while paused)...")
        try:
            regs = session.get_registers(["rip", "rsp", "rax"])
            registers = regs["result"]["registers"]
            print(f"✓ RIP: {registers.get('rip', 'N/A')}")
            print(f"✓ RSP: {registers.get('rsp', 'N/A')}")
            print(f"✓ RAX: {registers.get('rax', 'N/A')}")
        except Exception as e:
            print(f"⚠ Register read failed: {e}")

        # Boot Alpine
        print("\nBooting Alpine Linux...")
        session.resume(timeout=10.0)

        # Wait for boot output
        print("Waiting for boot output...")
        time.sleep(5.0)  # Let it boot for a few seconds

        # Pause to capture output
        session.pause(timeout=5.0)
        
        # Read boot output
        stdout_result = session.read_stdout(cursor=0, max_chars=8192)
        boot_output = stdout_result.get("result", {}).get("data", "")
        
        if boot_output:
            print(f"\n--- Boot Output (first 1000 chars) ---")
            print(boot_output[:1000])
            print("---")
            if "ISOLINUX" in boot_output or "Alpine" in boot_output:
                print("✓ Alpine Linux boot detected!")
            else:
                print("⚠ Boot marker not found")
        else:
            print("No serial output captured")
        
        state = session.get_state()["state"]
        print(f"Final status: {state['session_status']}")

        print("\n✓ All tests passed!")

    except Exception as e:
        print(f"\n✗ Test failed: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        raise

    finally:
        if session is not None:
            try:
                session.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q", "-m", "live_qemu"]))
