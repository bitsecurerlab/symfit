from __future__ import annotations

import os
import shlex
from pathlib import Path

import pytest

from dynamiq.qemu_user import QemuUserLaunchConfig


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "live_qemu: requires a real QEMU/instrumentation environment")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    run_live = os.environ.get("RUN_LIVE_QEMU") == "1"
    skip_live = pytest.mark.skip(reason="set RUN_LIVE_QEMU=1 and required IA_LIVE_* env vars to run live QEMU tests")
    for item in items:
        if "live_qemu" in item.keywords and not run_live:
            item.add_marker(skip_live)


@pytest.fixture
def live_qemu_start_kwargs() -> dict[str, object]:
    required = {
        "instrumentation_rpc_socket_path": os.environ.get("IA_LIVE_RPC_SOCKET"),
        "target": os.environ.get("IA_LIVE_TARGET"),
    }
    missing = [key for key, value in required.items() if not value]
    if missing:
        pytest.skip(f"missing required live QEMU env vars: {', '.join(missing)}")

    target_path = Path(required["target"])
    if not target_path.exists():
        pytest.skip(f"live target does not exist: {target_path}")

    args = shlex.split(os.environ.get("IA_LIVE_ARGS", ""))
    cwd = os.environ.get("IA_LIVE_CWD")
    launch = os.environ.get("IA_LIVE_LAUNCH") == "1"
    qemu_user_path = os.environ.get("IA_LIVE_QEMU_USER_PATH", "qemu-x86_64")
    qemu_args = shlex.split(os.environ.get("IA_LIVE_QEMU_ARGS", ""))

    launch_config = QemuUserLaunchConfig(
        qemu_user_path=qemu_user_path,
        target=str(target_path),
        args=args,
        cwd=cwd,
        instrumentation_event_socket=os.environ.get("IA_LIVE_EVENT_SOCKET"),
        instrumentation_rpc_socket=required["instrumentation_rpc_socket_path"],
        extra_args=qemu_args,
    )
    qemu_config = launch_config.to_backend_config(launch=launch)
    qmp_socket = os.environ.get("IA_LIVE_QMP_SOCKET")
    if qmp_socket:
        qemu_config["qmp_socket_path"] = qmp_socket

    return {
        "target": str(target_path),
        "args": args,
        "cwd": cwd,
        "qemu_config": qemu_config,
    }
