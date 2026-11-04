from __future__ import annotations

from typing import Any

from .client import QmpClient


class QmpController:
    def __init__(self, client: QmpClient) -> None:
        self.client = client
        self.cpu_index: int | None = None

    def connect(self) -> dict[str, Any]:
        return self.client.connect()

    def resume(self) -> dict[str, Any]:
        return self.client.execute("cont")

    def pause(self) -> dict[str, Any]:
        return self.client.execute("stop")

    def query_status(self) -> dict[str, Any]:
        return self.client.execute("query-status")

    def execute(self, command: str, arguments: dict[str, Any] | None = None) -> Any:
        return self.client.execute(command, arguments)

    def save_snapshot(self, name: str) -> dict[str, Any]:
        return self.client.execute("savevm", {"name": name})

    def load_snapshot(self, name: str) -> dict[str, Any]:
        return self.client.execute("loadvm", {"name": name})

    def select_cpu(self, cpu_index: int) -> Any:
        # Each human-monitor-command creates a temporary monitor. Validate the
        # CPU through QMP, then supply its index on every subsequent HMP call.
        result = self.client.execute("human-monitor-command", {
            "command-line": "info cpus", "cpu-index": cpu_index,
        })
        self.cpu_index = cpu_index
        return result

    def monitor_command(self, command_line: str) -> Any:
        arguments: dict[str, Any] = {"command-line": command_line}
        if self.cpu_index is not None:
            arguments["cpu-index"] = self.cpu_index
        return self.client.execute("human-monitor-command", arguments)

    def close(self) -> None:
        self.client.close()
