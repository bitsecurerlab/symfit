from __future__ import annotations

from typing import Any

from .client import QmpClient


class QmpController:
    def __init__(self, client: QmpClient) -> None:
        self.client = client

    def connect(self) -> dict[str, Any]:
        return self.client.connect()

    def resume(self) -> dict[str, Any]:
        return self.client.execute("cont")

    def pause(self) -> dict[str, Any]:
        return self.client.execute("stop")

    def query_status(self) -> dict[str, Any]:
        return self.client.execute("query-status")

    def save_snapshot(self, name: str) -> dict[str, Any]:
        return self.client.execute("savevm", {"name": name})

    def load_snapshot(self, name: str) -> dict[str, Any]:
        return self.client.execute("loadvm", {"name": name})

    def monitor_command(self, command_line: str) -> dict[str, Any]:
        return self.client.execute("human-monitor-command", {"command-line": command_line})

    def close(self) -> None:
        self.client.close()
