"""Native omp config CLI client for managed role records."""
from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from pathlib import Path
from typing import Any

MANAGED_ROLE_KEY = "modelRoles"
MANAGED_CHAIN_KEY = "retry.fallbackChains"
OVERRIDES_KEY = "task.agentModelOverrides"


class OmpConfigError(RuntimeError):
    """A native omp config command failed or returned unusable output."""


class OmpConfigClient:
    """Run the native omp config CLI for one binary path.

    Record keys are read and written as whole records: `config get` returns
    the record mapping, `config set` replaces it with one JSON document.
    """

    def __init__(self, binary: str | Path, timeout: float = 30.0) -> None:
        self.binary = str(binary)
        self.timeout = timeout

    def get(self, key: str) -> dict[str, Any]:
        payload = self._run("get", key, "--json")
        if not isinstance(payload, dict):
            raise OmpConfigError(f"config get {key} did not return an object")
        value = payload.get("value")
        if not isinstance(value, dict):
            raise OmpConfigError(f"config get {key} did not return a record")
        return value

    def set(self, key: str, value: Mapping[str, Any]) -> None:
        self._run("set", key, json.dumps(value, sort_keys=True), expect_json=False)

    def _run(self, *arguments: str, expect_json: bool = True) -> Any:
        command = [self.binary, "config", *arguments]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise OmpConfigError(f"config command timed out: {' '.join(command)}") from exc
        if completed.returncode != 0:
            detail = completed.stderr.strip() or completed.stdout.strip()
            raise OmpConfigError(
                f"config {arguments[0]} {arguments[1]} failed "
                f"({completed.returncode}): {detail}"
            )
        if not expect_json:
            return None
        try:
            return json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise OmpConfigError(f"config output was not JSON: {completed.stdout[:200]!r}") from exc
