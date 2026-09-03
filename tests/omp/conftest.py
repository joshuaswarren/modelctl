"""Shared fake omp executable proving native config call behavior."""
from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

from pytest import fixture

_FAKE_OMP = '''#!/usr/bin/env python3
import json
import sys

STATE_PATH = {state_path!r}

with open(STATE_PATH, encoding="utf-8") as handle:
    state = json.load(handle)


def save() -> None:
    with open(STATE_PATH, "w", encoding="utf-8") as handle:
        json.dump(state, handle)


args = sys.argv[1:]
state.setdefault("calls", []).append(args)

if len(args) == 4 and args[0] == "config" and args[1] == "get" and args[3] == "--json":
    key = args[2]
    value = state.get(key, {{}})
    if (
        state.get("tamperReadback")
        and any(call[1] == "set" for call in state.get("calls", []) if len(call) >= 3)
        and key in ("modelRoles", "retry.fallbackChains")
    ):
        value = {{"tampered-by-fake": True}}
        state["tamperReadback"] = False
    print(json.dumps({{"key": key, "value": value, "type": "record", "description": ""}}))
    save()
    sys.exit(0)

if len(args) == 4 and args[0] == "config" and args[1] == "set":
    key = args[2]
    budget = state.get("failSetForKey", {{}}).get(key, 0)
    if budget > 0:
        state["failSetForKey"][key] = budget - 1
        save()
        print(f"fake omp refused to set {{key}}", file=sys.stderr)
        sys.exit(1)
    if state.get("tamperOverridesOnSet"):
        state["task.agentModelOverrides"] = {{"external": "disturbed"}}
    try:
        state[key] = json.loads(args[3])
    except json.JSONDecodeError:
        print("Error: Invalid record JSON", file=sys.stderr)
        sys.exit(1)
    save()
    print(f"Set {{key}}")
    sys.exit(0)

print("unknown invocation", file=sys.stderr)
sys.exit(3)
'''


class FakeOmp:
    """Temporary omp executable with inspectable JSON state."""

    def __init__(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        self.state_path = directory / "state.json"
        self.binary = directory / "omp"
        self.binary.write_text(_FAKE_OMP.format(state_path=str(self.state_path)), encoding="utf-8")
        mode = self.binary.stat().st_mode
        self.binary.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        self.state: dict[str, Any] = {}
        self._flush()

    def seed(self, **records: Any) -> None:
        self.state.update(records)
        self._flush()

    def reload(self) -> dict[str, Any]:
        self.state = json.loads(self.state_path.read_text(encoding="utf-8"))
        return self.state

    def config_calls(self) -> list[tuple[str, str]]:
        calls = [entry for entry in self.reload().get("calls", []) if len(entry) >= 3]
        return [(entry[1], entry[2]) for entry in calls]

    def record(self, key: str) -> dict[str, Any]:
        return self.reload().get(key, {})

    def _flush(self) -> None:
        self.state_path.write_text(json.dumps(self.state), encoding="utf-8")


@fixture
def fake_omp(tmp_path: Path) -> FakeOmp:
    return FakeOmp(tmp_path / "bin")


@fixture
def seeded_fake(fake_omp: FakeOmp) -> FakeOmp:
    """Native state holding unmanaged keys an operator would fight to keep."""
    fake_omp.seed(
        **{
            "modelRoles": {"default": "native/default:high", "unmanaged-role": "native/keeper"},
            "retry.fallbackChains": {
                "default": ["native/one", "native/two"],
                "unmanaged-chain": ["keep/me"],
            },
            "task.agentModelOverrides": {"reviewer": "@smol"},
        }
    )
    return fake_omp
