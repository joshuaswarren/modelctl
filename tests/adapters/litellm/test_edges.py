from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path

import pytest

from modelctl.adapters.litellm import (
    BEGIN_MARKER,
    END_MARKER,
    ApplyError,
    LiteLLMRoute,
    RuntimeDecision,
    apply,
    render_config,
)
from modelctl.domain.engine import EngineHealth, PhysicalEngine
from modelctl.domain.policy import PolicyBundle


def test_weighted_split_is_bounded_after_interactive_reservation() -> None:
    physical = PhysicalEngine(
        id="gpu",
        host="gpu.example.test",
        baseUrl="https://gpu.example.test:8000/v1",
        aliases=["heavy", "light"],
        resident_models=["openai/generic-model"],
        max_slots=5,
        interactive_reserved=1,
        health=EngineHealth.HEALTHY,
    )
    routes = [
        LiteLLMRoute("heavy", "gpu", "openai/generic-model", weight=3),
        LiteLLMRoute("light", "gpu", "openai/generic-model", weight=1),
    ]

    rendered = render_config(_config(), PolicyBundle(engines=[physical]), routes=routes).decode()

    assert "model_name: \"heavy\"" in rendered
    assert "max_parallel_requests: 3" in rendered
    assert "model_name: \"light\"" in rendered
    assert "max_parallel_requests: 1" in rendered



def test_interactive_tier_is_allocated_before_serving_aliases() -> None:
    physical = PhysicalEngine(
        id="gpu",
        host="gpu.example.test",
        baseUrl="https://gpu.example.test:8000/v1",
        aliases=["interactive", "heavy", "light"],
        resident_models=["openai/generic-model"],
        max_slots=5,
        interactive_reserved=2,
        health=EngineHealth.HEALTHY,
    )
    routes = [
        LiteLLMRoute("interactive", "gpu", "openai/generic-model", interactive=True),
        LiteLLMRoute("heavy", "gpu", "openai/generic-model", weight=2),
        LiteLLMRoute("light", "gpu", "openai/generic-model"),
    ]

    rendered = render_config(_config(), PolicyBundle(engines=[physical]), routes=routes).decode()

    entries = rendered.split("- model_name: ")[1:]
    slots = {
        entry.splitlines()[0].strip('"'): int(
            next(line for line in entry.splitlines() if "max_parallel_requests" in line).rsplit(":", 1)[1]
        )
        for entry in entries
    }
    assert slots == {"heavy": 2, "interactive": 2, "light": 1}
    assert sum(slots.values()) == physical.max_slots

def test_render_rejects_end_marker_before_begin_marker() -> None:
    source = f"{END_MARKER}\n{BEGIN_MARKER}\n".encode()
    physical = PhysicalEngine(
        id="gpu",
        host="gpu.example.test",
        baseUrl="https://gpu.example.test:8000/v1",
        aliases=["auto"],
        resident_models=["openai/generic-model"],
        health=EngineHealth.HEALTHY,
    )

    with pytest.raises(ValueError, match="marker"):
        render_config(source, PolicyBundle(engines=[physical]))


def test_apply_rolls_back_when_runtime_restart_fails(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    original = _config()
    config_path.write_bytes(original)
    store = Store()

    with pytest.raises(ApplyError, match="rollback failed"):
        apply(
            config_path,
            _policy(),
            expected_original_digest=sha256(original).hexdigest(),
            store=store,
            runtime=Runtime(fail=True),
            smoke=Smoke(),
            receipts=Sink(),
        )

    assert config_path.read_bytes() == original
    assert ("restore", config_path) in store.operations


def _config() -> bytes:
    return f"before\n{BEGIN_MARKER}\nold\n{END_MARKER}\nafter\n".encode()


def _policy() -> PolicyBundle:
    return PolicyBundle(
        engines=[
            PhysicalEngine(
                id="gpu",
                host="gpu.example.test",
                baseUrl="https://gpu.example.test:8000/v1",
                aliases=["auto"],
                resident_models=["openai/generic-model"],
                health=EngineHealth.HEALTHY,
            )
        ]
    )


@dataclass
class Runtime:
    fail: bool = False

    def update(self, config_path: Path, bundle_id: str) -> RuntimeDecision:
        return RuntimeDecision(restart=self.fail)

    def restart_service(self) -> None:
        raise RuntimeError("restart failed")


class Smoke:
    def verify(self, distributions: Mapping[str, Mapping[str, int]]) -> None:
        return None


class Sink:
    def append(self, receipt: Mapping[str, object]) -> None:
        return None


class Store:
    def __init__(self) -> None:
        self.operations: list[tuple[str, Path]] = []

    def read(self, path: Path) -> bytes:
        self.operations.append(("read", path))
        return path.read_bytes()

    def backup(self, source: Path, destination: Path) -> None:
        self.operations.append(("backup", destination))
        destination.write_bytes(source.read_bytes())

    def atomic_write(self, path: Path, content: bytes) -> None:
        self.operations.append(("write", path))
        path.write_bytes(content)

    def restore(self, source: Path, backup: Path) -> None:
        self.operations.append(("restore", source))
        source.write_bytes(backup.read_bytes())
