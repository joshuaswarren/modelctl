from __future__ import annotations

import json
import subprocess
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest

from modelctl.adapters.litellm import (
    BEGIN_MARKER,
    END_MARKER,
    FileConfigStore,
    FileLockProvider,
    JsonlReceiptSink,
    LiteLLMRoute,
    RuntimeDecision,
    SubprocessRuntimeController,
    SubprocessSmokeVerifier,
    apply,
)
from modelctl.domain.engine import EngineHealth, PhysicalEngine
from modelctl.domain.policy import PolicyBundle


def test_concrete_apply_writes_backup_and_durable_receipt(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_text(f"{BEGIN_MARKER}\nold\n{END_MARKER}\n", encoding="utf-8")
    policy = PolicyBundle(
        engines=[
            PhysicalEngine(
                id="engine",
                host="engine.example.test",
                baseUrl="https://engine.example.test:8000/v1",
                aliases=["automatic"],
                resident_models=["openai/generic-model"],
                health=EngineHealth.HEALTHY,
            )
        ]
    )
    sink = JsonlReceiptSink(tmp_path / "events.jsonl")
    runtime = Runtime()
    smoke = Smoke()

    receipt = apply(
        config_path,
        policy,
        routes=[LiteLLMRoute("automatic", "engine", "openai/generic-model")],
        expected_original_digest=sha256(config_path.read_bytes()).hexdigest(),
        store=FileConfigStore(),
        lock=FileLockProvider(),
        runtime=runtime,
        smoke=smoke,
        receipts=sink,
    )

    assert b'model_name: "automatic"' in config_path.read_bytes()
    assert receipt.backup_path is not None
    assert receipt.backup_path.read_bytes() == f"{BEGIN_MARKER}\nold\n{END_MARKER}\n".encode()
    assert len((tmp_path / "events.jsonl").read_text(encoding="utf-8").splitlines()) == 1
    assert runtime.updated is True
    assert smoke.distributions == receipt.distributions


def test_atomic_write_preserves_config_permissions(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_bytes(b"original")
    config_path.chmod(0o640)

    FileConfigStore().atomic_write(config_path, b"replacement")

    assert config_path.read_bytes() == b"replacement"
    assert config_path.stat().st_mode & 0o777 == 0o640


def test_subprocess_runtime_and_smoke_use_exact_argv(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[tuple[tuple[str, ...], dict[str, Any]]] = []

    def run(command: tuple[str, ...], **arguments: Any) -> None:
        calls.append((command, arguments))

    monkeypatch.setattr(subprocess, "run", run)
    runtime = SubprocessRuntimeController(("systemctl", "restart", "litellm"))
    smoke = SubprocessSmokeVerifier(("python3", "smoke.py"))

    assert runtime.update(tmp_path / "config.yaml", "bundle").restart is True
    runtime.restart_service()
    smoke.verify({"gpu": {"interactive": 1, "serving": 3}})

    assert calls[0] == (("systemctl", "restart", "litellm"), {"check": True})
    assert calls[1][0] == ("python3", "smoke.py")
    assert calls[1][1]["check"] is True
    assert json.loads(calls[1][1]["env"]["MODELCTL_EXPECTED_DISTRIBUTION"]) == {
        "gpu": {"interactive": 1, "serving": 3}
    }


class Runtime:
    updated = False

    def update(self, config_path: Path, bundle_id: str) -> RuntimeDecision:
        self.updated = True
        return RuntimeDecision(restart=False)

    def restart_service(self) -> None:
        raise AssertionError("restart was not requested")


class Smoke:
    distributions: Mapping[str, Mapping[str, int]] | None = None

    def verify(self, distributions: Mapping[str, Mapping[str, int]]) -> None:
        self.distributions = distributions
