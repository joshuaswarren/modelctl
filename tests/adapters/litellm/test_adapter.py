from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
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
from modelctl.domain.engine import EngineHealth, EngineState, PhysicalEngine
from modelctl.domain.policy import PolicyBundle


def engine(
    engine_id: str,
    aliases: list[str],
    *,
    max_slots: int = 8,
    interactive_reserved: int = 2,
    active_slots: int = 0,
    state: EngineState = EngineState.ACTIVE,
    health: EngineHealth = EngineHealth.HEALTHY,
) -> PhysicalEngine:
    return PhysicalEngine(
        id=engine_id,
        host=f"{engine_id}.example.test",
        baseUrl=f"https://{engine_id}.example.test:8000/v1",
        aliases=aliases,
        resident_models=["openai/generic-model"],
        max_slots=max_slots,
        interactive_reserved=interactive_reserved,
        active_slots=active_slots,
        state=state,
        health=health,
    )


def policy(*engines: PhysicalEngine) -> PolicyBundle:
    return PolicyBundle(engines=list(engines))


def marked_config(body: str = "manual: keep\n") -> bytes:
    return (
        b"before\r\n"
        + BEGIN_MARKER.encode()
        + b"\r\n"
        + body.encode()
        + END_MARKER.encode()
        + b"\r\n"
        + b"manual_model: keep\n"
    )


def test_render_is_deterministic_and_preserves_unmanaged_bytes() -> None:
    source = marked_config()
    target = policy(engine("gpu", ["zeta", "alpha"], max_slots=7, interactive_reserved=2))

    first = render_config(source, target)
    second = render_config(source, target)

    assert first == second
    assert first.startswith(b"before\r\n")
    assert first.endswith(b"\r\nmanual_model: keep\n")
    assert b"max_parallel_requests: 2" in first
    assert b"max_parallel_requests: 3" in first
    assert b'api_base: "https://gpu.example.test:8000/v1"' in first
    assert b'id: "gpu:alpha"' in first
    assert b'id: "gpu:zeta"' in first
    assert first.count(BEGIN_MARKER.encode()) == 1
    assert first.count(END_MARKER.encode()) == 1


def test_render_rejects_missing_duplicate_and_malformed_markers() -> None:
    target = policy(engine("gpu", ["alpha"]))

    sources = (
        b"no markers\n",
        marked_config() + marked_config(),
        b"# BEGIN modelctl managed extra\n# END modelctl managed\n",
    )
    for source in sources:
        with pytest.raises(ValueError, match="marker"):
            render_config(source, target)


def test_render_excludes_unavailable_engines_and_manual_aliases() -> None:
    target = policy(
        engine("active", ["automatic", "manual"]),
        engine("draining", ["drain"], state=EngineState.DRAINING),
        engine("training", ["train"], state=EngineState.TRAINING),
        engine("offline", ["off"], state=EngineState.OFFLINE),
        engine("bad", ["bad"], health=EngineHealth.UNHEALTHY),
    )
    routes = [
        LiteLLMRoute("automatic", "active", "openai/generic-model"),
        LiteLLMRoute("manual", "active", "openai/manual", manual=True),
    ]

    rendered = render_config(marked_config(), target, routes=routes).decode()

    assert 'model_name: "automatic"' in rendered
    assert 'model_name: "manual"' not in rendered
    assert 'model_name: "drain"' not in rendered
    assert 'model_name: "train"' not in rendered
    assert 'model_name: "off"' not in rendered
    assert 'model_name: "bad"' not in rendered


def test_capacity_is_calculated_once_per_physical_engine() -> None:
    target = policy(engine("gpu", ["a", "b", "c"], max_slots=5, interactive_reserved=1))

    rendered = render_config(marked_config(), target).decode()
    slots = [int(line.rsplit(":", 1)[1]) for line in rendered.splitlines() if "max_parallel_requests" in line]

    assert len(slots) == 3
    assert sum(slots) == 4
    assert sum(slots) + 1 <= 5


def test_apply_dry_run_does_not_call_side_effects(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_bytes(marked_config())
    expected = sha256(config_path.read_bytes()).hexdigest()
    recorder = RecordingRuntime()
    smoke = RecordingSmoke()
    sink = RecordingSink()

    receipt = apply(
        config_path,
        policy(engine("gpu", ["alpha"])),
        expected_original_digest=expected,
        dry_run=True,
        runtime=recorder,
        smoke=smoke,
        receipts=sink,
    )

    assert receipt.dry_run is True
    assert config_path.read_bytes() == marked_config()
    assert recorder.calls == []
    assert smoke.receipts == []
    assert sink.receipts == []


def test_apply_uses_cas_lock_backup_atomic_runtime_and_smoke(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_bytes(marked_config())
    expected = sha256(config_path.read_bytes()).hexdigest()
    lock = RecordingLock()
    store = RecordingStore()
    runtime = RecordingRuntime(restart=True)
    smoke = RecordingSmoke()
    sink = RecordingSink()

    receipt = apply(
        config_path,
        policy(engine("gpu", ["alpha"])),
        expected_original_digest=expected,
        lock=lock,
        store=store,
        runtime=runtime,
        smoke=smoke,
        receipts=sink,
        now=lambda: datetime(2026, 8, 29, tzinfo=UTC),
    )

    assert receipt.dry_run is False
    assert lock.calls == [config_path.with_name("config.yaml.lock")]
    assert store.operations[:2] == [("read", config_path), ("backup", receipt.backup_path)]
    assert runtime.calls == [(config_path, receipt.bundle_id), ("restart",)]
    assert smoke.receipts == [receipt.distributions]
    assert sink.receipts[0]["kind"] == "modelctl.litellm.apply"
    assert receipt.backup_path is not None
    assert receipt.backup_path.name == f"config.yaml.modelctl-2026-08-29-{receipt.bundle_id}.bak"


def test_apply_rejects_stale_digest_before_write(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    config_path.write_bytes(marked_config())
    store = RecordingStore()

    with pytest.raises(ApplyError, match="digest"):
        apply(
            config_path,
            policy(engine("gpu", ["alpha"])),
            expected_original_digest="stale",
            store=store,
            runtime=RecordingRuntime(),
            smoke=RecordingSmoke(),
            lock=RecordingLock(),
        )

    assert [operation for operation, _ in store.operations] == ["read"]


def test_apply_rolls_back_after_smoke_failure(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    original = marked_config()
    config_path.write_bytes(original)
    expected = sha256(original).hexdigest()
    store = RecordingStore()
    smoke = RecordingSmoke(fail=True)
    runtime = RecordingRuntime(restart=True)

    with pytest.raises(ApplyError, match="rolled back"):
        apply(
            config_path,
            policy(engine("gpu", ["alpha"])),
            expected_original_digest=expected,
            store=store,
            runtime=runtime,
            smoke=smoke,
            receipts=RecordingSink(),
        )

    assert ("restore", config_path) in store.operations
    assert config_path.read_bytes() == original
    assert runtime.calls is not None
    assert runtime.calls[1] == ("restart",)
    assert runtime.calls[2] == (config_path, expected)
    assert runtime.calls[3] == ("restart",)


def test_apply_rolls_back_when_success_receipt_cannot_be_persisted(tmp_path: Path) -> None:
    config_path = tmp_path / "config.yaml"
    original = marked_config()
    config_path.write_bytes(original)
    expected = sha256(original).hexdigest()
    runtime = RecordingRuntime()

    with pytest.raises(ApplyError, match="rolled back"):
        apply(
            config_path,
            policy(engine("gpu", ["alpha"])),
            expected_original_digest=expected,
            runtime=runtime,
            smoke=RecordingSmoke(),
            receipts=RecordingSink(fail=True),
        )

    assert config_path.read_bytes() == original
    assert runtime.calls is not None
    assert runtime.calls[-1] == (config_path, expected)


@dataclass
class RecordingRuntime:
    restart: bool = False
    calls: list[object] | None = None

    def __post_init__(self) -> None:
        self.calls = []

    def update(self, config_path: Path, bundle_id: str) -> RuntimeDecision:
        assert self.calls is not None
        self.calls.append((config_path, bundle_id))
        return RuntimeDecision(restart=self.restart)

    def restart_service(self) -> None:
        assert self.calls is not None
        self.calls.append(("restart",))


@dataclass
class RecordingSmoke:
    fail: bool = False
    receipts: list[Mapping[str, Mapping[str, int]]] | None = None

    def __post_init__(self) -> None:
        self.receipts = []

    def verify(self, distributions: Mapping[str, Mapping[str, int]]) -> None:
        assert self.receipts is not None
        self.receipts.append(distributions)
        if self.fail:
            raise RuntimeError("smoke failed")


@dataclass
class RecordingSink:
    fail: bool = False
    receipts: list[Mapping[str, object]] | None = None

    def __post_init__(self) -> None:
        self.receipts = []

    def append(self, receipt: Mapping[str, object]) -> None:
        assert self.receipts is not None
        if self.fail:
            raise OSError("receipt unavailable")
        self.receipts.append(receipt)


class RecordingLock:
    def __init__(self) -> None:
        self.calls: list[Path] = []

    def acquire(self, path: Path):
        self.calls.append(path)
        return _LockContext()


class _LockContext:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *_: object) -> None:
        return None


class RecordingStore:
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
