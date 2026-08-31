from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
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
)
from modelctl.domain.engine import EngineHealth, EngineState, PhysicalEngine
from modelctl.domain.policy import PolicyBundle
from modelctl.evals import (
    JsonlDecisionLog,
    LiteLLMRouteTable,
    LiteLLMRouteTarget,
    PromotionOutcome,
    PromotionPipeline,
    PromotionRequest,
)


class MemoryConfigStore:
    def __init__(self, content: bytes) -> None:
        self.content = content
        self.operations: list[str] = []
        self.backups: dict[Path, bytes] = {}

    def read(self, path: Path) -> bytes:
        self.operations.append(f"read:{path}")
        return self.content

    def backup(self, source: Path, destination: Path) -> None:
        self.operations.append(f"backup:{destination}")
        self.backups[destination] = self.content

    def atomic_write(self, path: Path, content: bytes) -> None:
        self.operations.append(f"write:{path}")
        self.content = content

    def restore(self, source: Path, backup: Path) -> None:
        self.operations.append(f"restore:{backup}")
        self.content = self.backups[backup]


class RecordingLock:
    def __init__(self) -> None:
        self.paths: list[Path] = []

    @contextmanager
    def acquire(self, path: Path) -> Iterator[None]:
        self.paths.append(path)
        yield


class RecordingRuntime:
    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []

    def update(self, config_path: Path, bundle_id: str) -> RuntimeDecision:
        self.calls.append((config_path, bundle_id))
        return RuntimeDecision(restart=False)

    def restart_service(self) -> None:
        self.calls.append(("restart",))


class RecordingSmoke:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.distributions: list[Mapping[str, Mapping[str, int]]] = []

    def verify(self, distributions: Mapping[str, Mapping[str, int]]) -> None:
        self.distributions.append(distributions)
        if self.fail:
            raise RuntimeError("smoke failed")


class RecordingSink:
    def __init__(self) -> None:
        self.receipts: list[Mapping[str, object]] = []

    def append(self, receipt: Mapping[str, object]) -> None:
        self.receipts.append(receipt)


def config() -> bytes:
    return (
        b"before\n"
        + BEGIN_MARKER.encode()
        + b"\nold\n"
        + END_MARKER.encode()
        + b"\nafter\n"
    )


def policy(alias: str) -> PolicyBundle:
    engine = PhysicalEngine(
        id="gpu",
        host="gpu.example.test",
        baseUrl="https://gpu.example.test:8000/v1",
        aliases=[alias],
        resident_models=["openai/generic-model"],
        max_slots=4,
        interactive_reserved=0,
        active_slots=0,
        state=EngineState.ACTIVE,
        health=EngineHealth.HEALTHY,
    )
    return PolicyBundle(
        engines=[engine],
        routes={
            "aliases": {
                alias: {"engineId": "gpu", "model": "openai/generic-model"},
            },
        },
    )

def make_table(
    *,
    smoke: RecordingSmoke | None = None,
) -> tuple[
    LiteLLMRouteTable,
    MemoryConfigStore,
    RecordingRuntime,
    RecordingSmoke,
    RecordingSink,
]:
    source = config()
    store = MemoryConfigStore(source)
    runtime = RecordingRuntime()
    verifier = smoke or RecordingSmoke()
    sink = RecordingSink()
    table = LiteLLMRouteTable(
        "stable-route",
        {
            "stable-route": LiteLLMRouteTarget(policy("stable")),
            "candidate-route": LiteLLMRouteTarget(
                policy("candidate"),
                LiteLLMRoute("candidate", "gpu", "openai/generic-model"),
            ),
        },
        config_path=Path("config.yaml"),
        expected_config_digest=sha256(source).hexdigest(),
        store=store,
        lock=RecordingLock(),
        runtime=runtime,
        smoke=verifier,
        receipts=sink,
        now=lambda: datetime(2026, 8, 30, tzinfo=UTC),
    )
    return table, store, runtime, verifier, sink


def test_candidate_and_rollback_apply_with_digest_advance() -> None:
    table, store, runtime, smoke, sink = make_table()
    initial_digest = table.expected_config_digest

    table.activate("candidate-route")
    candidate_digest = table.expected_config_digest
    assert table.current_route == "candidate-route"
    assert candidate_digest != initial_digest
    assert candidate_digest == sha256(store.content).hexdigest()
    assert b'model_name: "candidate"' in store.content

    table.rollback("stable-route")
    assert table.current_route == "stable-route"
    assert table.expected_config_digest == sha256(store.content).hexdigest()
    assert table.expected_config_digest != candidate_digest
    assert b'model_name: "stable"' in store.content
    assert len(runtime.calls) == 2
    assert len(smoke.distributions) == 2
    assert len(sink.receipts) == 2
    assert sink.receipts[1]["originalDigest"] == candidate_digest


def test_missing_route_rejects_before_any_mutation() -> None:
    table, store, runtime, smoke, sink = make_table()
    before = (table.current_route, table.expected_config_digest, store.content, list(store.operations))

    with pytest.raises(ValueError, match="route is not configured"):
        table.activate("missing-route")

    assert (table.current_route, table.expected_config_digest, store.content, store.operations) == before
    assert runtime.calls == []
    assert smoke.distributions == []
    assert sink.receipts == []


def test_failed_apply_preserves_route_state() -> None:
    failing_smoke = RecordingSmoke(fail=True)
    table, store, runtime, _smoke, sink = make_table(smoke=failing_smoke)
    source = store.content
    initial_digest = table.expected_config_digest

    with pytest.raises(ApplyError, match="smoke failed"):
        table.activate("candidate-route")

    assert table.current_route == "stable-route"
    assert table.history == []
    assert table.expected_config_digest == initial_digest
    assert table.last_receipt is None
    assert store.content == source
    assert len(runtime.calls) == 2
    assert runtime.calls[0][0] == Path("config.yaml")
    assert runtime.calls[0][1] == sink.receipts[0]["bundleId"]
    assert runtime.calls[1] == (Path("config.yaml"), initial_digest)
    assert len(sink.receipts) == 1


def test_promotion_decision_is_durable_before_real_adapter_apply(tmp_path: Path) -> None:
    decision_path = tmp_path / "decisions.jsonl"
    decisions = JsonlDecisionLog(decision_path)

    class OrderedStore(MemoryConfigStore):
        def atomic_write(self, path: Path, content: bytes) -> None:
            assert decisions.records()
            super().atomic_write(path, content)

    source = config()
    store = OrderedStore(source)
    table = LiteLLMRouteTable(
        "stable-route",
        {
            "stable-route": LiteLLMRouteTarget(policy("stable")),
            "good-route": LiteLLMRouteTarget(policy("good")),
        },
        config_path=Path("config.yaml"),
        expected_config_digest=sha256(source).hexdigest(),
        store=store,
        lock=RecordingLock(),
        runtime=RecordingRuntime(),
        smoke=RecordingSmoke(),
        receipts=RecordingSink(),
        now=lambda: datetime(2026, 8, 30, tzinfo=UTC),
    )
    fixture = json.loads(Path("fixtures/evals/good_candidate.json").read_text(encoding="utf-8"))

    result = PromotionPipeline(table, decisions=decisions).run(PromotionRequest.from_fixture(fixture))

    assert result.decision.outcome is PromotionOutcome.PROMOTED
    assert table.current_route == "good-route"
    assert len(decisions.records()) == 1
