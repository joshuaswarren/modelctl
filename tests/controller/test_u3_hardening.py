from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from modelctl.controller.api import Controller, create_app
from modelctl.controller.auth import PrincipalRegistry
from modelctl.controller.replication import ReplicationMessage
from modelctl.policy.signing import PolicySigner, SignedEnvelope

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
TOKEN = "fleet-test-token"
SCOPES = (
    "event:write",
    "policy:write",
    "replication:write",
    "controller:promote",
)


def setup() -> tuple[PrincipalRegistry, PolicySigner, PolicySigner]:
    registry = PrincipalRegistry()
    writers: list[PolicySigner] = []
    for key_id, scopes in (("writer", SCOPES), ("replicator", ("replication:write",))):
        private = ed25519.Ed25519PrivateKey.generate()
        registry.register(key_id, private.public_key(), scopes)
        writers.append(PolicySigner(private, key_id))
    return registry, writers[0], writers[1]


def signed(signer: PolicySigner, payload: dict[str, object], sequence: int, operation_id: str) -> SignedEnvelope:
    return signer.sign(
        {**payload, "operationId": operation_id},
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce=f"{signer.key_id}-{sequence}-{operation_id}",
        sequence=sequence,
    )


class PrepareFailurePeer:
    def prepare_replication(self, message: ReplicationMessage, envelope: SignedEnvelope) -> bool:
        return False

    def commit_replication(self, operation_id: str) -> bool:
        raise AssertionError("commit must not run after prepare failure")

    def abort_replication(self, operation_id: str) -> None:
        return None


def make_active(
    path: Path,
    registry: PrincipalRegistry,
    replicator: PolicySigner,
    peer: object,
) -> Controller:
    return Controller(
        path,
        controller_id="active",
        role="active",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        peer=peer,
        replication_signer=replicator,
        now=lambda: NOW,
    )


def test_standby_prepare_failure_does_not_commit_active(tmp_path: Path) -> None:
    registry, writer, replicator = setup()
    active = make_active(tmp_path / "active.db", registry, replicator, PrepareFailurePeer())
    client = TestClient(create_app(active))

    response = client.post(
        "/v1/events",
        json=signed(writer, {"subject": "not-committed"}, 1, "op-prepare-failure").model_dump(
            mode="json", by_alias=True
        ),
    )

    assert response.status_code == 503
    assert active.operation_count("op-prepare-failure") == 0
    assert not any(event["subject"] == "event" for event in active.events())
    assert active.outbound_sequence("replicator") == 1


def test_local_commit_failure_leaves_both_sides_uncommitted(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    registry, writer, replicator = setup()
    standby = Controller(
        tmp_path / "standby.db",
        controller_id="standby",
        role="standby",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        now=lambda: NOW,
    )
    active = make_active(tmp_path / "active.db", registry, replicator, standby)

    def fail_commit(*args: object, **kwargs: object) -> None:
        raise RuntimeError("local storage failure")

    monkeypatch.setattr(active, "_apply_payload_tx", fail_commit)
    response = TestClient(create_app(active)).post(
        "/v1/events",
        json=signed(writer, {"subject": "not-committed"}, 1, "op-local-failure").model_dump(
            mode="json", by_alias=True
        ),
    )

    assert response.status_code == 503
    assert active.operation_count("op-local-failure") == 0
    assert standby.operation_count("op-local-failure") == 0


def test_operation_id_requires_same_authenticated_envelope(tmp_path: Path) -> None:
    registry, writer, replicator = setup()
    standby = Controller(
        tmp_path / "standby.db",
        controller_id="standby",
        role="standby",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        now=lambda: NOW,
    )
    active = make_active(tmp_path / "active.db", registry, replicator, standby)
    client = TestClient(create_app(active))
    first = signed(writer, {"subject": "first"}, 1, "same-operation")
    different = signed(writer, {"subject": "different"}, 2, "same-operation")

    assert client.post("/v1/events", json=first.model_dump(mode="json", by_alias=True)).status_code == 200
    assert client.post("/v1/events", json=different.model_dump(mode="json", by_alias=True)).status_code == 409
    assert active.operation_count("same-operation") == 1
    assert sum(event["subject"] == "event" for event in active.events()) == 1


def test_unauthenticated_replication_inner_envelope_cannot_consume_replay(tmp_path: Path) -> None:
    registry, writer, replicator = setup()
    standby = Controller(
        tmp_path / "standby.db",
        controller_id="standby",
        role="standby",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        now=lambda: NOW,
    )
    unknown_private = ed25519.Ed25519PrivateKey.generate()
    unknown = PolicySigner(unknown_private, "unknown")
    inner = signed(unknown, {"version": 1}, 1, "inner-operation")
    message = standby.replication_message(
        "active",
        1,
        1,
        "inner-operation",
        {
            "kind": "policy",
            "payload": {"version": 1},
            "policyEnvelope": inner.model_dump(mode="json", by_alias=True),
        },
    )
    outer = replicator.sign(
        message.model_dump(mode="json", by_alias=True),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce="replication-1",
        sequence=1,
    )

    assert standby.apply_replication(message, outer) is False
    assert standby.replay_state() == {"nonces": [], "sequences": {}}
    assert writer.key_id == "writer"


def test_replication_sequence_survives_controller_restart(tmp_path: Path) -> None:
    registry, writer, replicator = setup()
    standby = Controller(
        tmp_path / "standby.db",
        controller_id="standby",
        role="standby",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        now=lambda: NOW,
    )
    active = make_active(tmp_path / "active.db", registry, replicator, standby)
    client = TestClient(create_app(active))
    first = signed(writer, {"subject": "first"}, 1, "first-operation")
    assert client.post("/v1/events", json=first.model_dump(mode="json", by_alias=True)).status_code == 200
    active.store.close()

    restarted = make_active(tmp_path / "active.db", registry, replicator, standby)
    second = signed(writer, {"subject": "second"}, 2, "second-operation")
    assert TestClient(create_app(restarted)).post(
        "/v1/events", json=second.model_dump(mode="json", by_alias=True)
    ).status_code == 200
    assert standby.replay_state()["sequences"]["replicator"] == 2


def test_status_redacts_camel_case_secret_fields(tmp_path: Path) -> None:
    registry, writer, replicator = setup()
    standby = Controller(
        tmp_path / "standby.db",
        controller_id="standby",
        role="standby",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        now=lambda: NOW,
    )
    active = make_active(tmp_path / "active.db", registry, replicator, standby)
    response = TestClient(create_app(active)).post(
        "/v1/events",
        json=signed(
            writer,
            {"subject": "secret", "apiKey": "do-not-return", "bearerToken": "also-secret"},
            1,
            "secret-operation",
        ).model_dump(mode="json", by_alias=True),
    )

    assert response.status_code == 200
    status = active.status()
    detail = next(event["detail"] for event in active.events() if event["subject"] == "event")
    assert detail["apiKey"] == "[redacted]"
    assert detail["bearerToken"] == "[redacted]"
    assert "do-not-return" not in str(status)
    assert "also-secret" not in str(status)
