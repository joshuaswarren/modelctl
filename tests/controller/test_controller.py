from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from modelctl.controller.api import Controller, create_app
from modelctl.controller.auth import PrincipalRegistry
from modelctl.policy.signing import PolicySigner

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
TOKEN = "fleet-test-token"


def signer_and_registry(*scopes: str) -> tuple[PolicySigner, PrincipalRegistry]:
    private = ed25519.Ed25519PrivateKey.generate()
    signer = PolicySigner(private, "writer")
    registry = PrincipalRegistry()
    registry.register("writer", private.public_key(), scopes)
    return signer, registry


def test_reads_require_constant_time_fleet_token(tmp_path: Path) -> None:
    signer, registry = signer_and_registry("event:write")
    controller = Controller(
        tmp_path / "controller.db",
        controller_id="active",
        role="active",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        now=lambda: NOW,
    )
    client = TestClient(create_app(controller))

    assert client.get("/health").status_code == 401
    assert client.get("/v1/status", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/v1/status", headers={"Authorization": f"Bearer {TOKEN}"}).status_code == 200
    assert signer.key_id == "writer"


def test_scope_rejection_does_not_consume_replay_state(tmp_path: Path) -> None:
    signer, registry = signer_and_registry("event:write")
    replication_private = ed25519.Ed25519PrivateKey.generate()
    registry.register("replicator", replication_private.public_key(), ("replication:write",))
    peer = Controller(
        tmp_path / "peer.db",
        controller_id="standby",
        role="standby",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        now=lambda: NOW,
    )
    controller = Controller(
        tmp_path / "controller.db",
        controller_id="active",
        role="active",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        now=lambda: NOW,
        peer=peer,
        replication_signer=PolicySigner(replication_private, "replicator"),
    )
    client = TestClient(create_app(controller))
    envelope = signer.sign(
        {"subsystem": "test", "severity": "info", "subject": "one"},
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce="scope-retry",
        sequence=1,
    )

    assert client.post("/v1/quota", json=envelope.model_dump(mode="json", by_alias=True)).status_code == 403
    assert client.post("/v1/events", json=envelope.model_dump(mode="json", by_alias=True)).status_code == 200


def test_expired_and_future_envelopes_are_rejected_without_replay_consumption(tmp_path: Path) -> None:
    signer, registry = signer_and_registry("event:write")
    controller = Controller(
        tmp_path / "controller.db",
        controller_id="active",
        role="active",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        now=lambda: NOW,
    )
    client = TestClient(create_app(controller))
    expired = signer.sign(
        {"subject": "expired"},
        issued_at=NOW - timedelta(minutes=10),
        expires_at=NOW - timedelta(minutes=1),
        nonce="expired",
        sequence=1,
    )
    future = signer.sign(
        {"subject": "future"},
        issued_at=NOW + timedelta(seconds=1),
        expires_at=NOW + timedelta(minutes=5),
        nonce="future",
        sequence=2,
    )

    assert client.post("/v1/events", json=expired.model_dump(mode="json", by_alias=True)).status_code == 401
    assert client.post("/v1/events", json=future.model_dump(mode="json", by_alias=True)).status_code == 401
    assert controller.replay_state() == {"nonces": [], "sequences": {}}
    assert controller.rejected_events() == 2


def test_standby_rejects_ordinary_mutation_and_records_attempt(tmp_path: Path) -> None:
    signer, registry = signer_and_registry("event:write")
    standby = Controller(
        tmp_path / "standby.db",
        controller_id="standby",
        role="standby",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        now=lambda: NOW,
    )
    client = TestClient(create_app(standby))
    envelope = signer.sign(
        {"subject": "blocked"},
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce="standby-reject",
        sequence=1,
    )

    assert client.post("/v1/events", json=envelope.model_dump(mode="json", by_alias=True)).status_code == 409
    assert standby.replay_state() == {"nonces": [], "sequences": {}}
    assert standby.rejected_events() == 1


def test_replication_failure_rolls_back_policy_generation(tmp_path: Path) -> None:
    signer, registry = signer_and_registry("policy:write")
    active = Controller(
        tmp_path / "active.db",
        controller_id="active",
        role="active",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        now=lambda: NOW,
    )
    client = TestClient(create_app(active))
    envelope = signer.sign(
        {"version": 1, "routes": {"tiny": "engine-a"}},
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce="rollback",
        sequence=1,
    )

    response = client.post("/v1/policies", json=envelope.model_dump(mode="json", by_alias=True))
    assert response.status_code == 503
    assert active.status()["generation"] == 0
    assert active.policy() is None


def test_replay_requires_unique_nonce_and_strict_sequence(tmp_path: Path) -> None:
    signer, registry = signer_and_registry("event:write")
    replication_private = ed25519.Ed25519PrivateKey.generate()
    registry.register("replicator", replication_private.public_key(), ("replication:write",))
    peer = Controller(
        tmp_path / "peer.db",
        controller_id="standby",
        role="standby",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        now=lambda: NOW,
    )
    controller = Controller(
        tmp_path / "controller.db",
        controller_id="active",
        role="active",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        now=lambda: NOW,
        peer=peer,
        replication_signer=PolicySigner(replication_private, "replicator"),
    )
    client = TestClient(create_app(controller))
    first = signer.sign(
        {"subject": "one"},
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce="one",
        sequence=2,
    )
    stale = signer.sign(
        {"subject": "stale"},
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce="stale",
        sequence=1,
    )
    duplicate = signer.sign(
        {"subject": "duplicate"},
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce="one",
        sequence=3,
    )

    assert client.post("/v1/events", json=first.model_dump(mode="json", by_alias=True)).status_code == 200
    assert client.post("/v1/events", json=stale.model_dump(mode="json", by_alias=True)).status_code == 401
    assert client.post("/v1/events", json=duplicate.model_dump(mode="json", by_alias=True)).status_code == 409
    assert controller.replay_state() == {"nonces": ["one"], "sequences": {"writer": 2}}
