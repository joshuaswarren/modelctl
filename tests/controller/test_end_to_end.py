from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from modelctl.controller.api import Controller, create_app
from modelctl.controller.auth import PrincipalRegistry
from modelctl.controller.promotion import FencingReceipt
from modelctl.controller.store import envelope_fingerprint
from modelctl.policy.signing import PolicySigner

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
TOKEN = "fleet-test-token"
ALL_SCOPES = (
    "host:report",
    "event:write",
    "quota:write",
    "adapter:write",
    "policy:write",
    "replication:write",
    "controller:promote",
)


def setup_controller_principals() -> tuple[PrincipalRegistry, PolicySigner, PolicySigner, PolicySigner]:
    registry = PrincipalRegistry()
    writers: list[PolicySigner] = []
    for key_id, scopes in (
        ("writer", ALL_SCOPES),
        ("replicator", ("replication:write",)),
        ("promoter", ("controller:promote",)),
    ):
        private = ed25519.Ed25519PrivateKey.generate()
        registry.register(key_id, private.public_key(), scopes)
        writers.append(PolicySigner(private, key_id))
    return registry, writers[0], writers[1], writers[2]


def signed(signer: PolicySigner, payload: dict[str, object], sequence: int):
    return signer.sign(
        payload,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce=f"{signer.key_id}-{sequence}",
        sequence=sequence,
    )


def test_active_standby_replication_promotion_and_role_reversal(tmp_path: Path) -> None:
    registry, writer, replicator, promoter = setup_controller_principals()
    active = Controller(
        tmp_path / "active.db",
        controller_id="active",
        role="active",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        replication_signer=replicator,
        now=lambda: NOW,
    )
    standby = Controller(
        tmp_path / "standby.db",
        controller_id="standby",
        role="standby",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        replication_signer=replicator,
        fencing_verifier=lambda candidate: candidate.token == "fence-2",
        now=lambda: NOW,
    )
    active.set_peer(standby)
    standby.set_peer(active)

    active_client = TestClient(create_app(active))
    standby_client = TestClient(create_app(standby))
    report = signed(writer, {"hostId": "host-a", "health": "failed", "state": "active"}, 1)
    policy = signed(writer, {"version": 1, "routes": {"tiny": "engine-a"}}, 2)

    assert active_client.post("/v1/host-reports", json=report.model_dump(mode="json", by_alias=True)).status_code == 200
    assert active_client.post("/v1/policies", json=policy.model_dump(mode="json", by_alias=True)).status_code == 200
    assert standby.status()["hosts"][0]["hostId"] == "host-a"
    assert active.status()["last_replication_ack"] is not None
    assert standby.policy()["payload"]["version"] == 1
    assert standby.status()["action_targets"]["drained_hosts"] == ["host-a"]

    receipt = FencingReceipt(epoch=2, token="fence-2")
    promotion = signed(promoter, {"fencingReceipt": receipt.model_dump(mode="json")}, 1)
    assert standby_client.post("/v1/promote", json=promotion.model_dump(mode="json", by_alias=True)).status_code == 200
    assert standby.status()["role"] == "active"
    assert active.status()["role"] == "follower"

    reversed_policy = signed(writer, {"version": 2, "routes": {"tiny": "engine-b"}}, 3)
    assert (
        standby_client.post(
            "/v1/policies",
            json=reversed_policy.model_dump(mode="json", by_alias=True),
        ).status_code
        == 200
    )
    assert active.status()["role"] == "follower"
    assert active.status()["generation"] == 2
    assert (
        active_client.post(
            "/v1/events",
            json=signed(writer, {"subject": "old-active"}, 4).model_dump(
                mode="json",
                by_alias=True,
            ),
        ).status_code
        == 409
    )


def test_replication_deduplicates_operation_and_lag_degrades_health(tmp_path: Path) -> None:
    registry, writer, replicator, _ = setup_controller_principals()
    standby = Controller(
        tmp_path / "standby.db",
        controller_id="standby",
        role="standby",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        replication_signer=replicator,
        now=lambda: NOW,
        replication_lag_seconds=5,
    )
    original = writer.sign(
        {"subject": "one"},
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce="op-1",
        sequence=1,
    )

    message = standby.replication_message(
        "active",
        1,
        1,
        "op-1",
        {
            "kind": "event",
            "payload": original.payload,
            "operationFingerprint": envelope_fingerprint(original),
            "originalEnvelope": original.model_dump(mode="json", by_alias=True),
        },
    )
    envelope = signed(replicator, message.model_dump(mode="json", by_alias=True), 1)

    assert standby.apply_replication(message, envelope) is True
    assert standby.apply_replication(message, envelope) is True
    assert standby.operation_count("op-1") == 1
    standby.set_replication_ack("op-1", 1, NOW - timedelta(seconds=6))
    assert "replication-lag" in standby.health()["degraded_reasons"]


def test_promotion_requires_external_fencing_receipt(tmp_path: Path) -> None:
    registry, _, _, promoter = setup_controller_principals()
    old_active = Controller(
        tmp_path / "active.db",
        controller_id="active",
        role="active",
        epoch=4,
        fleet_token=TOKEN,
        principals=registry,
        now=lambda: NOW,
    )
    standby = Controller(
        tmp_path / "standby.db",
        controller_id="standby",
        role="standby",
        epoch=4,
        fleet_token=TOKEN,
        principals=registry,
        peer=old_active,
        fencing_verifier=lambda receipt: receipt.token == "valid",
        now=lambda: NOW,
    )
    client = TestClient(create_app(standby))
    old = signed(promoter, {"fencingReceipt": {"epoch": 4, "token": "valid"}}, 1)
    bad = signed(promoter, {"fencingReceipt": {"epoch": 5, "token": "bad"}}, 2)
    good = signed(promoter, {"fencingReceipt": {"epoch": 5, "token": "valid"}}, 3)

    assert client.post("/v1/promote", json=old.model_dump(mode="json", by_alias=True)).status_code == 409
    assert client.post("/v1/promote", json=bad.model_dump(mode="json", by_alias=True)).status_code == 403
    assert client.post("/v1/promote", json=good.model_dump(mode="json", by_alias=True)).status_code == 200
    assert standby.status()["epoch"] == 5
