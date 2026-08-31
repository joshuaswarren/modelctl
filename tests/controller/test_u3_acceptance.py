import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from modelctl.controller.api import Controller, create_app
from modelctl.controller.auth import PrincipalRegistry
from modelctl.controller.replication import ReplicationMessage
from modelctl.policy.signing import PolicySigner, SignedEnvelope

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


def setup() -> tuple[PrincipalRegistry, PolicySigner, PolicySigner, PolicySigner]:
    registry = PrincipalRegistry()
    signers: list[PolicySigner] = []
    for key_id, scopes in (
        ("writer", ALL_SCOPES),
        ("replicator", ("replication:write",)),
        ("promoter", ("controller:promote",)),
    ):
        private = ed25519.Ed25519PrivateKey.generate()
        registry.register(key_id, private.public_key(), scopes)
        signers.append(PolicySigner(private, key_id))
    return registry, signers[0], signers[1], signers[2]


def signed(signer: PolicySigner, payload: dict[str, object], sequence: int, nonce: str | None = None) -> SignedEnvelope:
    return signer.sign(
        payload,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce=nonce or f"{signer.key_id}-{sequence}",
        sequence=sequence,
    )


def controller(
    path: Path,
    registry: PrincipalRegistry,
    *,
    controller_id: str,
    role: str,
    epoch: int,
    peer: object | None = None,
    replication_signer: PolicySigner | None = None,
    fencing_verifier: object | None = None,
) -> Controller:
    return Controller(
        path,
        controller_id=controller_id,
        role=role,
        epoch=epoch,
        fleet_token=TOKEN,
        principals=registry,
        peer=peer,
        replication_signer=replication_signer,
        fencing_verifier=fencing_verifier,
        now=lambda: NOW,
    )


class CommitFailurePeer:
    def __init__(self, standby: Controller) -> None:
        self.standby = standby
        self.fail_commit = True

    def prepare_replication(self, message: ReplicationMessage, envelope: SignedEnvelope) -> bool:
        return self.standby.prepare_replication(message, envelope)

    def commit_replication(self, operation_id: str) -> bool:
        if self.fail_commit:
            return False
        return self.standby.commit_replication(operation_id)

    def abort_replication(self, operation_id: str) -> None:
        self.standby.abort_replication(operation_id)

    def fence(self, epoch: int) -> bool:
        return self.standby.fence(epoch)


def test_outbound_sequence_survives_active_restart(tmp_path: Path) -> None:
    registry, writer, replicator, _ = setup()
    standby = controller(tmp_path / "standby.db", registry, controller_id="standby", role="standby", epoch=1)
    active = controller(
        tmp_path / "active.db",
        registry,
        controller_id="active",
        role="active",
        epoch=1,
        peer=standby,
        replication_signer=replicator,
    )
    client = TestClient(create_app(active))
    assert client.post("/v1/events", json=signed(writer, {"subject": "one"}, 1).model_dump(mode="json", by_alias=True)).status_code == 200
    active.store.close()

    restarted = controller(
        tmp_path / "active.db",
        registry,
        controller_id="active",
        role="active",
        epoch=1,
        peer=standby,
        replication_signer=replicator,
    )
    assert TestClient(create_app(restarted)).post(
        "/v1/events", json=signed(writer, {"subject": "two"}, 2).model_dump(mode="json", by_alias=True)
    ).status_code == 200
    assert restarted.outbound_sequence("replicator") == 2
    assert standby.replay_state()["sequences"]["replicator"] == 2


def test_pending_commit_recovers_after_active_restart(tmp_path: Path) -> None:
    registry, writer, replicator, _ = setup()
    standby = controller(tmp_path / "standby.db", registry, controller_id="standby", role="standby", epoch=1)
    peer = CommitFailurePeer(standby)
    active = controller(
        tmp_path / "active.db",
        registry,
        controller_id="active",
        role="active",
        epoch=1,
        peer=peer,
        replication_signer=replicator,
    )
    response = TestClient(create_app(active)).post(
        "/v1/events", json=signed(writer, {"subject": "pending"}, 1, "pending-nonce").model_dump(mode="json", by_alias=True)
    )
    assert response.status_code == 503
    assert active.operation_count("pending-nonce") == 1
    assert standby.operation_count("pending-nonce") == 0
    active.store.close()

    restarted = controller(
        tmp_path / "active.db",
        registry,
        controller_id="active",
        role="active",
        epoch=1,
        peer=peer,
        replication_signer=replicator,
    )
    peer.fail_commit = False
    assert restarted.recover_pending_operations() == ["pending-nonce"]
    assert restarted.operation_count("pending-nonce") == 1
    assert standby.operation_count("pending-nonce") == 1


def test_inner_authentication_precedes_replication_replay_state(tmp_path: Path) -> None:
    registry, _, replicator, _ = setup()
    standby = controller(tmp_path / "standby.db", registry, controller_id="standby", role="standby", epoch=1)
    unknown_private = ed25519.Ed25519PrivateKey.generate()
    unknown = PolicySigner(unknown_private, "unknown")
    inner = signed(unknown, {"subject": "forbidden"}, 1, "inner-nonce")
    message = standby.replication_message(
        "active",
        1,
        1,
        "inner-nonce",
        {
            "kind": "event",
            "payload": {"subject": "forbidden"},
            "operationFingerprint": "0" * 64,
            "originalEnvelope": inner.model_dump(mode="json", by_alias=True),
        },
    )
    outer = signed(replicator, message.model_dump(mode="json", by_alias=True), 1, "outer-nonce")

    assert standby.apply_replication(message, outer) is False
    assert standby.replay_state() == {"nonces": [], "sequences": {}}


def test_pending_operation_rejects_different_authenticated_envelope(tmp_path: Path) -> None:
    registry, writer, replicator, _ = setup()
    standby = controller(tmp_path / "standby.db", registry, controller_id="standby", role="standby", epoch=1)
    peer = CommitFailurePeer(standby)
    active = controller(
        tmp_path / "active.db",
        registry,
        controller_id="active",
        role="active",
        epoch=1,
        peer=peer,
        replication_signer=replicator,
    )
    first = signed(writer, {"subject": "first", "operationId": "same"}, 1, "first")
    different = signed(writer, {"subject": "different", "operationId": "same"}, 2, "different")
    client = TestClient(create_app(active))
    assert client.post("/v1/events", json=first.model_dump(mode="json", by_alias=True)).status_code == 503
    assert client.post("/v1/events", json=different.model_dump(mode="json", by_alias=True)).status_code == 409


def test_promotion_fences_old_active_and_rejects_degraded_standby(tmp_path: Path) -> None:
    registry, writer, replicator, promoter = setup()
    old_active = controller(tmp_path / "active.db", registry, controller_id="active", role="active", epoch=1)
    standby = controller(
        tmp_path / "standby.db",
        registry,
        controller_id="standby",
        role="standby",
        epoch=1,
        peer=old_active,
        replication_signer=replicator,
        fencing_verifier=lambda receipt: receipt.token == "fence-2",
    )
    old_active.set_peer(standby)
    old_active.replication_signer = replicator
    old_active.store.set_lag_degraded(True)
    promote = signed(promoter, {"fencingReceipt": {"epoch": 2, "token": "fence-2"}}, 1, "promote")
    assert TestClient(create_app(standby)).post(
        "/v1/promote", json=promote.model_dump(mode="json", by_alias=True)
    ).status_code == 409
    assert standby.status()["role"] == "standby"

    old_active.store.set_lag_degraded(False)
    assert TestClient(create_app(standby)).post(
        "/v1/promote", json=promote.model_dump(mode="json", by_alias=True)
    ).status_code == 200
    assert old_active.status()["role"] == "follower"
    blocked = signed(writer, {"subject": "stale"}, 1, "stale")
    assert TestClient(create_app(old_active)).post(
        "/v1/events", json=blocked.model_dump(mode="json", by_alias=True)
    ).status_code == 409


def test_status_and_health_reads_are_side_effect_free_and_actions_are_stable(tmp_path: Path) -> None:
    registry, _, _, _ = setup()
    active = controller(tmp_path / "active.db", registry, controller_id="active", role="active", epoch=1)
    before = len(active.events())
    first = active.status()
    second = active.status()
    assert first == second
    assert len(active.events()) == before
    client = TestClient(create_app(active))
    headers = {"Authorization": f"Bearer {TOKEN}"}
    assert client.get("/health", headers=headers).json() == active.health()
    assert client.get("/v1/actions", headers=headers).json() == {"drained_hosts": []}


def test_existing_operations_schema_migrates_without_data_loss(tmp_path: Path) -> None:
    path = tmp_path / "legacy.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE state (name TEXT PRIMARY KEY, value TEXT NOT NULL)")
    connection.execute("CREATE TABLE operations (operation_id TEXT PRIMARY KEY, source_controller TEXT NOT NULL, epoch INTEGER NOT NULL, generation INTEGER NOT NULL)")
    connection.execute("INSERT INTO operations VALUES ('legacy', 'active', 1, 0)")
    connection.commit()
    connection.close()

    restored = controller(path, PrincipalRegistry(), controller_id="active", role="active", epoch=1)
    assert restored.operation_count("legacy") == 1
    columns = {row[1] for row in sqlite3.connect(path).execute("PRAGMA table_info(operations)")}
    assert {"fingerprint", "replication_state"} <= columns


def test_controller_cli_exposes_production_parser() -> None:
    from modelctl.controller.cli import build_parser

    args = build_parser().parse_args(
        [
            "--db-path",
            "/var/lib/modelctl/controller.db",
            "--controller-id",
            "active",
            "--role",
            "active",
            "--epoch",
            "3",
            "--fleet-token",
            "token",
            "--principals",
            "/etc/modelctl/principals.json",
            "--tls-ca-file",
            "/etc/modelctl/ca.pem",
            "--tls-cert-file",
            "/etc/modelctl/controller.pem",
            "--tls-key-file",
            "/etc/modelctl/controller-key.pem",
        ]
    )
    assert args.controller_id == "active"
    assert args.epoch == 3
    assert args.principals.name == "principals.json"
    assert args.tls_ca_file.name == "ca.pem"
    assert args.tls_cert_file.name == "controller.pem"
    assert args.tls_key_file.name == "controller-key.pem"
