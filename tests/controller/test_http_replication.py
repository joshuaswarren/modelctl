import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from modelctl.controller.api import Controller, create_app
from modelctl.controller.auth import PrincipalRegistry
from modelctl.controller.store import envelope_fingerprint
from modelctl.policy.signing import PolicySigner, SignedEnvelope

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
TOKEN = "fleet-test-token"


def sign(signer: PolicySigner, payload: dict[str, object], sequence: int, nonce: str) -> SignedEnvelope:
    return signer.sign(
        payload,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce=nonce,
        sequence=sequence,
    )


def test_load_principals_accepts_scoped_raw_ed25519_keys(tmp_path: Path) -> None:
    from modelctl.controller.cli import load_principals
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = base64.b64encode(private_key.public_key().public_bytes_raw()).decode("ascii")
    path = tmp_path / "principals.json"
    path.write_text(
        json.dumps(
            {
                "principals": [
                    {
                        "keyId": "writer",
                        "publicKey": public_key,
                        "scopes": ["event:write"],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    registry = load_principals(path)

    assert registry.get("writer") is not None
    assert registry.get("writer").allows("event:write")


def test_replication_prepare_and_commit_require_signed_control(tmp_path: Path) -> None:
    writer_private = ed25519.Ed25519PrivateKey.generate()
    replicator_private = ed25519.Ed25519PrivateKey.generate()
    writer = PolicySigner(writer_private, "writer")
    replicator = PolicySigner(replicator_private, "replicator")
    registry = PrincipalRegistry()
    registry.register("writer", writer_private.public_key(), ("event:write",))
    registry.register("replicator", replicator_private.public_key(), ("replication:write",))
    standby = Controller(
        tmp_path / "standby.db",
        controller_id="standby",
        role="standby",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        now=lambda: NOW,
    )
    original = sign(writer, {"subject": "wire"}, 1, "wire-op")
    operation_fingerprint = envelope_fingerprint(original)
    message = standby.replication_message(
        "active",
        1,
        0,
        "wire-op",
        {
            "kind": "event",
            "payload": original.payload,
            "operationFingerprint": operation_fingerprint,
            "originalEnvelope": original.model_dump(mode="json", by_alias=True),
        },
    )
    prepare = sign(
        replicator,
        message.model_dump(mode="json", by_alias=True),
        1,
        "prepare-wire-op",
    )
    client = TestClient(create_app(standby))

    assert client.post(
        "/v1/replication/prepare",
        json=prepare.model_dump(mode="json", by_alias=True),
    ).status_code == 200
    assert standby.operation_count("wire-op") == 0

    unsigned = client.post("/v1/replication/commit", json={"operationId": "wire-op"})
    assert unsigned.status_code == 422
    assert standby.operation_count("wire-op") == 0

    commit = sign(
        replicator,
        {"action": "commit", "operationId": "wire-op"},
        2,
        "commit-wire-op",
    )
    assert client.post(
        "/v1/replication/commit",
        json=commit.model_dump(mode="json", by_alias=True),
    ).status_code == 200
    assert standby.operation_count("wire-op") == 1
    assert client.post(
        "/v1/replication/commit",
        json=commit.model_dump(mode="json", by_alias=True),
    ).status_code == 409
