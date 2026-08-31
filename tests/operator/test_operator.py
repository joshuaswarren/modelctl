import hashlib
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from modelctl.agents.host.transport import HttpResponse
from modelctl.operator import (
    ActionDeliveryError,
    SequenceAllocator,
    load_operator_signer,
    main,
    run_action,
)
from modelctl.policy.signing import SignedEnvelope, canonical_json


class RecordingTransport:
    def __init__(
        self,
        sequence_path: Path,
        *,
        statuses: dict[str, int] | None = None,
        fail: bool = False,
    ) -> None:
        self.sequence_path = sequence_path
        self.statuses = statuses or {}
        self.fail = fail
        self.posts: list[tuple[str, bytes, dict[str, str]]] = []

    def post(self, url: str, body: bytes, headers: dict[str, str]) -> HttpResponse:
        assert self.sequence_path.exists()
        self.posts.append((url, body, headers))
        if self.fail:
            raise OSError("transport failure with hidden detail")
        return HttpResponse(self.statuses.get(url, 202), {"accepted": True})


def write_key(path: Path, *, mode: int = 0o600) -> ed25519.Ed25519PrivateKey:
    key = ed25519.Ed25519PrivateKey.generate()
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(path, mode)
    return key


def payload_digest(payload: dict[str, object]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def test_load_operator_signer_requires_mode_0600_ed25519_key(tmp_path: Path) -> None:
    key_path = tmp_path / "operator.pem"
    write_key(key_path, mode=0o640)

    with pytest.raises(ValueError, match="0600"):
        load_operator_signer(key_path, "operator")

    os.chmod(key_path, 0o600)
    signer = load_operator_signer(key_path, "operator")
    assert signer.key_id == "operator"


def test_sequence_allocator_is_durable_and_allocates_before_delivery(tmp_path: Path) -> None:
    sequence_path = tmp_path / "sequence.json"
    allocator = SequenceAllocator(sequence_path)

    assert allocator.allocate() == 1
    assert allocator.allocate() == 2
    assert SequenceAllocator(sequence_path).allocate() == 3
    assert json.loads(sequence_path.read_text()) == {"sequence": 3}


def test_run_action_posts_one_exact_policy_envelope_and_accepts_one_controller(tmp_path: Path) -> None:
    key_path = tmp_path / "operator.pem"
    write_key(key_path)
    sequence_path = tmp_path / "sequence.json"
    transport = RecordingTransport(
        sequence_path,
        statuses={"https://standby.example/v1/policies": 409},
    )
    payload = {"version": 2, "actions": {"drain": ["host-a"]}}

    result = run_action(
        payload,
        kind="policy",
        key_path=key_path,
        key_id="operator",
        sequence_path=sequence_path,
        controllers=["https://primary.example", "https://standby.example"],
        transport=transport,
    )

    assert result.sequence == 1
    assert len(result.responses) == 1
    assert transport.posts[0][1] == transport.posts[1][1]
    envelope = SignedEnvelope.model_validate(json.loads(transport.posts[0][1]))
    assert envelope.sequence == 1
    assert envelope.payload == payload
    assert [post[0] for post in transport.posts] == [
        "https://primary.example/v1/policies",
        "https://standby.example/v1/policies",
    ]


def test_run_action_requires_one_controller_acceptance_and_writes_secret_free_receipt(tmp_path: Path) -> None:
    key_path = tmp_path / "operator.pem"
    write_key(key_path)
    sequence_path = tmp_path / "sequence.json"
    receipt_path = tmp_path / "receipts.jsonl"
    transport = RecordingTransport(sequence_path, fail=True)

    with pytest.raises(ActionDeliveryError):
        run_action(
            {"secret": "do-not-write", "version": 2},
            kind="policy",
            key_path=key_path,
            key_id="operator",
            sequence_path=sequence_path,
            controllers=["https://primary.example"],
            receipt_path=receipt_path,
            transport=transport,
        )

    receipt = receipt_path.read_text()
    assert "do-not-write" not in receipt
    assert "transport failure with hidden detail" not in receipt
    assert "primary.example" not in receipt
    record = json.loads(receipt)
    assert record["kind"] == "policy"
    assert record["endpoints"] == ["/v1/policies"]
    assert record["errorType"] == "ActionDeliveryError"


def test_run_action_rejects_unknown_kind_and_http_origin_before_network(tmp_path: Path) -> None:
    key_path = tmp_path / "operator.pem"
    write_key(key_path)
    transport = RecordingTransport(tmp_path / "sequence.json")

    with pytest.raises(ValueError, match="unsupported action kind"):
        run_action(
            {},
            kind="promote",
            key_path=key_path,
            key_id="operator",
            sequence_path=tmp_path / "sequence.json",
            controllers=["https://primary.example"],
            transport=transport,
        )
    with pytest.raises(ValueError, match="HTTPS origin"):
        run_action(
            {},
            kind="policy",
            key_path=key_path,
            key_id="operator",
            sequence_path=tmp_path / "sequence.json",
            controllers=["http://primary.example"],
            transport=transport,
        )
    assert transport.posts == []


def test_main_defaults_to_dry_run_and_writes_prepared_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    key_path = tmp_path / "operator.pem"
    write_key(key_path)
    sequence_path = tmp_path / "sequence.json"
    payload_path = tmp_path / "payload.json"
    receipt_path = tmp_path / "receipts.jsonl"
    payload = {"version": 2, "actions": {"pin": {"workload": "host-a"}}}
    payload_path.write_text(json.dumps(payload))
    transport = RecordingTransport(sequence_path)
    monkeypatch.setattr("modelctl.operator.cli.UrllibTransport", lambda **_: transport)

    result = main(
        [
            "--kind",
            "policy",
            "--payload",
            str(payload_path),
            "--key",
            str(key_path),
            "--key-id",
            "operator",
            "--sequence",
            str(sequence_path),
            "--controller",
            "https://primary.example",
            "--receipt",
            str(receipt_path),
        ]
    )

    assert result == 0
    output = json.loads(capsys.readouterr().out)
    assert output["applied"] is False
    assert output["payloadDigest"] == payload_digest(payload)
    assert SignedEnvelope.model_validate(output["envelope"]).payload == payload
    assert transport.posts == []
    receipt = json.loads(receipt_path.read_text())
    assert receipt["status"] == "prepared"
    assert receipt["payloadDigest"] == payload_digest(payload)
    assert "primary.example" not in receipt_path.read_text()


def test_main_apply_requires_digest_confirmation_and_mtls(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    key_path = tmp_path / "operator.pem"
    write_key(key_path)
    sequence_path = tmp_path / "sequence.json"
    payload_path = tmp_path / "payload.json"
    receipt_path = tmp_path / "receipts.jsonl"
    payload = {"version": 2, "actions": {"rollback": "policy-1"}}
    payload_path.write_text(json.dumps(payload))
    transport = RecordingTransport(sequence_path)
    monkeypatch.setattr("modelctl.operator.cli.UrllibTransport", lambda **_: transport)

    common = [
        "--kind",
        "policy",
        "--payload",
        str(payload_path),
        "--key",
        str(key_path),
        "--key-id",
        "operator",
        "--sequence",
        str(sequence_path),
        "--controller",
        "https://primary.example",
        "--receipt",
        str(receipt_path),
        "--apply",
    ]
    assert main([*common, "--confirm", "wrong"]) == 1
    assert transport.posts == []
    capsys.readouterr()

    for name in ("ca.pem", "cert.pem", "tls-key.pem"):
        (tmp_path / name).write_text(name)
    monkeypatch.setattr("modelctl.operator.cli.require_mtls_context", lambda *_: object())
    result = main(
        [
            *common,
            "--confirm",
            payload_digest(payload),
            "--tls-ca-file",
            str(tmp_path / "ca.pem"),
            "--tls-cert-file",
            str(tmp_path / "cert.pem"),
            "--tls-key-file",
            str(tmp_path / "tls-key.pem"),
        ]
    )

    assert result == 0
    output = json.loads(capsys.readouterr().out)
    assert output == {"acceptedControllers": 1, "applied": True, "sequence": 1}
    assert len(transport.posts) == 1
    records = [json.loads(line) for line in receipt_path.read_text().splitlines()]
    assert records[-1]["status"] == "applied"
    assert records[-1]["acceptedControllers"] == 1
