from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from modelctl.policy.signing import PolicySigner, bundle_id, canonical_json
from modelctl.policy.store import PolicyKeyStore, PolicyStore
from modelctl.policy.verify import PolicyVerifier

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


def make_signer(key_id: str) -> tuple[PolicySigner, ed25519.Ed25519PublicKey]:
    private = ed25519.Ed25519PrivateKey.generate()
    return PolicySigner(private, key_id), private.public_key()


def test_canonical_json_and_bundle_id_are_stable_and_content_addressed() -> None:
    first = {"routes": {"slow": "engine-b", "tiny": "engine-a"}, "version": 1}
    second = {"version": 1, "routes": {"tiny": "engine-a", "slow": "engine-b"}}

    assert canonical_json(first) == b'{"routes":{"slow":"engine-b","tiny":"engine-a"},"version":1}'
    assert bundle_id(first) == bundle_id(second)
    assert bundle_id(first) != bundle_id({**first, "version": 2})


def test_signed_envelope_rejects_tamper_expiry_future_replay_and_stale_sequence() -> None:
    signer, public_key = make_signer("key-a")
    verifier = PolicyVerifier({"key-a": public_key}, now=lambda: NOW)
    payload = {"version": 1, "route": "engine-a"}
    envelope = signer.sign(
        payload,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=10),
        nonce="nonce-a",
        sequence=2,
    )

    assert verifier.verify(envelope) is True
    assert verifier.verify(envelope) is False
    assert verifier.verify(envelope.model_copy(update={"payload": {"route": "engine-b", "version": 1}})) is False
    assert verifier.verify(signer.sign(payload, issued_at=NOW - timedelta(minutes=1), expires_at=NOW, nonce="nonce-b", sequence=3)) is False
    assert verifier.verify(signer.sign(payload, issued_at=NOW + timedelta(seconds=1), expires_at=NOW + timedelta(minutes=10), nonce="nonce-c", sequence=4)) is False
    assert verifier.verify(signer.sign(payload, issued_at=NOW - timedelta(minutes=1), expires_at=NOW + timedelta(minutes=10), nonce="nonce-d", sequence=1)) is False


def test_unknown_and_revoked_keys_fail_while_rotated_keys_overlap() -> None:
    first_signer, first_public = make_signer("key-a")
    second_signer, second_public = make_signer("key-b")
    key_store = PolicyKeyStore({"key-a": first_public})
    verifier = PolicyVerifier(key_store, now=lambda: NOW)
    payload = {"version": 1}

    first = first_signer.sign(payload, issued_at=NOW, expires_at=NOW + timedelta(hours=1), nonce="a", sequence=1)
    second = second_signer.sign(payload, issued_at=NOW, expires_at=NOW + timedelta(hours=1), nonce="b", sequence=1)

    assert verifier.verify(first) is True
    assert verifier.verify(second) is False
    key_store.add("key-b", second_public)
    assert verifier.verify(second) is True
    key_store.revoke("key-a")
    assert verifier.verify(first_signer.sign(payload, issued_at=NOW, expires_at=NOW + timedelta(hours=1), nonce="c", sequence=2)) is False


def test_signed_envelope_uses_shared_camel_case_wire_contract() -> None:
    signer, _ = make_signer("key-wire")
    envelope = signer.sign(
        {"version": 1},
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce="wire",
        sequence=1,
    )

    wire = envelope.model_dump(mode="json", by_alias=True)

    assert set(wire) == {
        "keyId",
        "issuedAt",
        "expiresAt",
        "nonce",
        "sequence",
        "payloadDigest",
        "signature",
        "payload",
    }
    assert wire["issuedAt"] == "2026-08-29T12:00:00Z"
    assert wire["expiresAt"] == "2026-08-29T12:05:00Z"


def test_replay_state_survives_verifier_restart(tmp_path: Path) -> None:
    signer, public_key = make_signer("key-persist")
    key_store = PolicyKeyStore({"key-persist": public_key}, path=tmp_path / "keys.json")
    replay_path = tmp_path / "replay.json"
    envelope = signer.sign(
        {"version": 1},
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce="persisted",
        sequence=1,
    )

    assert PolicyVerifier(key_store, now=lambda: NOW, replay_path=replay_path).verify(envelope)
    restarted = PolicyVerifier(
        PolicyKeyStore(path=tmp_path / "keys.json"),
        now=lambda: NOW,
        replay_path=replay_path,
    )

    assert restarted.verify(envelope) is False


def test_last_known_good_policy_survives_restart(tmp_path: Path) -> None:
    signer, public_key = make_signer("key-store")
    key_store = PolicyKeyStore({"key-store": public_key})
    verifier = PolicyVerifier(key_store, now=lambda: NOW)
    envelope = signer.sign(
        {"version": 1, "route": "engine-a"},
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce="store",
        sequence=1,
    )
    policy_path = tmp_path / "policy.json"
    store = PolicyStore(path=policy_path)

    assert store.apply(envelope, verifier) is True
    restarted = PolicyStore(path=policy_path)

    assert restarted.current_payload == {"version": 1, "route": "engine-a"}


def test_compromise_recovery_revokes_old_key_and_adds_replacement() -> None:
    first_signer, first_public = make_signer("key-compromised")
    replacement_signer, replacement_public = make_signer("key-replacement")
    key_store = PolicyKeyStore({"key-compromised": first_public})

    key_store.recover_from_compromise(
        compromised_key_id="key-compromised",
        replacement_key_id="key-replacement",
        replacement_public_key=replacement_public,
    )

    assert key_store.is_trusted("key-compromised") is False
    assert key_store.is_trusted("key-replacement") is True
    assert first_signer is not replacement_signer


def test_signed_envelope_normalizes_rfc3339_offset_to_utc() -> None:
    signer, _ = make_signer("key-time")

    envelope = signer.sign(
        {"version": 1},
        issued_at=datetime(2026, 8, 29, 14, 0, tzinfo=timezone(timedelta(hours=2))),
        expires_at=datetime(2026, 8, 29, 15, 0, tzinfo=timezone(timedelta(hours=2))),
        nonce="offset",
        sequence=1,
    )

    assert envelope.issued_at == datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
    assert envelope.model_dump(mode="json", by_alias=True)["issuedAt"] == "2026-08-29T12:00:00Z"


def test_key_store_does_not_reactivate_revoked_or_reuse_compromised_key() -> None:
    signer, public_key = make_signer("key-old")
    replacement, replacement_public = make_signer("key-new")
    key_store = PolicyKeyStore({"key-old": public_key})
    key_store.recover_from_compromise(
        compromised_key_id="key-old",
        replacement_key_id="key-new",
        replacement_public_key=replacement_public,
    )

    with pytest.raises(ValueError):
        key_store.add("key-old", public_key)
    with pytest.raises(ValueError):
        key_store.recover_from_compromise(
            compromised_key_id="key-new",
            replacement_key_id="key-new",
            replacement_public_key=replacement_public,
        )

    assert signer is not replacement
    assert key_store.is_trusted("key-old") is False
