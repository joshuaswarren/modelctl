from __future__ import annotations

import base64
import json
import ssl
import sys
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from modelctl.adapters.litellm.apply import ApplyError, ApplyReceipt
from modelctl.adapters.litellm.core import BEGIN_MARKER, END_MARKER
from modelctl.adapters.litellm.receiver_cli import (
    PolicyResponse,
    Receiver,
    ReceiverConfig,
    load_config,
)
from modelctl.domain.engine import EngineHealth, PhysicalEngine
from modelctl.domain.policy import PolicyBundle
from modelctl.policy.signing import PolicySigner, SignedEnvelope
from modelctl.policy.store import PolicyKeyStore, PolicyStore
from modelctl.policy.verify import PolicyVerifier

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
TOKEN = "receiver-token-do-not-print"
PRIVATE_KEY_TEXT = "private-key-do-not-print"


class FakeTransport:
    def __init__(self, responses: dict[str, object | BaseException]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, Mapping[str, str], ssl.SSLContext | None, float]] = []

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        ssl_context: ssl.SSLContext | None,
        timeout: float,
    ) -> PolicyResponse:
        self.calls.append((url, headers, ssl_context, timeout))
        response = self.responses[url]
        if isinstance(response, BaseException):
            raise response
        return PolicyResponse(200, response)


def _policy(model: str = "provider/model-a") -> PolicyBundle:
    return PolicyBundle(
        engines=[
            PhysicalEngine(
                id="engine-a",
                host="engine-a.example.test",
                baseUrl="https://engine-a.example.test:8000/v1",
                aliases=["advisor"],
                residentModels=[model],
                maxSlots=4,
                interactiveReserved=1,
                health=EngineHealth.HEALTHY,
            )
        ],
        routes={"aliases": {"advisor": "engine-a"}},
    )


def _envelope(private_key: ed25519.Ed25519PrivateKey, sequence: int, policy: PolicyBundle) -> SignedEnvelope:
    signer = PolicySigner(private_key, "controller-key")
    return signer.sign(
        policy.model_dump(mode="json", by_alias=True),
        sequence=sequence,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1),
        nonce=f"nonce-{sequence}-{policy.engines[0].resident_models[0]}",
    )


def _config(
    tmp_path: Path,
    public_key: ed25519.Ed25519PublicKey,
    *,
    apply_enabled: bool = True,
) -> ReceiverConfig:
    token_path = tmp_path / "token"
    token_path.write_text(TOKEN)
    token_path.chmod(0o600)
    config_path = tmp_path / "litellm.yaml"
    config_path.write_bytes((BEGIN_MARKER + "\n" + END_MARKER + "\n").encode())
    return ReceiverConfig(
        active_controller_url="https://active.example.test",
        standby_controller_url="https://standby.example.test",
        bearer_token_file=token_path,
        tls_ca_file=tmp_path / "ca.pem",
        tls_cert_file=tmp_path / "client.pem",
        tls_key_file=tmp_path / "client-key.pem",
        trusted_controller_keys={"controller-key": public_key.public_bytes_raw()},
        policy_state_path=tmp_path / "policy.json",
        litellm_config_path=config_path,
        restart_command=(sys.executable, "-c", "pass"),
        smoke_command=(sys.executable, "-c", "pass"),
        apply_receipt_path=tmp_path / "receipts.jsonl",
        apply_enabled=apply_enabled,
    )


def _receiver(
    tmp_path: Path,
    *,
    private_key: ed25519.Ed25519PrivateKey,
    active: SignedEnvelope | object,
    standby: SignedEnvelope | object,
    apply_operation: Callable[..., ApplyReceipt],
) -> tuple[Receiver, FakeTransport, PolicyStore]:
    config = _config(tmp_path, private_key.public_key())
    key_store = PolicyKeyStore(config.trusted_controller_keys)
    store = PolicyStore(key_store, path=config.policy_state_path)
    verifier = PolicyVerifier(key_store, now=lambda: NOW)
    transport = FakeTransport(
        {
            "https://active.example.test/v1/policy": _body(active),
            "https://standby.example.test/v1/policy": _body(standby),
        }
    )
    receiver = Receiver(
        config,
        ssl_context=ssl.create_default_context(),
        transport=transport,
        store=store,
        verifier=verifier,
        apply_operation=apply_operation,
    )
    return receiver, transport, store


def _body(value: SignedEnvelope | object) -> object:
    return value.model_dump(mode="json", by_alias=True) if isinstance(value, SignedEnvelope) else value


def _receipt() -> ApplyReceipt:
    return ApplyReceipt(
        dry_run=False,
        bundle_id="bundle-id",
        original_digest="0" * 64,
        rendered_digest="1" * 64,
        distributions={"engine-a": {"advisor": 3}},
        diff="",
        backup_path=None,
        restart_performed=True,
    )


def test_selects_highest_valid_sequence_from_both_controllers(tmp_path: Path) -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    active = _envelope(private_key, 4, _policy())
    standby = _envelope(private_key, 5, _policy("provider/model-b"))
    receiver, transport, store = _receiver(
        tmp_path,
        private_key=private_key,
        active=active,
        standby=standby,
        apply_operation=lambda *args, **kwargs: _receipt(),
    )

    result = receiver.sync_once()

    assert result["status"] == "applied"
    assert result["selected"] == {"sequence": 5, "digest": standby.payload_digest}
    assert store.current == standby
    assert {call[0] for call in transport.calls} == {
        "https://active.example.test/v1/policy",
        "https://standby.example.test/v1/policy",
    }
    assert all(call[1]["Authorization"] == f"Bearer {TOKEN}" for call in transport.calls)


def test_observe_only_receiver_reports_update_without_apply_or_state_change(tmp_path: Path) -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    candidate = _envelope(private_key, 6, _policy())
    config = _config(tmp_path, private_key.public_key(), apply_enabled=False)
    transport = FakeTransport(
        {
            "https://active.example.test/v1/policy": _body(candidate),
            "https://standby.example.test/v1/policy": _body(candidate),
        }
    )
    key_store = PolicyKeyStore(config.trusted_controller_keys)
    store = PolicyStore(key_store, path=config.policy_state_path)
    receiver = Receiver(
        config,
        ssl_context=ssl.create_default_context(),
        transport=transport,
        store=store,
        verifier=PolicyVerifier(key_store, now=lambda: NOW),
        apply_operation=lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("apply must not run")),
    )

    result = receiver.sync_once()

    assert result["status"] == "update_available"
    assert result["selected"] == {"sequence": 6, "digest": candidate.payload_digest}
    assert result["exitCode"] == 0
    assert store.current is None
    assert not config.policy_state_path.exists()


def test_rejects_split_brain_without_apply_or_state_mutation(tmp_path: Path) -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    active = _envelope(private_key, 7, _policy("provider/model-a"))
    standby = _envelope(private_key, 7, _policy("provider/model-b"))
    calls = 0

    def fail_if_called(*args: object, **kwargs: object) -> ApplyReceipt:
        nonlocal calls
        calls += 1
        raise AssertionError("apply must not run")

    receiver, _, store = _receiver(tmp_path, private_key=private_key, active=active, standby=standby, apply_operation=fail_if_called)

    result = receiver.sync_once()

    assert result["status"] == "split_brain"
    assert result["exitCode"] == 1
    assert calls == 0
    assert store.current is None
    assert not (tmp_path / "policy.json").exists()


@pytest.mark.parametrize("tamper", ["signature", "digest"])
def test_rejects_invalid_signature_or_digest(tmp_path: Path, tamper: str) -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    valid = _envelope(private_key, 8, _policy())
    if tamper == "signature":
        signature = bytearray(base64.b64decode(valid.signature))
        signature[0] ^= 1
        invalid = valid.model_copy(update={"signature": base64.b64encode(signature).decode()})
    else:
        invalid = valid.model_copy(update={"payload_digest": "0" * 64})
    receiver, _, _ = _receiver(tmp_path, private_key=private_key, active=invalid, standby=invalid, apply_operation=lambda *a, **k: _receipt())

    result = receiver.sync_once()

    assert result["status"] == "no_update"
    assert result["exitCode"] == 0
    assert result["controllerFailures"] == [
        {"controller": "active", "class": "verification_failed"},
        {"controller": "standby", "class": "verification_failed"},
    ]


def test_stale_sequence_is_a_non_mutating_noop(tmp_path: Path) -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    old = _envelope(private_key, 9, _policy())
    receiver, _, store = _receiver(tmp_path, private_key=private_key, active=old, standby=old, apply_operation=lambda *a, **k: _receipt())
    store.apply(old, PolicyVerifier(store.keys, now=lambda: NOW))
    before = (tmp_path / "policy.json").read_bytes()

    result = receiver.sync_once()

    assert result["status"] == "no_update"
    assert result["selected"] == {"sequence": 9, "digest": old.payload_digest}
    assert (tmp_path / "policy.json").read_bytes() == before


def test_successful_apply_uses_guarded_adapter_and_commits_state(tmp_path: Path) -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    candidate = _envelope(private_key, 10, _policy())
    config = _config(tmp_path, private_key.public_key())
    transport = FakeTransport(
        {
            "https://active.example.test/v1/policy": _body(candidate),
            "https://standby.example.test/v1/policy": _body(candidate),
        }
    )
    key_store = PolicyKeyStore(config.trusted_controller_keys)
    store = PolicyStore(key_store, path=config.policy_state_path)
    verifier = PolicyVerifier(key_store, now=lambda: NOW)
    receiver = Receiver(
        config,
        ssl_context=ssl.create_default_context(),
        transport=transport,
        store=store,
        verifier=verifier,
    )

    result = receiver.sync_once()

    assert result["status"] == "applied"
    assert config.litellm_config_path.read_bytes() != (BEGIN_MARKER + "\n" + END_MARKER + "\n").encode()
    assert store.current == candidate
    assert config.apply_receipt_path.read_text().count("modelctl.litellm.apply") == 1


def test_apply_failure_preserves_previous_policy_state(tmp_path: Path) -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    old = _envelope(private_key, 11, _policy("provider/model-old"))
    new = _envelope(private_key, 12, _policy("provider/model-new"))
    receiver, _, store = _receiver(tmp_path, private_key=private_key, active=new, standby=new, apply_operation=_raise_apply)
    store.apply(old, PolicyVerifier(store.keys, now=lambda: NOW))
    before = (tmp_path / "policy.json").read_bytes()

    result = receiver.sync_once()

    assert result["status"] == "apply_failed"
    assert result["exitCode"] == 1
    assert store.current == old
    assert (tmp_path / "policy.json").read_bytes() == before


def _raise_apply(*args: object, **kwargs: object) -> ApplyReceipt:
    raise ApplyError("not exposed")


def test_config_requires_0600_token_and_client_key_and_mtls(tmp_path: Path) -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    token = tmp_path / "token"
    token.write_text(TOKEN)
    client_key = tmp_path / "client-key.pem"
    trusted_keys = tmp_path / "trusted-controller-keys.yaml"
    trusted_keys.write_text(
        json.dumps({"controller-key": base64.b64encode(private_key.public_key().public_bytes_raw()).decode()})
    )
    client_key.write_text(PRIVATE_KEY_TEXT)
    config_path = tmp_path / "receiver.yaml"
    config_path.write_text(
        json.dumps(
            {
                "controllers": {"active": "https://a.example", "standby": "https://b.example"},
                "bearerTokenFile": "token",
                "mtls": {"caPath": "ca.pem", "clientCertPath": "client.pem", "clientKeyPath": "client-key.pem"},
                "trustedControllerKeysFile": "trusted-controller-keys.yaml",
                "policyStatePath": "policy.json",
                "litellmConfigPath": "litellm.yaml",
                "restartCommand": [sys.executable, "-c", "pass"],
                "applyEnabled": False,
                "smokeCommand": [sys.executable, "-c", "pass"],
                "applyReceiptPath": "receipts.jsonl",
            }
        )
    )
    token.chmod(0o644)
    client_key.chmod(0o600)
    with pytest.raises(ValueError, match="0600"):
        load_config(config_path)
    token.chmod(0o600)
    client_key.chmod(0o644)
    with pytest.raises(ValueError, match="0600"):
        load_config(config_path)
    client_key.chmod(0o600)
    config = load_config(config_path)
    assert config.apply_enabled is False
    with pytest.raises(ValueError, match="mutual TLS"):
        Receiver(config, ssl_context=None)


def test_transport_failures_are_secret_free(tmp_path: Path) -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    receiver, _, _ = _receiver(
        tmp_path,
        private_key=private_key,
        active=RuntimeError(f"{TOKEN} {PRIVATE_KEY_TEXT}"),
        standby=RuntimeError(f"{TOKEN} {PRIVATE_KEY_TEXT}"),
        apply_operation=lambda *a, **k: _receipt(),
    )

    result = receiver.sync_once()
    encoded = json.dumps(result)

    assert result["status"] == "no_update"
    assert result["controllerFailures"] == [
        {"controller": "active", "class": "transport_error"},
        {"controller": "standby", "class": "transport_error"},
    ]
    assert TOKEN not in encoded
    assert PRIVATE_KEY_TEXT not in encoded
