"""Operator command for preparing and delivering signed controller policies."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import ssl
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from modelctl.agents.host.transport import (
    HttpResponse,
    HttpTransport,
    UrllibTransport,
    build_mtls_context,
)
from modelctl.operator.actions import ActionSpec, action_endpoint, action_spec
from modelctl.operator.sequence import SequenceAllocator
from modelctl.policy.signing import PolicySigner, SignedEnvelope, canonical_json

DEFAULT_RECEIPT_PATH = Path("modelctl-operator-actions.jsonl")


@dataclass(frozen=True)
class ActionResult:
    """The signed envelope and successful controller responses."""

    sequence: int
    envelope: SignedEnvelope
    responses: tuple[HttpResponse, ...]


class ActionDeliveryError(RuntimeError):
    """No controller accepted the signed policy."""


def load_operator_signer(key_path: Path, key_id: str) -> PolicySigner:
    """Load one unencrypted Ed25519 key after enforcing mode 0600."""

    if stat.S_IMODE(key_path.stat().st_mode) != 0o600:
        raise ValueError("operator signing key permissions must be 0600")
    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError("operator signing key is not a valid unencrypted PEM key") from exc
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise TypeError("operator signing key must be Ed25519")
    return PolicySigner(key, key_id)


def prepare_signed_action(
    payload: dict[str, Any],
    *,
    kind: str,
    key_path: Path,
    key_id: str,
    sequence_path: Path,
) -> SignedEnvelope:
    """Allocate a durable sequence, then sign the unchanged payload."""

    action_spec(kind)
    signer = load_operator_signer(key_path, key_id)
    sequence = SequenceAllocator(sequence_path).allocate()
    return signer.sign(dict(payload), sequence=sequence)


def _payload_digest(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def write_action_receipt(
    path: Path,
    *,
    status: str,
    kind: str,
    endpoints: Sequence[str],
    sequence: int | None = None,
    payload_digest: str | None = None,
    accepted_controllers: int | None = None,
    error: BaseException | None = None,
) -> None:
    """Append one secret-free operator decision receipt."""

    record: dict[str, Any] = {
        "timestamp": datetime.now(UTC).isoformat(),
        "status": status,
        "kind": kind,
        "endpoints": list(endpoints),
    }
    if sequence is not None:
        record["sequence"] = sequence
    if payload_digest is not None:
        record["payloadDigest"] = payload_digest
    if accepted_controllers is not None:
        record["acceptedControllers"] = accepted_controllers
    if error is not None:
        record["errorType"] = type(error).__name__
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with path.open("ab") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())


def write_failure_receipt(
    path: Path,
    *,
    kind: str,
    endpoints: Sequence[str],
    error: BaseException,
) -> None:
    """Append one secret-free failure receipt."""

    write_action_receipt(path, status="failed", kind=kind, endpoints=endpoints, error=error)


def _post_envelope(
    envelope: SignedEnvelope,
    spec: ActionSpec,
    controllers: Sequence[str],
    transport: HttpTransport,
) -> tuple[HttpResponse, ...]:
    body = canonical_json(envelope.model_dump(mode="json", by_alias=True))
    responses: list[HttpResponse] = []
    for controller in controllers:
        endpoint = action_endpoint(spec.kind, controller)
        try:
            response = transport.post(
                endpoint,
                body,
                {"Accept": "application/json", "Content-Type": "application/json"},
            )
        except (OSError, UnicodeError, json.JSONDecodeError):
            response = None
        if response is not None and 200 <= response.status_code < 300:
            responses.append(response)
    if not responses:
        raise ActionDeliveryError("no controller accepted the signed policy")
    return tuple(responses)


def run_action(
    payload: dict[str, Any],
    *,
    kind: str,
    key_path: Path,
    key_id: str,
    sequence_path: Path,
    controllers: Sequence[str],
    receipt_path: Path = DEFAULT_RECEIPT_PATH,
    transport: HttpTransport | None = None,
    tls_context: ssl.SSLContext | None = None,
    timeout: float = 10.0,
) -> ActionResult:
    """Sign one policy and deliver the same envelope to one or two controllers."""

    endpoint_labels: list[str] = []
    try:
        spec = action_spec(kind)
        endpoint_labels = [spec.endpoint]
        if not 1 <= len(controllers) <= 2:
            raise ValueError("one or two controller URLs are required")
        for controller in controllers:
            action_endpoint(kind, controller)
        if transport is None and tls_context is None:
            raise ValueError("mTLS is required for policy delivery")
        envelope = prepare_signed_action(
            payload,
            kind=kind,
            key_path=key_path,
            key_id=key_id,
            sequence_path=sequence_path,
        )
        active_transport = transport or UrllibTransport(timeout=timeout, ssl_context=tls_context)
        responses = _post_envelope(envelope, spec, controllers, active_transport)
        write_action_receipt(
            receipt_path,
            status="applied",
            kind=kind,
            endpoints=endpoint_labels,
            sequence=envelope.sequence,
            payload_digest=_payload_digest(payload),
            accepted_controllers=len(responses),
        )
        return ActionResult(envelope.sequence, envelope, responses)
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        write_failure_receipt(receipt_path, kind=kind, endpoints=endpoint_labels, error=exc)
        raise


def require_mtls_context(ca_path: Path | None, cert_path: Path | None, key_path: Path | None) -> ssl.SSLContext:
    """Build the required mTLS context."""

    if ca_path is None or cert_path is None or key_path is None:
        raise ValueError("mTLS requires CA, client certificate, and client key")
    return build_mtls_context(ca_path, cert_path, key_path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m modelctl.operator")
    parser.add_argument("--kind", required=True, help="allow-listed controller action kind")
    parser.add_argument("--payload", type=Path, default=Path("-"), help="JSON file, or - for stdin")
    parser.add_argument("--key", required=True, type=Path, help="0600 Ed25519 private PEM")
    parser.add_argument("--key-id", required=True, help="registered signing key ID")
    parser.add_argument("--sequence", required=True, type=Path, help="durable sequence JSON path")
    parser.add_argument("--controller", required=True, action="append", help="controller origin; repeat once")
    parser.add_argument("--receipt", type=Path, default=DEFAULT_RECEIPT_PATH)
    parser.add_argument("--apply", action="store_true", help="deliver after exact digest confirmation")
    parser.add_argument("--confirm", help="exact payload digest required with --apply")
    parser.add_argument("--tls-ca-file", type=Path)
    parser.add_argument("--tls-cert-file", type=Path)
    parser.add_argument("--tls-key-file", type=Path)
    parser.add_argument("--timeout", type=float, default=10.0)
    return parser


def _read_payload(path: Path, stream: TextIO) -> dict[str, Any]:
    source = stream if str(path) == "-" else path.open(encoding="utf-8")
    try:
        value = json.load(source)
    finally:
        if source is not stream:
            source.close()
    if not isinstance(value, dict):
        raise TypeError("JSON payload must be an object")
    return value


def _validate_controllers(kind: str, controllers: Sequence[str]) -> list[str]:
    if not 1 <= len(controllers) <= 2:
        raise ValueError("one or two controller URLs are required")
    spec = action_spec(kind)
    for controller in controllers:
        action_endpoint(kind, controller)
    return [spec.endpoint]


def main(argv: list[str] | None = None) -> int:
    """Prepare a policy by default, or apply it with explicit confirmation."""

    arguments = _parser().parse_args(argv)
    endpoint_labels: list[str] = []
    try:
        payload = _read_payload(arguments.payload, sys.stdin)
        endpoint_labels = _validate_controllers(arguments.kind, arguments.controller)
        digest = _payload_digest(payload)
        if not arguments.apply:
            envelope = prepare_signed_action(
                payload,
                kind=arguments.kind,
                key_path=arguments.key,
                key_id=arguments.key_id,
                sequence_path=arguments.sequence,
            )
            write_action_receipt(
                arguments.receipt,
                status="prepared",
                kind=arguments.kind,
                endpoints=endpoint_labels,
                sequence=envelope.sequence,
                payload_digest=digest,
                accepted_controllers=0,
            )
            print(
                json.dumps(
                    {
                        "applied": False,
                        "payloadDigest": digest,
                        "envelope": envelope.model_dump(mode="json", by_alias=True),
                    },
                    sort_keys=True,
                )
            )
            return 0
        if arguments.confirm != digest:
            raise ValueError("confirmation digest does not match the payload")
        tls_context = require_mtls_context(
            arguments.tls_ca_file,
            arguments.tls_cert_file,
            arguments.tls_key_file,
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        write_failure_receipt(arguments.receipt, kind=arguments.kind, endpoints=endpoint_labels, error=exc)
        print(f"operator action failed: {type(exc).__name__}", file=sys.stderr)
        return 1

    try:
        result = run_action(
            payload,
            kind=arguments.kind,
            key_path=arguments.key,
            key_id=arguments.key_id,
            sequence_path=arguments.sequence,
            controllers=arguments.controller,
            receipt_path=arguments.receipt,
            tls_context=tls_context,
            timeout=arguments.timeout,
        )
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        print(f"operator action failed: {type(exc).__name__}", file=sys.stderr)
        return 1
    print(json.dumps({"applied": True, "sequence": result.sequence, "acceptedControllers": len(result.responses)}))
    return 0
