"""Production command for the modelctl controller."""
from __future__ import annotations

import argparse
import base64
import hmac
import json
import os
import ssl
import stat
from collections.abc import Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import uvicorn
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from modelctl.agents.host.transport import build_mtls_context
from modelctl.controller.api import Controller, create_app
from modelctl.controller.auth import PrincipalRegistry
from modelctl.controller.http_peer import HttpReplicationPeer
from modelctl.controller.promotion import FencingReceipt
from modelctl.policy.signing import PolicySigner


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be an object")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a nonempty string")
    return value


def _secret_file(path: Path, label: str) -> str:
    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError(f"{label} permissions must be 0600")
    value = path.read_text(encoding="utf-8").strip()
    if not value:
        raise ValueError(f"{label} must not be empty")
    return value


def load_principals(path: Path) -> PrincipalRegistry:
    """Load scoped Ed25519 public keys from a strict JSON file."""

    try:
        root = _object(json.loads(path.read_text(encoding="utf-8")), "principals file")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not load principals from {path}") from exc
    values = root.get("principals")
    if not isinstance(values, list) or not values:
        raise ValueError("principals must be a nonempty list")
    registry = PrincipalRegistry()
    for index, raw_value in enumerate(values):
        value = _object(raw_value, f"principals[{index}]")
        if set(value) != {"keyId", "publicKey", "scopes"}:
            raise ValueError(f"principals[{index}] has unsupported fields")
        key_id = _text(value.get("keyId"), f"principals[{index}].keyId")
        public_key_text = _text(value.get("publicKey"), f"principals[{index}].publicKey")
        scopes = value.get("scopes")
        if not isinstance(scopes, list) or not scopes or not all(isinstance(item, str) and item for item in scopes):
            raise ValueError(f"principals[{index}].scopes must be nonempty strings")
        try:
            public_key = base64.b64decode(public_key_text, validate=True)
            parsed_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"principals[{index}].publicKey is not a raw Ed25519 key") from exc
        registry.register(key_id, parsed_key, scopes)
    return registry


def load_signer(path: Path, key_id: str) -> PolicySigner:
    """Load one private Ed25519 signer from a mode-0600 PEM file."""

    if stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError("replication private key permissions must be 0600")
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(f"could not load replication private key from {path}") from exc
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise TypeError("replication private key must be Ed25519")
    return PolicySigner(key, key_id)

def _exact_bool(value: str, label: str) -> bool:
    if value == "true":
        return True
    if value == "false":
        return False
    raise ValueError(f"{label} must be exactly true or false")


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    return default if value is None else _exact_bool(value, name)


def _cli_bool(value: str) -> bool:
    return _exact_bool(value, "--observe-only")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="modelctl-controller")
    data_dir = os.environ.get("MODELCTL_DATA_DIR")
    parser.add_argument("--db-path", type=Path, default=Path(data_dir) / "controller.db" if data_dir else None)
    parser.add_argument("--controller-id", default=os.environ.get("MODELCTL_CONTROLLER_ID"))
    parser.add_argument("--role", choices=("active", "standby", "follower"), default=os.environ.get("MODELCTL_ROLE"))
    parser.add_argument("--epoch", type=int, default=int(os.environ.get("MODELCTL_EPOCH", "1")))
    parser.add_argument("--fleet-token", default=os.environ.get("MODELCTL_READ_BEARER_TOKEN"))
    parser.add_argument(
        "--fleet-token-file",
        type=Path,
        default=os.environ.get("MODELCTL_READ_BEARER_TOKEN_FILE"),
    )
    parser.add_argument("--principals", type=Path, default=os.environ.get("MODELCTL_TRUSTED_SIGNERS_FILE"))
    parser.add_argument("--replication-key-id", default=os.environ.get("MODELCTL_SIGNING_KEY_ID"))
    parser.add_argument(
        "--replication-private-key",
        type=Path,
        default=os.environ.get("MODELCTL_SIGNING_PRIVATE_KEY_FILE"),
    )
    parser.add_argument("--peer-url", default=os.environ.get("MODELCTL_PEER_URL"))
    parser.add_argument(
        "--replication-timeout",
        type=float,
        default=float(os.environ.get("MODELCTL_REPLICATION_TIMEOUT_SECONDS", "5")),
    )
    parser.add_argument("--fencing-token-file", type=Path, default=os.environ.get("MODELCTL_FENCING_TOKEN_FILE"))
    parser.add_argument("--listen-host", default=os.environ.get("MODELCTL_LISTEN_HOST", "127.0.0.1"))
    parser.add_argument("--listen-port", type=int, default=int(os.environ.get("MODELCTL_LISTEN_PORT", "8443")))
    parser.add_argument("--tls-ca-file", type=Path, default=os.environ.get("MODELCTL_TLS_CA_FILE"))
    parser.add_argument("--tls-cert-file", type=Path, default=os.environ.get("MODELCTL_TLS_CERT_FILE"))
    parser.add_argument("--tls-key-file", type=Path, default=os.environ.get("MODELCTL_TLS_KEY_FILE"))
    parser.add_argument(
        "--observe-only",
        type=_cli_bool,
        default=_env_bool("MODELCTL_OBSERVE_ONLY"),
    )
    return parser


def _required(value: Any, label: str) -> Any:
    if value is None or value == "":
        raise ValueError(f"{label} is required")
    return value



def _tls_context(args: argparse.Namespace) -> ssl.SSLContext | None:
    values = (args.tls_ca_file, args.tls_cert_file, args.tls_key_file)
    if all(value is None for value in values):
        return None
    if any(value is None for value in values):
        raise ValueError("TLS requires --tls-ca-file, --tls-cert-file, and --tls-key-file")
    return build_mtls_context(args.tls_ca_file, args.tls_cert_file, args.tls_key_file)

def build_controller(
    args: argparse.Namespace,
    *,
    tls_context: ssl.SSLContext | None = None,
) -> Controller:
    db_path = _required(args.db_path, "--db-path")
    tls_context = tls_context if tls_context is not None else _tls_context(args)
    controller_id = _text(_required(args.controller_id, "--controller-id"), "--controller-id")
    role = _text(_required(args.role, "--role"), "--role")
    principals_path = _required(args.principals, "--principals")
    fleet_token = args.fleet_token
    if args.fleet_token_file is not None:
        if fleet_token is not None:
            raise ValueError("set only one of --fleet-token and --fleet-token-file")
        fleet_token = _secret_file(args.fleet_token_file, "fleet token file")
    fleet_token = _text(_required(fleet_token, "fleet token"), "fleet token")

    signer: PolicySigner | None = None
    if args.replication_private_key is not None or args.replication_key_id is not None:
        key_path = _required(args.replication_private_key, "--replication-private-key")
        key_id = _text(_required(args.replication_key_id, "--replication-key-id"), "--replication-key-id")
        signer = load_signer(key_path, key_id)

    fencing_token: str | None = None
    if args.fencing_token_file is not None:
        fencing_token = _secret_file(args.fencing_token_file, "fencing token file")

    def verify_fencing(receipt: FencingReceipt) -> bool:
        return (
            fencing_token is not None
            and receipt.token is not None
            and hmac.compare_digest(receipt.token.encode(), fencing_token.encode())
        )

    controller = Controller(
        db_path,
        controller_id=controller_id,
        role=role,
        epoch=args.epoch,
        fleet_token=fleet_token,
        principals=load_principals(principals_path),
        replication_signer=signer,
        fencing_verifier=verify_fencing,
        observe_only=args.observe_only,
    )
    if args.peer_url is not None:
        if signer is None:
            raise ValueError("a replication signer is required when --peer-url is set")
        if urlsplit(args.peer_url).scheme == "https" and tls_context is None:
            raise ValueError("an HTTPS replication peer requires mutual TLS configuration")
        controller.set_peer(
            HttpReplicationPeer(
                args.peer_url,
                sign_control=controller.sign_replication_control,
                timeout=args.replication_timeout,
                ssl_context=tls_context,
            )
        )
        controller.recover_pending_operations()
    return controller


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    tls_context = _tls_context(args)
    controller = build_controller(args, tls_context=tls_context)
    uvicorn.run(
        create_app(controller),
        host=args.listen_host,
        port=args.listen_port,
        ssl_keyfile=str(args.tls_key_file) if tls_context is not None else None,
        ssl_certfile=str(args.tls_cert_file) if tls_context is not None else None,
        ssl_ca_certs=str(args.tls_ca_file) if tls_context is not None else None,
        ssl_cert_reqs=ssl.CERT_REQUIRED if tls_context is not None else ssl.CERT_NONE,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
