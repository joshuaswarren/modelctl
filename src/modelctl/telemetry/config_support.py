"""Strict configuration helpers shared by telemetry producers."""
from __future__ import annotations

import ssl
import stat
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from modelctl.agents.host.transport import build_mtls_context
from modelctl.policy.signing import PolicySigner


def require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be an object")
    return value


def require_text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"{label} must be a nonempty string")
    return value


def positive_number(value: Any, label: str, default: float) -> float:
    result = default if value is None else value
    if isinstance(result, bool) or not isinstance(result, (int, float)) or result <= 0:
        raise ValueError(f"{label} must be positive")
    return float(result)


def resolve_path(config_path: Path, value: Any, label: str) -> Path:
    candidate = Path(require_text(value, label)).expanduser()
    return candidate if candidate.is_absolute() else config_path.parent / candidate


def load_ed25519_signer(config_path: Path, value: Mapping[str, Any]) -> PolicySigner:
    key_id = require_text(value.get("keyId"), "signing.keyId")
    key_path = resolve_path(config_path, value.get("privateKeyPath"), "signing.privateKeyPath")
    if stat.S_IMODE(key_path.stat().st_mode) & 0o077:
        raise ValueError(f"signing key permissions must be 0600 at {key_path}")
    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(f"could not load signing key at {key_path}") from exc
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise TypeError("signing key must be an Ed25519 private key")
    return PolicySigner(key, key_id)


def load_mtls_context(config_path: Path, value: Any) -> ssl.SSLContext | None:
    if value is None:
        return None
    tls = require_mapping(value, "tls")
    if set(tls) != {"caPath", "clientCertPath", "clientKeyPath"}:
        raise ValueError("tls must contain only caPath, clientCertPath, and clientKeyPath")
    return build_mtls_context(
        resolve_path(config_path, tls.get("caPath"), "tls.caPath"),
        resolve_path(config_path, tls.get("clientCertPath"), "tls.clientCertPath"),
        resolve_path(config_path, tls.get("clientKeyPath"), "tls.clientKeyPath"),
    )
