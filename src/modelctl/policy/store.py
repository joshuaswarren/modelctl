"""Trusted-key rotation and last-known-good policy storage."""
from __future__ import annotations

import base64
import binascii
import json
import os
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

from cryptography.hazmat.primitives.asymmetric import ed25519

from modelctl.policy.signing import SignedEnvelope, bundle_id

PublicKey = bytes | ed25519.Ed25519PublicKey


class EnvelopeVerifier(Protocol):
    """Protocol required by last-known-good policy storage."""

    def verify(self, envelope: SignedEnvelope, *, record_replay: bool = True) -> bool: ...


def _public_key(value: PublicKey) -> ed25519.Ed25519PublicKey:
    if isinstance(value, ed25519.Ed25519PublicKey):
        return value
    return ed25519.Ed25519PublicKey.from_public_bytes(value)


def _atomic_write_json(path: Path, value: object) -> None:
    """Write JSON and replace the target only after an fsync."""

    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        directory_descriptor = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid policy state at {path}") from exc


class PolicyKeyStore:
    """Trust store with overlapping rotation, revocation, and atomic persistence."""

    def __init__(self, keys: Mapping[str, PublicKey] | None = None, *, path: Path | None = None) -> None:
        self.path = path
        self._keys: dict[str, ed25519.Ed25519PublicKey] = {}
        self._revoked: set[str] = set()
        if path is not None and path.exists():
            self._load(path)
        elif keys is not None:
            for key_id, public_key in keys.items():
                self._keys[key_id] = _public_key(public_key)
            self._persist()

    def _load(self, path: Path) -> None:
        document = _read_json(path)
        if not isinstance(document, dict) or not isinstance(document.get("keys"), dict):
            raise TypeError(f"invalid key store at {path}")
        try:
            self._keys = {
                key_id: _public_key(base64.b64decode(encoded.encode("ascii"), validate=True))
                for key_id, encoded in document["keys"].items()
                if isinstance(key_id, str) and isinstance(encoded, str)
            }
        except (binascii.Error, UnicodeEncodeError, ValueError, TypeError) as exc:
            raise ValueError(f"invalid key store at {path}") from exc
        revoked = document.get("revoked", [])
        if not isinstance(revoked, list) or not all(isinstance(key_id, str) for key_id in revoked):
            raise ValueError(f"invalid key revocation state at {path}")
        self._revoked = set(revoked)
        if not self._revoked <= self._keys.keys():
            raise ValueError(f"revoked key is missing from key store at {path}")

    def _persist(self) -> None:
        if self.path is None:
            return
        _atomic_write_json(
            self.path,
            {
                "keys": {
                    key_id: base64.b64encode(key.public_bytes_raw()).decode("ascii")
                    for key_id, key in self._keys.items()
                },
                "revoked": sorted(self._revoked),
            },
        )

    def add(self, key_id: str, public_key: PublicKey) -> None:
        if not key_id:
            raise ValueError("key_id must not be empty")
        if key_id in self._revoked:
            raise ValueError("revoked key_id cannot be reused")
        self._keys[key_id] = _public_key(public_key)
        self._persist()

    def revoke(self, key_id: str) -> None:
        if key_id not in self._keys:
            raise KeyError(key_id)
        self._revoked.add(key_id)
        self._persist()

    def recover_from_compromise(
        self,
        *,
        compromised_key_id: str,
        replacement_key_id: str,
        replacement_public_key: PublicKey,
    ) -> None:
        """Add a replacement and revoke the compromised key in one write."""

        if compromised_key_id not in self._keys:
            raise KeyError(compromised_key_id)
        if not replacement_key_id:
            raise ValueError("replacement_key_id must not be empty")
        if compromised_key_id == replacement_key_id or replacement_key_id in self._keys:
            raise ValueError("replacement key_id must be new")
        self._keys[replacement_key_id] = _public_key(replacement_public_key)
        self._revoked.add(compromised_key_id)
        self._revoked.discard(replacement_key_id)
        self._persist()

    def is_trusted(self, key_id: str) -> bool:
        return key_id in self._keys and key_id not in self._revoked

    def get(self, key_id: str) -> ed25519.Ed25519PublicKey | None:
        if not self.is_trusted(key_id):
            return None
        return self._keys[key_id]

    @property
    def revoked(self) -> frozenset[str]:
        return frozenset(self._revoked)

    def public_keys(self) -> dict[str, bytes]:
        return {
            key_id: key.public_bytes_raw()
            for key_id, key in self._keys.items()
            if key_id not in self._revoked
        }


class PolicyStore:
    """Last-known-good envelope store for a receiver."""

    def __init__(self, key_store: PolicyKeyStore | None = None, *, path: Path | None = None) -> None:
        self.keys = key_store or PolicyKeyStore()
        self.path = path
        self._current: SignedEnvelope | None = None
        if path is not None and path.exists():
            candidate = SignedEnvelope.model_validate(_read_json(path))
            if bundle_id(candidate.payload) != candidate.payload_digest:
                raise ValueError(f"invalid policy digest at {path}")
            self._current = candidate

    @property
    def current(self) -> SignedEnvelope | None:
        return self._current

    @property
    def current_payload(self) -> dict[str, Any] | None:
        return None if self._current is None else self._current.payload

    def apply(self, envelope: SignedEnvelope, verifier: EnvelopeVerifier) -> bool:
        if not verifier.verify(envelope):
            return False
        if self.path is not None:
            _atomic_write_json(self.path, envelope.model_dump(mode="json", by_alias=True))
        self._current = envelope
        return True
