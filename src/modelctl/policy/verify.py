"""Fail-closed verification for signed policy envelopes."""
from __future__ import annotations

import base64
import binascii
import hmac
import json
import os
import tempfile
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature

from modelctl.policy.signing import SignedEnvelope, _signature_input, bundle_id
from modelctl.policy.store import PolicyKeyStore, PublicKey


class PolicyVerifier:
    """Verify provenance, freshness, replay, digest, and sequence fences."""

    def __init__(
        self,
        trusted_keys: Mapping[str, PublicKey] | PolicyKeyStore,
        *,
        now: Callable[[], datetime] | None = None,
        max_future_skew: timedelta = timedelta(0),
        replay_path: Path | None = None,
    ) -> None:
        if max_future_skew < timedelta(0):
            raise ValueError("max_future_skew must not be negative")
        self._keys = trusted_keys if isinstance(trusted_keys, PolicyKeyStore) else PolicyKeyStore(trusted_keys)
        self._now = now or (lambda: datetime.now(UTC))
        self._max_future_skew = max_future_skew
        self.replay_path = replay_path
        self._nonces: set[str] = set()
        self._sequences: dict[str, int] = {}
        if replay_path is not None and replay_path.exists():
            self._load_replay(replay_path)

    def _load_replay(self, path: Path) -> None:
        try:
            document: Any = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid replay state at {path}") from exc
        if not isinstance(document, dict):
            raise TypeError(f"invalid replay state at {path}")
        nonces = document.get("nonces", [])
        sequences = document.get("sequences", {})
        if not isinstance(nonces, list) or not all(isinstance(nonce, str) for nonce in nonces):
            raise ValueError(f"invalid replay nonces at {path}")
        if not isinstance(sequences, dict) or not all(
            isinstance(key_id, str) and isinstance(sequence, int) and sequence >= 0
            for key_id, sequence in sequences.items()
        ):
            raise ValueError(f"invalid replay sequences at {path}")
        self._nonces = set(nonces)
        self._sequences = dict(sequences)

    def _persist_replay(self, nonces: set[str], sequences: dict[str, int]) -> None:
        if self.replay_path is None:
            return
        self.replay_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{self.replay_path.name}.", dir=self.replay_path.parent)
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(
                    {"nonces": sorted(nonces), "sequences": sequences},
                    handle,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.replay_path)
            directory_descriptor = os.open(self.replay_path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except BaseException:
            temporary_path.unlink(missing_ok=True)
            raise

    @property
    def key_store(self) -> PolicyKeyStore:
        return self._keys

    def verify(self, envelope: SignedEnvelope, *, record_replay: bool = True) -> bool:
        """Return false for every invalid, expired, future, replayed, or stale envelope."""

        try:
            key = self._keys.get(envelope.key_id)
            if key is None:
                return False
            now = self._now()
            if now.tzinfo is None or now.utcoffset() is None:
                return False
            now_utc = now.astimezone(UTC)
            issued_at = envelope.issued_at.astimezone(UTC)
            expires_at = envelope.expires_at.astimezone(UTC)
            if issued_at > now_utc + self._max_future_skew or expires_at <= now_utc:
                return False
            if envelope.nonce in self._nonces:
                return False
            if envelope.sequence <= self._sequences.get(envelope.key_id, -1):
                return False
            expected_digest = bundle_id(envelope.payload)
            if not hmac.compare_digest(expected_digest, envelope.payload_digest):
                return False
            signature = base64.b64decode(envelope.signature.encode("ascii"), validate=True)
            key.verify(
                signature,
                _signature_input(
                    key_id=envelope.key_id,
                    issued_at=issued_at,
                    expires_at=expires_at,
                    nonce=envelope.nonce,
                    sequence=envelope.sequence,
                    payload_digest=envelope.payload_digest,
                ),
            )
            if record_replay:
                nonces = self._nonces | {envelope.nonce}
                sequences = {**self._sequences, envelope.key_id: envelope.sequence}
                self._persist_replay(nonces, sequences)
                self._nonces = nonces
                self._sequences = sequences
            return True
        except (InvalidSignature, ValueError, TypeError, UnicodeEncodeError, binascii.Error, OSError):
            return False
