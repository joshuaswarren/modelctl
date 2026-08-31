"""Canonical JSON and Ed25519 signing for policy envelopes."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)


def _rfc3339(value: datetime) -> str:
    """Return an aware timestamp in the shared UTC wire format."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _json_ready(value: Any) -> Any:
    """Convert supported values recursively to JSON-compatible primitives."""

    if isinstance(value, BaseModel):
        return _json_ready(value.model_dump(mode="python", by_alias=True, exclude_none=True))
    if isinstance(value, Enum):
        return _json_ready(value.value)
    if isinstance(value, datetime):
        return _rfc3339(value)
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_json_ready(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError(f"unsupported canonical JSON value: {type(value).__name__}")


def canonical_json(value: Any) -> bytes:
    """Serialize a value with sorted keys and no insignificant whitespace."""

    return json.dumps(
        _json_ready(value),
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def bundle_id(payload: Any) -> str:
    """Return the SHA-256 content address of a policy payload."""

    return hashlib.sha256(canonical_json(payload)).hexdigest()


def generate_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate one Ed25519 signing key pair."""

    private = ed25519.Ed25519PrivateKey.generate()
    return private, private.public_key()


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return value.astimezone(UTC)


def _signature_input(
    *, key_id: str, issued_at: datetime, expires_at: datetime, nonce: str, sequence: int, payload_digest: str
) -> bytes:
    return canonical_json(
        {
            "expiresAt": _rfc3339(expires_at),
            "issuedAt": _rfc3339(issued_at),
            "keyId": key_id,
            "nonce": nonce,
            "payloadDigest": payload_digest,
            "sequence": sequence,
        }
    )


class SignedEnvelope(BaseModel):
    """A signed, replay-fenced policy payload."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    key_id: str = Field(min_length=1, alias="keyId")
    issued_at: datetime = Field(alias="issuedAt")
    expires_at: datetime = Field(alias="expiresAt")
    nonce: str = Field(min_length=1)
    sequence: int = Field(ge=0)
    payload_digest: str = Field(pattern=r"^[0-9a-f]{64}$", alias="payloadDigest")
    signature: str = Field(min_length=1)
    payload: dict[str, Any]

    @field_validator("issued_at", "expires_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return _utc(value)

    @field_validator("signature")
    @classmethod
    def validate_signature_encoding(cls, value: str) -> str:
        try:
            decoded = base64.b64decode(value.encode("ascii"), validate=True)
        except (UnicodeEncodeError, binascii.Error) as exc:
            raise ValueError("signature must be base64") from exc
        if len(decoded) != 64:
            raise ValueError("signature must contain 64 Ed25519 bytes")
        return value

    @model_validator(mode="after")
    def validate_expiry(self) -> SignedEnvelope:
        if self.expires_at <= self.issued_at:
            raise ValueError("expiresAt must be after issuedAt")
        return self

    @field_serializer("issued_at", "expires_at")
    def serialize_timestamp(self, value: datetime) -> str:
        return _rfc3339(value)


class PolicySigner:
    """Sign policy payloads with one identified Ed25519 key."""

    def __init__(self, private_key: ed25519.Ed25519PrivateKey, key_id: str) -> None:
        if not key_id:
            raise ValueError("key_id must not be empty")
        self._private_key = private_key
        self.key_id = key_id

    def sign(
        self,
        payload: dict[str, Any],
        *,
        issued_at: datetime | None = None,
        expires_at: datetime | None = None,
        nonce: str | None = None,
        sequence: int = 0,
        ttl: timedelta = timedelta(hours=1),
    ) -> SignedEnvelope:
        if sequence < 0:
            raise ValueError("sequence must be non-negative")
        if ttl <= timedelta(0) and expires_at is None:
            raise ValueError("ttl must be positive")
        issued = _utc(issued_at) if issued_at is not None else datetime.now(UTC)
        expires = _utc(expires_at) if expires_at is not None else issued + ttl
        actual_nonce = nonce if nonce is not None else f"{uuid4().hex}{secrets.token_hex(8)}"
        digest = bundle_id(payload)
        signature = self._private_key.sign(
            _signature_input(
                key_id=self.key_id,
                issued_at=issued,
                expires_at=expires,
                nonce=actual_nonce,
                sequence=sequence,
                payload_digest=digest,
            )
        )
        return SignedEnvelope(
            keyId=self.key_id,
            issuedAt=issued,
            expiresAt=expires,
            nonce=actual_nonce,
            sequence=sequence,
            payloadDigest=digest,
            signature=base64.b64encode(signature).decode("ascii"),
            payload=payload,
        )
