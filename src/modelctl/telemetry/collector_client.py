"""Normalize broker snapshots and publish signed quota records."""
from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlsplit
from uuid import uuid4

import yaml
from pydantic import Field, ValidationError, field_validator

from modelctl.agents.host.report import EventStore, ReportSequenceStore
from modelctl.agents.host.transport import HttpResponse, UrllibTransport
from modelctl.domain.events import Event, EventSeverity
from modelctl.domain.runway import RunwaySource
from modelctl.domain.workload import DomainModel
from modelctl.policy.signing import PolicySigner, SignedEnvelope
from modelctl.telemetry.config_support import (
    load_ed25519_signer,
    load_mtls_context,
    positive_number,
    require_mapping,
    require_text,
    resolve_path,
)
from modelctl.telemetry.contracts import QuotaRecord, QuotaUnit


class QuotaSnapshot(DomainModel):
    """One normalized reading from broker or dashboard source data."""

    provider: str = Field(min_length=1)
    account_label: str = Field(min_length=1, max_length=128, alias="accountLabel")
    quota_used: float | int = Field(ge=0, alias="quotaUsed")
    quota_unit: QuotaUnit = Field(default=QuotaUnit.TOKENS, alias="quotaUnit")
    reset_time: datetime = Field(alias="resetTime")
    captured_at: datetime = Field(alias="capturedAt")

    @field_validator("reset_time", "captured_at")
    @classmethod
    def normalize_times(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("snapshot timestamps must include a UTC offset")
        return value.astimezone(UTC)


def snapshot_record(snapshot: QuotaSnapshot, source: RunwaySource | str) -> QuotaRecord:
    """Attach an explicit source class to one normalized snapshot."""

    source_class = source if isinstance(source, RunwaySource) else RunwaySource(source)
    return QuotaRecord(
        provider=snapshot.provider,
        accountLabel=snapshot.account_label,
        quotaUsed=snapshot.quota_used,
        quotaUnit=snapshot.quota_unit,
        resetTime=snapshot.reset_time,
        sourceClass=source_class,
        freshnessTime=snapshot.captured_at,
    )


@dataclass(frozen=True)
class QuotaPublishResult:
    """One signed record and its per-controller delivery results."""

    envelope: SignedEnvelope
    deliveries: Mapping[str, bool]


class PostTransport(Protocol):
    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> HttpResponse: ...


class QuotaCollectorClient:
    """Allocate durable sequences, sign records, and post every record to both controllers."""

    def __init__(
        self,
        *,
        signer: PolicySigner,
        controllers: Sequence[str],
        sequence_store: ReportSequenceStore,
        transport: PostTransport,
        event_store: EventStore,
        now: Callable[[], datetime],
        ttl: timedelta = timedelta(minutes=5),
    ) -> None:
        if ttl <= timedelta(0):
            raise ValueError("quota envelope ttl must be positive")
        endpoints = list(dict.fromkeys(self._endpoint(value) for value in controllers))
        if not endpoints:
            raise ValueError("at least one controller is required")
        self.signer = signer
        self.controllers = endpoints
        self.sequence_store = sequence_store
        self.transport = transport
        self.event_store = event_store
        self.now = now
        self.ttl = ttl

    @staticmethod
    def _endpoint(value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"controller URL is invalid: {value}")
        if parsed.path.rstrip("/") == "/v1/quota":
            return value.rstrip("/")
        if parsed.path not in {"", "/"}:
            raise ValueError(f"controller URL has an unsupported path: {value}")
        return f"{value.rstrip('/')}/v1/quota"

    def _next_sequence(self) -> int:
        sequence = self.sequence_store.load() + 1
        self.sequence_store.commit(sequence)
        return sequence

    def _sign(self, record: QuotaRecord) -> SignedEnvelope:
        issued_at = self.now()
        if issued_at.tzinfo is None or issued_at.utcoffset() is None:
            raise ValueError("quota collector clock must include a UTC offset")
        return self.signer.sign(
            record.model_dump(mode="json", by_alias=True),
            issued_at=issued_at.astimezone(UTC),
            sequence=self._next_sequence(),
            ttl=self.ttl,
        )

    def _delivery_failed(self, controller: str, sequence: int, reason: str) -> None:
        self.event_store.append(
            Event(
                id=uuid4().hex,
                time=self.now(),
                subsystem="quota-collector",
                severity=EventSeverity.ERROR,
                subject="quota-delivery-failed",
                detail={"controller": controller, "sequence": sequence, "reason": reason},
            )
        )

    def publish(self, records: Sequence[QuotaRecord]) -> list[QuotaPublishResult]:
        results: list[QuotaPublishResult] = []
        for record in records:
            envelope = self._sign(record)
            body = envelope.model_dump_json(by_alias=True).encode("utf-8")
            deliveries: dict[str, bool] = {}
            for controller in self.controllers:
                try:
                    response = self.transport.post(
                        controller,
                        body,
                        {"content-type": "application/json", "x-modelctl-kind": "quota"},
                    )
                    delivered = 200 <= response.status_code < 300
                    deliveries[controller] = delivered
                    if not delivered:
                        self._delivery_failed(controller, envelope.sequence, f"http-{response.status_code}")
                except (OSError, RuntimeError, TypeError, ValueError) as exc:
                    deliveries[controller] = False
                    self._delivery_failed(controller, envelope.sequence, type(exc).__name__)
            results.append(QuotaPublishResult(envelope, deliveries))
        return results




def _load_source(path: Path, source_class: RunwaySource) -> list[QuotaRecord]:
    try:
        value: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"could not load quota source at {path}") from exc
    if not isinstance(value, list):
        raise TypeError(f"quota source at {path} must contain a JSON list")
    records: list[QuotaRecord] = []
    for index, raw_snapshot in enumerate(value):
        try:
            snapshot = QuotaSnapshot.model_validate(raw_snapshot)
            records.append(snapshot_record(snapshot, source_class))
        except ValidationError as exc:
            raise ValueError(f"quota source {path} record {index} is invalid") from exc
    return records


def load_collector_config(
    path: Path,
    *,
    transport: PostTransport | None = None,
    now: Callable[[], datetime] | None = None,
) -> tuple[QuotaCollectorClient, list[QuotaRecord]]:
    """Load production collector configuration and its current sanitized source records."""

    try:
        value: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"could not load collector config at {path}") from exc
    root = require_mapping(value, "collector config")
    controllers = root.get("controllers")
    if not isinstance(controllers, list) or not controllers:
        raise ValueError("controllers must be a nonempty list")
    controller_values = [require_text(item, "controller") for item in controllers]
    source_values = root.get("sources")
    if not isinstance(source_values, list) or not source_values:
        raise ValueError("sources must be a nonempty list")
    records: list[QuotaRecord] = []
    for index, raw_source in enumerate(source_values):
        source = require_mapping(raw_source, f"sources[{index}]")
        if set(source) != {"path", "sourceClass"}:
            raise ValueError(f"sources[{index}] must contain only path and sourceClass")
        try:
            source_class = RunwaySource(
                require_text(source.get("sourceClass"), f"sources[{index}].sourceClass")
            )
        except ValueError as exc:
            raise ValueError(f"sources[{index}].sourceClass is invalid") from exc
        records.extend(
            _load_source(
                resolve_path(path, source.get("path"), f"sources[{index}].path"),
                source_class,
            )
        )
    timeout = positive_number(root.get("timeoutSeconds"), "timeoutSeconds", 10.0)
    ttl_seconds = positive_number(root.get("recordTtlSeconds"), "recordTtlSeconds", 300.0)
    ssl_context = load_mtls_context(path, root.get("tls"))
    client = QuotaCollectorClient(
        signer=load_ed25519_signer(path, require_mapping(root.get("signing"), "signing")),
        controllers=controller_values,
        sequence_store=ReportSequenceStore(
            resolve_path(path, root.get("sequencePath", "quota-sequence.json"), "sequencePath")
        ),
        transport=transport or UrllibTransport(timeout=timeout, ssl_context=ssl_context),
        event_store=EventStore(
            resolve_path(path, root.get("eventsPath", "quota-events.jsonl"), "eventsPath")
        ),
        now=now or (lambda: datetime.now(UTC)),
        ttl=timedelta(seconds=ttl_seconds),
    )
    return client, records
