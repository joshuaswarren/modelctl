"""Host telemetry reports, local maintenance state, and controller delivery."""
from __future__ import annotations

import json
import os
import tempfile
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from pydantic import Field, field_validator, model_validator

from modelctl.agents.host.transport import HttpResponse, HttpTransport, UrllibTransport
from modelctl.domain.engine import EngineHealth, EngineState, PhysicalEngine
from modelctl.domain.events import Event, EventSeverity
from modelctl.domain.workload import DomainModel
from modelctl.policy.signing import PolicySigner, SignedEnvelope

MaintenanceState = EngineState


class Clock(Protocol):
    """Clock boundary used for timestamps, timing, and retry scheduling."""

    def now(self) -> datetime:
        """Return the current aware time."""
        ...

    def monotonic(self) -> float:
        """Return a monotonic time value."""
        ...


class SystemClock:
    """System clock used by production host agents."""

    def now(self) -> datetime:
        return datetime.now(UTC)

    def monotonic(self) -> float:
        return time.monotonic()


@dataclass(frozen=True)
class EngineObservation:
    """Normalized telemetry returned by one provider collector."""

    engine_id: str
    base_url: str
    aliases: list[str]
    resident_models: list[str]
    in_flight: int
    queue_depth: int
    health: EngineHealth
    collection_time_ms: float
    short_request_latency_ms: float | None
    short_request_latency_samples_ms: list[float]


class Collector(Protocol):
    """Provider-neutral collector boundary."""

    engine_id: str
    base_url: str
    aliases: list[str]
    endpoint: str

    def collect(self) -> EngineObservation:
        """Collect one normalized engine observation."""
        ...


class MaintenanceRecord(DomainModel):
    """Persisted operator state for one host."""

    host_id: str = Field(min_length=1, alias="hostId")
    state: MaintenanceState
    updated_at: datetime = Field(alias="updatedAt")

    @field_validator("updated_at")
    @classmethod
    def require_aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("updatedAt must include a UTC offset")
        return value.astimezone(UTC)


class MaintenanceStateStore:
    """Atomically persist operator maintenance state on the host."""

    def __init__(self, path: Path, *, host_id: str) -> None:
        if not host_id.strip():
            raise ValueError("host_id must not be blank")
        self.path = path
        self.host_id = host_id

    def load(self) -> MaintenanceRecord:
        if not self.path.exists():
            return MaintenanceRecord(hostId=self.host_id, state=MaintenanceState.ACTIVE, updatedAt=datetime.now(UTC))
        try:
            value: Any = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid maintenance state at {self.path}") from exc
        record = MaintenanceRecord.model_validate(value)
        if record.host_id != self.host_id:
            raise ValueError("maintenance state hostId does not match host")
        return record

    def set_state(self, state: MaintenanceState, at: datetime) -> MaintenanceRecord:
        record = MaintenanceRecord(hostId=self.host_id, state=state, updatedAt=at)
        _atomic_json_write(self.path, record.model_dump(mode="json", by_alias=True))
        return record


class ReportSequenceStore:
    """Atomically persist the last signed report sequence."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> int:
        if not self.path.exists():
            return 0
        try:
            value: Any = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid report sequence at {self.path}") from exc
        if not isinstance(value, dict):
            raise TypeError(f"invalid report sequence at {self.path}")
        sequence = value.get("sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            raise ValueError(f"invalid report sequence at {self.path}")
        return sequence

    def commit(self, sequence: int) -> int:
        if sequence < 0:
            raise ValueError("sequence must not be negative")
        current = self.load()
        if sequence <= current:
            return current
        _atomic_json_write(self.path, {"sequence": sequence})
        return sequence


def _atomic_json_write(path: Path, value: object) -> None:
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


class EventStore:
    """Append durable JSONL events for local failures and state changes."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def events(self) -> list[Event]:
        if not self.path.exists():
            return []
        result: list[Event] = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                result.append(Event.model_validate(json.loads(line)))
        return result

    def append(self, event: Event) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        encoded = (json.dumps(event.model_dump(mode="json"), sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        with self.path.open("ab") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())


@dataclass
class HostConfig:
    """Static host identity, collectors, controllers, and N+1 declaration."""

    host_id: str
    engines: Sequence[Collector]
    controllers: list[str] = field(default_factory=list)
    maintenance_state: MaintenanceState = MaintenanceState.ACTIVE
    n1_impossible: bool = False
    n1_impossible_reason: str | None = None

    def __post_init__(self) -> None:
        if not self.host_id.strip():
            raise ValueError("host_id must not be blank")
        if self.n1_impossible and not self.n1_impossible_reason:
            raise ValueError("n1Impossible requires a nonempty reason")
        if not self.n1_impossible and self.n1_impossible_reason is not None:
            raise ValueError("n1ImpossibleReason requires n1Impossible")


class HostReport(DomainModel):
    """Signed payload describing one host's current local truth."""

    kind: str = "host-report"
    schema_version: int = Field(default=1, alias="schemaVersion")
    host_id: str = Field(min_length=1, alias="hostId")
    reported_at: datetime = Field(alias="reportedAt")
    sequence: int = Field(ge=0)
    stale: bool = False
    engines: list[PhysicalEngine] = Field(default_factory=list)
    n1_impossible: bool = Field(default=False, alias="n1Impossible")
    n1_impossible_reason: str | None = Field(default=None, alias="n1ImpossibleReason")
    events: list[Event] = Field(default_factory=list)

    @field_validator("reported_at")
    @classmethod
    def normalize_report_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("reportedAt must include a UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def validate_n1_reason(self) -> HostReport:
        if self.kind != "host-report":
            raise ValueError("kind must be host-report")
        if self.schema_version != 1:
            raise ValueError("schemaVersion must be 1")
        if self.n1_impossible and not self.n1_impossible_reason:
            raise ValueError("n1Impossible requires a nonempty reason")
        if not self.n1_impossible and self.n1_impossible_reason is not None:
            raise ValueError("n1ImpossibleReason requires n1Impossible")
        return self


class HostAgent:
    """Collect, sign, and publish host state without blocking local collection."""

    def __init__(
        self,
        config: HostConfig,
        *,
        signer: PolicySigner,
        state_store: MaintenanceStateStore | None = None,
        events_path: Path | None = None,
        sequence_path: Path | None = None,
        transport: HttpTransport | None = None,
        clock: Clock | None = None,
        report_ttl: timedelta = timedelta(minutes=10),
        retry_base_s: float = 1.0,
        retry_max_s: float = 60.0,
    ) -> None:
        if report_ttl <= timedelta(0):
            raise ValueError("report_ttl must be positive")
        if retry_base_s <= 0 or retry_max_s < retry_base_s:
            raise ValueError("retry bounds are invalid")
        self.config = config
        self.signer = signer
        self.state_store = state_store
        event_path = events_path or Path.home() / ".local" / "state" / "modelctl" / "host-events.jsonl"
        self.event_store = EventStore(event_path)
        if sequence_path is None and state_store is not None:
            sequence_path = state_store.path.with_name(f"{state_store.path.stem}.sequence.json")
        self.sequence_store = ReportSequenceStore(sequence_path) if sequence_path is not None else None
        self.transport = transport or UrllibTransport()
        self.clock = clock or SystemClock()
        self.report_ttl = report_ttl
        self.retry_base_s = retry_base_s
        self.retry_max_s = retry_max_s
        self._sequence = self.sequence_store.load() if self.sequence_store is not None else 0
        self._last_engines: dict[str, PhysicalEngine] = {}
        self._failure_attempts: dict[str, int] = {}
        self._retry_after: dict[str, float] = {}

    def _next_sequence(self) -> int:
        if self.sequence_store is not None:
            current = max(self._sequence, self.sequence_store.load())
            self._sequence = self.sequence_store.commit(current + 1)
        else:
            self._sequence += 1
        return self._sequence

    def _maintenance_state(self) -> MaintenanceState:
        return self.state_store.load().state if self.state_store is not None else self.config.maintenance_state

    def _record_event(self, *, subject: str, severity: EventSeverity, detail: dict[str, Any]) -> Event:
        event = Event(
            id=f"host-{uuid4().hex}",
            time=self.clock.now(),
            subsystem="host-agent",
            severity=severity,
            subject=subject,
            detail=detail,
        )
        self.event_store.append(event)
        return event

    @staticmethod
    def _health_rank(value: EngineHealth) -> int:
        return {
            EngineHealth.HEALTHY: 0,
            EngineHealth.DEGRADED: 1,
            EngineHealth.UNKNOWN: 2,
            EngineHealth.UNHEALTHY: 3,
        }[value]

    def _merge_observations(self, observations: list[EngineObservation]) -> list[PhysicalEngine]:
        merged: dict[str, PhysicalEngine] = {}
        for observation in observations:
            current = merged.get(observation.engine_id)
            if current is None:
                merged[observation.engine_id] = PhysicalEngine(
                    id=observation.engine_id,
                    host=self.config.host_id,
                    baseUrl=observation.base_url,
                    aliases=sorted(set(observation.aliases)),
                    residentModels=observation.resident_models,
                    inFlight=observation.in_flight,
                    activeSlots=observation.in_flight,
                    queueDepth=observation.queue_depth,
                    health=observation.health,
                    collectionTimeMs=observation.collection_time_ms,
                    shortRequestLatencyMs=observation.short_request_latency_ms,
                    shortRequestLatencySamplesMs=observation.short_request_latency_samples_ms,
                    state=self._maintenance_state(),
                )
                continue
            current.aliases = sorted(set(current.aliases) | set(observation.aliases))
            current.resident_models = sorted(set(current.resident_models) | set(observation.resident_models))
            current.in_flight += observation.in_flight
            current.active_slots = current.in_flight
            current.queue_depth += observation.queue_depth
            if self._health_rank(observation.health) > self._health_rank(current.health):
                current.health = observation.health
            current.collection_time_ms = (current.collection_time_ms or 0) + observation.collection_time_ms
            if current.short_request_latency_ms is None:
                current.short_request_latency_ms = observation.short_request_latency_ms
            current.short_request_latency_samples_ms.extend(observation.short_request_latency_samples_ms)

        return sorted(merged.values(), key=lambda engine: engine.id or "")

    def _collect_report(self) -> HostReport:
        observations: list[EngineObservation] = []
        failed_engine_ids: set[str] = set()
        for collector in self.config.engines:
            try:
                observation = collector.collect()
            except (RuntimeError, OSError, ValueError, TypeError) as exc:
                failed_engine_ids.add(collector.engine_id)
                failure_endpoint = getattr(exc, "endpoint", collector.endpoint)
                self._record_event(
                    subject="collector-failed",
                    severity=EventSeverity.ERROR,
                    detail={
                        "engineId": collector.engine_id,
                        "endpoint": failure_endpoint,
                        "error": str(exc),
                    },
                )
            else:
                observations.append(observation)

        engines = self._merge_observations(observations)
        for engine_id in failed_engine_ids:
            if engine_id in self._last_engines and all(engine.id != engine_id for engine in engines):
                engines.append(self._last_engines[engine_id].model_copy(deep=True))
        maintenance_state = self._maintenance_state()
        for engine in engines:
            engine.state = maintenance_state
        engines.sort(key=lambda engine: engine.id or "")
        if engines:
            self._last_engines = {engine.id or engine.host: engine for engine in engines}
        sequence = self._next_sequence()
        report = HostReport(
            hostId=self.config.host_id,
            reportedAt=self.clock.now(),
            sequence=sequence,
            stale=bool(failed_engine_ids),
            engines=engines,
            n1Impossible=self.config.n1_impossible,
            n1ImpossibleReason=self.config.n1_impossible_reason,
            events=self.event_store.events(),
        )
        return report


    def collect_report(self) -> HostReport:
        return self._collect_report()

    def collect_envelope(self) -> SignedEnvelope:
        report = self._collect_report()
        payload = report.model_dump(mode="json", by_alias=True)
        return self.signer.sign(
            payload,
            issued_at=report.reported_at,
            sequence=report.sequence,
            ttl=self.report_ttl,
        )

    def publish(self, envelope: SignedEnvelope) -> dict[str, bool]:
        body = envelope.model_dump_json(by_alias=True).encode("utf-8")
        results: dict[str, bool] = {}
        for controller in self.config.controllers:
            if self.clock.monotonic() < self._retry_after.get(controller, 0.0):
                results[controller] = False
                continue
            try:
                response = self.transport.post(
                    controller,
                    body,
                    {"content-type": "application/json", "x-modelctl-kind": "host-report"},
                )
                if response.status_code < 200 or response.status_code >= 300:
                    raise OSError(f"POST returned HTTP {response.status_code}")
            except (RuntimeError, OSError, ValueError, TypeError) as exc:
                attempt = self._failure_attempts.get(controller, 0) + 1
                self._failure_attempts[controller] = attempt
                exponent = min(attempt - 1, 20)
                delay = min(self.retry_max_s, self.retry_base_s * (2**exponent))
                self._retry_after[controller] = self.clock.monotonic() + delay
                self._record_event(
                    subject="controller-post-failed",
                    severity=EventSeverity.ERROR,
                    detail={"controller": controller, "error": str(exc), "retryAfterSeconds": delay},
                )
                results[controller] = False
            else:
                self._failure_attempts.pop(controller, None)
                self._retry_after.pop(controller, None)
                results[controller] = True
        return results

    def collect_and_publish(self) -> SignedEnvelope:
        envelope = self.collect_envelope()
        if self.config.controllers:
            self.publish(envelope)
        return envelope

    def collect_once(self) -> SignedEnvelope:
        return self.collect_and_publish()


__all__ = [
    "Clock",
    "Collector",
    "EngineObservation",
    "EventStore",
    "HostAgent",
    "HostConfig",
    "HostReport",
    "HttpResponse",
    "HttpTransport",
    "MaintenanceRecord",
    "MaintenanceState",
    "MaintenanceStateStore",
    "ReportSequenceStore",
    "SystemClock",
]
