"""Physical model engine state and admission facts."""
from __future__ import annotations

from enum import Enum
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from modelctl.domain.workload import DomainModel


class EngineState(str, Enum):
    ACTIVE = "active"
    DRAINING = "draining"
    TRAINING = "training"
    OFFLINE = "offline"


class EngineHealth(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class PhysicalEngine(DomainModel):
    """State for one physical engine across all of its aliases."""

    id: str | None = Field(default=None, min_length=1)
    host: str = Field(min_length=1)
    base_url: str | None = Field(default=None, alias="baseUrl")
    aliases: list[str] = Field(default_factory=list)
    resident_models: list[str] = Field(default_factory=list, alias="residentModels")
    in_flight: int = Field(default=0, ge=0, alias="inFlight")
    active_slots: int = Field(default=0, ge=0, alias="activeSlots")
    max_slots: int = Field(default=4, ge=1, alias="maxSlots")
    interactive_reserved: int = Field(default=1, ge=0, alias="interactiveReserved")
    queue_depth: int = Field(default=0, ge=0, alias="queueDepth")
    health: EngineHealth = EngineHealth.UNKNOWN
    collection_time_ms: float | None = Field(default=None, ge=0, alias="collectionTimeMs")
    short_request_latency_ms: float | None = Field(default=None, ge=0, alias="shortRequestLatencyMs")
    short_request_latency_samples_ms: list[float] = Field(
        default_factory=list,
        alias="shortRequestLatencySamplesMs",
    )
    state: EngineState = EngineState.ACTIVE

    @field_validator("aliases", "resident_models")
    @classmethod
    def reject_blank_names(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("engine names must not be blank")
        return values

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("baseUrl must be an HTTP(S) URL without credentials, query, or fragment")
        return value.rstrip("/")


    @field_validator("short_request_latency_samples_ms")
    @classmethod
    def reject_negative_latency_samples(cls, values: list[float]) -> list[float]:
        if any(value < 0 for value in values):
            raise ValueError("latency samples must not be negative")
        return values

    @model_validator(mode="after")
    def validate_capacity(self) -> PhysicalEngine:
        if self.id is None:
            self.id = self.host
        if self.active_slots > self.max_slots:
            raise ValueError("activeSlots must not exceed maxSlots")
        if self.interactive_reserved > self.max_slots:
            raise ValueError("interactiveReserved must not exceed maxSlots")
        if self.in_flight > self.max_slots:
            raise ValueError("inFlight must not exceed maxSlots")
        if self.active_slots == 0 and self.in_flight > 0:
            self.active_slots = self.in_flight
        return self

    @property
    def reserved_interactive_slots(self) -> int:
        return self.interactive_reserved

    @property
    def available_slots(self) -> int:
        return max(0, self.max_slots - self.active_slots)

    @property
    def borrowable_slots(self) -> int:
        return max(0, self.available_slots - self.interactive_reserved)


Engine = PhysicalEngine
