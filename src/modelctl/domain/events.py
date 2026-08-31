"""Durable event records for visible failure and state changes."""
from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any

from pydantic import Field, field_validator

from modelctl.domain.workload import DomainModel


class EventSeverity(str, Enum):
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class Event(DomainModel):
    """An indexable event emitted by a model control subsystem."""

    id: str = Field(min_length=1)
    time: datetime
    subsystem: str = Field(min_length=1)
    severity: EventSeverity
    subject: str = Field(min_length=1)
    detail: dict[str, Any] = Field(default_factory=dict)

    @field_validator("time")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("event time must include a UTC offset")
        return value.astimezone(UTC)
