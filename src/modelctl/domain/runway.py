"""Runway estimates and their required source classification."""
from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import Field, field_validator

from modelctl.domain.workload import DomainModel


class RunwaySource(str, Enum):
    PROVIDER_DERIVED = "provider-derived"
    DELAYED_DASHBOARD = "delayed-dashboard"
    CONSUMPTION_ESTIMATED = "consumption-estimated"
    UNKNOWN = "unknown"


class Runway(DomainModel):
    """Remaining usage with an explicit confidence source."""

    source: RunwaySource
    remaining_tokens: int = Field(ge=0, alias="remainingTokens")
    reset_at: datetime | None = Field(default=None, alias="resetAt")
    direct_cloud_tokens: int = Field(default=0, ge=0, alias="directCloudTokens")
    manual_cloud_tokens: int = Field(default=0, ge=0, alias="manualCloudTokens")

    @field_validator("reset_at")
    @classmethod
    def normalize_reset_at(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("resetAt must include a UTC offset")
        return value.astimezone(UTC)
