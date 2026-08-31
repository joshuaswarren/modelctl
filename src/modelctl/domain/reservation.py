"""Strict-local reservation and N+1 placement guarantees."""
from __future__ import annotations

from pydantic import Field, field_validator, model_validator

from modelctl.domain.workload import DomainModel


class Reservation(DomainModel):
    """A reservation with two-host pre-warm or an explicit exception."""

    workload: str = Field(min_length=1)
    prewarm_hosts: list[str] = Field(default_factory=list, alias="prewarmHosts")
    n1_impossible: bool = Field(default=False, alias="n1Impossible")
    n1_impossible_reason: str | None = Field(default=None, alias="n1ImpossibleReason")
    failover_timeout_s: int = Field(default=60, ge=1, alias="failoverTimeoutS")

    @field_validator("prewarm_hosts")
    @classmethod
    def validate_hosts(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("prewarmHosts values must not be blank")
        if len(values) != len(set(values)):
            raise ValueError("prewarmHosts must contain distinct hosts")
        return values

    @field_validator("n1_impossible_reason")
    @classmethod
    def normalize_reason(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("n1ImpossibleReason must not be blank")
        return value

    @model_validator(mode="after")
    def validate_placement(self) -> Reservation:
        if self.n1_impossible:
            if self.n1_impossible_reason is None:
                raise ValueError("n1Impossible requires n1ImpossibleReason")
            return self
        if self.n1_impossible_reason is not None:
            raise ValueError("n1ImpossibleReason requires n1Impossible")
        if len(self.prewarm_hosts) < 2:
            raise ValueError("reservation requires two distinct prewarm hosts")
        return self
