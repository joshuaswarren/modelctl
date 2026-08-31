"""Budget envelopes for agents, projects, and providers."""
from __future__ import annotations

from pydantic import Field, field_validator

from modelctl.domain.workload import DomainModel


class Budget(DomainModel):
    """Non-negative ceilings for each enforcement scope."""

    agent: dict[str, int] = Field(default_factory=dict)
    project: dict[str, int] = Field(default_factory=dict)
    provider: dict[str, int] = Field(default_factory=dict)

    @field_validator("agent", "project", "provider")
    @classmethod
    def validate_values(cls, values: dict[str, int]) -> dict[str, int]:
        if any(not name.strip() or value < 0 for name, value in values.items()):
            raise ValueError("budget names must be non-empty and values non-negative")
        return values
