"""Workload classes and strict-local availability behavior."""
from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class DomainModel(BaseModel):
    """Base model for strict, alias-aware public contracts."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class WorkloadName(str, Enum):
    TINY = "tiny"
    SONIC = "sonic"
    SCOUT_BOUNDED = "scout-bounded"
    RESEARCHER = "researcher"
    REVIEWER = "reviewer"
    TASK = "task"
    VISION = "vision"
    DESIGNER = "designer"
    ADVISOR = "advisor"
    PLAN = "plan"
    SLOW = "slow"


WORKLOAD_CLASSES: tuple[Literal[
    "tiny",
    "sonic",
    "scout-bounded",
    "researcher",
    "reviewer",
    "task",
    "vision",
    "designer",
    "advisor",
    "plan",
    "slow",
], ...] = tuple(item.value for item in WorkloadName)


class UnavailableBehavior(str, Enum):
    """Behavior when a strict-local workload has no compatible replica."""

    WARN = "warn"
    BLOCK = "block"
    DEGRADE = "degrade"


class WorkloadClass(DomainModel):
    """A role-shaped workload definition."""

    name: WorkloadName
    strict_local: bool = Field(default=False, alias="strictLocal")
    unavailable_behavior: UnavailableBehavior = Field(
        default=UnavailableBehavior.DEGRADE,
        alias="unavailableBehavior",
    )
    reserved_replicas: int = Field(default=1, ge=0, alias="reservedReplicas")
    interactive: bool = False

    @model_validator(mode="after")
    def validate_strict_local_reservation(self) -> WorkloadClass:
        if self.strict_local and self.reserved_replicas < 1:
            raise ValueError("strict-local workloads require a reserved replica")
        return self
