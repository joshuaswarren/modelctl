"""Provider-neutral policy bundle payload."""
from __future__ import annotations

from typing import Any

from pydantic import Field

from modelctl.domain.budget import Budget
from modelctl.domain.engine import PhysicalEngine
from modelctl.domain.events import Event
from modelctl.domain.metadata import RequestMetadata
from modelctl.domain.reservation import Reservation
from modelctl.domain.runway import Runway
from modelctl.domain.workload import DomainModel, WorkloadClass


class OMPContainmentPolicy(DomainModel):
    """Loop-containment thresholds enforced by each OMP process."""

    threshold: int = Field(default=5, ge=1)
    window_ms: int = Field(default=120_000, ge=1, alias="windowMs")


class OMPRuntimePolicy(DomainModel):
    """Signed OMP limits that remain enforceable without a controller."""

    containment: OMPContainmentPolicy = Field(default_factory=OMPContainmentPolicy)
    budgets: Budget = Field(default_factory=Budget)



class PolicyBundle(DomainModel):
    """Typed sections for a provider-neutral routing policy."""

    version: int = Field(default=1, ge=1)
    workloads: list[WorkloadClass] = Field(default_factory=list)
    metadata: list[RequestMetadata] = Field(default_factory=list)
    engines: list[PhysicalEngine] = Field(default_factory=list)
    reservations: list[Reservation] = Field(default_factory=list)
    budgets: list[Budget] = Field(default_factory=list)
    runway: list[Runway] = Field(default_factory=list)
    events: list[Event] = Field(default_factory=list)
    routes: dict[str, Any] = Field(default_factory=dict)
    omp: OMPRuntimePolicy | None = None
