"""Canary metrics, threshold checks, and automatic rollback."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from pydantic import Field, model_validator

from modelctl.domain.workload import DomainModel


class CanaryMetrics(DomainModel):
    """Observed metrics for one canary cohort."""

    requests: int = Field(ge=1)
    errors: int = Field(ge=0)
    latency_p95_ms: float = Field(ge=0, alias="latencyP95Ms")
    quota_draw: int = Field(ge=0, alias="quotaDraw")

    @model_validator(mode="after")
    def validate_errors(self) -> CanaryMetrics:
        if self.errors > self.requests:
            raise ValueError("errors cannot exceed requests")
        return self

    @property
    def error_rate(self) -> float:
        return self.errors / self.requests


class CanaryPolicy(DomainModel):
    """Hard limits for a candidate cohort."""

    max_error_rate: float = Field(ge=0.0, le=1.0, alias="maxErrorRate")
    max_latency_p95_ms: float = Field(ge=0.0, alias="maxLatencyP95Ms")
    max_quota_draw_regression: float = Field(ge=0.0, alias="maxQuotaDrawRegression")
    cohort: str = Field(min_length=1)


class CanaryDecision(DomainModel):
    """Canary outcome and threshold failures."""

    passed: bool
    rolled_back: bool = Field(alias="rolledBack")
    reasons: list[str] = Field(default_factory=list)
    baseline: CanaryMetrics
    candidate: CanaryMetrics
    prior_route: str = Field(alias="priorRoute")
    active_route: str = Field(alias="activeRoute")


class CanaryRouteTable(Protocol):
    """Route mutation boundary used after a durable canary decision."""

    current_route: str

    def activate(self, route: str) -> None: ...

    def rollback(self, route: str) -> None: ...


@dataclass
class RouteTable:
    """Small route table used by adapters and the fixture run."""

    current_route: str
    history: list[str] = field(default_factory=list)

    def activate(self, route: str) -> None:
        if not route.strip():
            raise ValueError("route is required")
        self.history.append(self.current_route)
        self.current_route = route

    def rollback(self, route: str) -> None:
        if not route.strip():
            raise ValueError("rollback route is required")
        self.current_route = route


def canary_failures(
    baseline: CanaryMetrics,
    candidate: CanaryMetrics,
    policy: CanaryPolicy,
) -> list[str]:
    """Return every breached reliability, latency, and quota threshold."""

    reasons: list[str] = []
    if candidate.error_rate > policy.max_error_rate:
        reasons.append("error-rate regression")
    if candidate.latency_p95_ms > policy.max_latency_p95_ms:
        reasons.append("latency-p95 regression")
    quota_limit = baseline.quota_draw * (1.0 + policy.max_quota_draw_regression)
    if candidate.quota_draw > quota_limit:
        reasons.append("quota-draw regression")
    return reasons


class CanaryRunner:
    """Activate a candidate, then restore the prior route on any breach."""

    def __init__(self, routes: CanaryRouteTable) -> None:
        self.routes = routes

    def evaluate(
        self,
        candidate_route: str,
        rollback_target: str,
        baseline: CanaryMetrics,
        candidate: CanaryMetrics,
        policy: CanaryPolicy,
    ) -> CanaryDecision:
        """Evaluate canary metrics without changing a serving route."""

        prior_route = self.routes.current_route
        reasons = canary_failures(baseline, candidate, policy)
        return CanaryDecision(
            passed=not reasons,
            rolledBack=bool(reasons),
            reasons=reasons,
            baseline=baseline,
            candidate=candidate,
            priorRoute=prior_route,
            activeRoute=rollback_target if reasons else candidate_route,
        )

    def apply(self, decision: CanaryDecision) -> None:
        """Apply a precomputed canary decision after its audit record is durable."""

        if decision.rolled_back:
            self.routes.rollback(decision.active_route)
        else:
            self.routes.activate(decision.active_route)

    def run(
        self,
        candidate_route: str,
        rollback_target: str,
        baseline: CanaryMetrics,
        candidate: CanaryMetrics,
        policy: CanaryPolicy,
    ) -> CanaryDecision:
        decision = self.evaluate(
            candidate_route,
            rollback_target,
            baseline,
            candidate,
            policy,
        )
        self.apply(decision)
        return decision
