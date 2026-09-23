"""Pure provider-neutral subscription selection engine.

Parses the typed ``routes['omp']['selection']`` policy section and selects
per-role candidates from runway telemetry without side effects.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta

from pydantic import Field, field_validator, model_validator

from modelctl.domain.policy import PolicyBundle
from modelctl.domain.workload import DomainModel
from modelctl.evals.contracts import Candidate, EvaluationMode
from modelctl.evals.promotion import PromotionDecision, PromotionOutcome
from modelctl.telemetry.contracts import QuotaUnit, RunwayEstimate

_OLDEST = datetime.min.replace(tzinfo=UTC)


class SelectionCandidate(Candidate):
    """Evaluation candidate extended with the account and qualification fields selection needs."""

    account: str = Field(min_length=1)
    priority: int = 0
    qualification_expires_at: datetime | None = Field(
        default=None,
        alias="qualificationExpiresAt",
    )

    @field_validator("qualification_expires_at")
    @classmethod
    def normalize_qualification_expiry(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("qualificationExpiresAt must include a UTC offset")
        return value.astimezone(UTC)


class RunwayMaximum(DomainModel):
    """Quota ceiling for one exact provider/account pair."""

    maximum: float = Field(gt=0)


class SelectionRole(DomainModel):
    """Native-role mapping to a workload class and its candidate references."""

    workload_class: str = Field(min_length=1, alias="workloadClass")
    candidates: list[str] = Field(default_factory=list)
    strict_local: bool = False

    @field_validator("candidates")
    @classmethod
    def validate_candidate_refs(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("selection role candidate references must not be blank")
        return values

    def expected_mode(self) -> EvaluationMode:
        """The evaluation mode this role may select from."""
        return EvaluationMode.STRICT_LOCAL if self.strict_local else EvaluationMode.CLOUD


class SelectionPolicy(DomainModel):
    """Typed ``routes['omp']['selection']`` section."""

    quota_unit: QuotaUnit = Field(default=QuotaUnit.TOKENS, alias="quotaUnit")
    max_quota_used: float = Field(alias="maxQuotaUsed", ge=0, le=1)
    max_observation_age_seconds: int = Field(default=3600, ge=1, alias="maxObservationAgeSeconds")
    runway: dict[str, RunwayMaximum] = Field(default_factory=dict)
    candidates: list[SelectionCandidate]
    promotions: list[PromotionDecision] = Field(default_factory=list)
    roles: dict[str, SelectionRole]

    @model_validator(mode="after")
    def validate_catalog_and_runway(self) -> SelectionPolicy:
        candidate_ids = [candidate.id for candidate in self.candidates]
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError("selection candidate ids must be unique")
        for key in self.runway:
            provider, _, account = key.partition("/")
            if not provider or not account or "/" in account:
                raise ValueError(f"runway maximum key must be provider/account: {key}")
        return self


class SelectionRequest(DomainModel):
    """All inputs for one pure selection run."""

    policy: SelectionPolicy
    runway: Sequence[RunwayEstimate]
    current_model_roles: Mapping[str, str] = Field(default_factory=dict, alias="currentModelRoles")
    current_fallback_chains: Mapping[str, Sequence[str]] = Field(
        default_factory=dict,
        alias="currentFallbackChains",
    )
    now: datetime

    @field_validator("now")
    @classmethod
    def normalize_now(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("now must include a UTC offset")
        return value.astimezone(UTC)


class SelectionDecision(DomainModel):
    """Audit record for one managed role."""

    role: str = Field(min_length=1)
    workload_class: str = Field(min_length=1, alias="workloadClass")
    previous: str | None = None
    selected: str | None = None
    changed: bool = False
    blocked: bool = False
    reason: str = Field(min_length=1)


class SelectionPlan(DomainModel):
    """Merged assignment output plus per-role audit decisions."""

    model_roles: dict[str, str] = Field(default_factory=dict, alias="modelRoles")
    fallback_chains: dict[str, list[str]] = Field(default_factory=dict, alias="fallbackChains")
    changed_roles: list[str] = Field(default_factory=list, alias="changedRoles")
    blocked_roles: list[str] = Field(default_factory=list, alias="blockedRoles")
    decisions: list[SelectionDecision] = Field(default_factory=list)


def selection_policy_from_bundle(bundle: PolicyBundle) -> SelectionPolicy:
    """Parse and validate the typed selection section of ``routes['omp']``."""
    omp = bundle.routes.get("omp", {})
    if not isinstance(omp, Mapping):
        raise TypeError("policy.routes['omp'] must be an object")
    section = omp.get("selection")
    if section is None:
        raise ValueError("policy.routes['omp'].selection is required")
    if not isinstance(section, Mapping):
        raise TypeError("policy.routes['omp'].selection must be an object")
    policy = SelectionPolicy.model_validate(dict(section))
    workloads = {workload.name.value: workload for workload in bundle.workloads}
    roles: dict[str, SelectionRole] = {}
    for name, role in policy.roles.items():
        workload = workloads.get(role.workload_class)
        if workload is None:
            raise ValueError(
                f"selection role {name} references unknown workload class: {role.workload_class}"
            )
        roles[name] = role.model_copy(update={"strict_local": workload.strict_local})
    policy.roles = roles
    return policy


def _promoted_ids(decisions: Sequence[PromotionDecision]) -> set[str]:
    promoted: set[str] = set()
    for decision in decisions:
        if decision.outcome is not PromotionOutcome.PROMOTED:
            continue
        candidate = decision.inputs.get("candidate")
        if isinstance(candidate, Mapping):
            candidate_id = candidate.get("id")
            if isinstance(candidate_id, str):
                promoted.add(candidate_id)
    return promoted


def _runway_rank(estimate: RunwayEstimate) -> tuple[datetime, float]:
    used = float(estimate.quota_used) if estimate.quota_used is not None else float("inf")
    return estimate.freshness_time or _OLDEST, used

def _runway_index(estimates: Sequence[RunwayEstimate]) -> dict[tuple[str, str], RunwayEstimate]:
    """Join estimates to exact (provider, accountLabel) pairs, freshest first."""
    index: dict[tuple[str, str], RunwayEstimate] = {}
    for estimate in estimates:
        if estimate.provider is None or estimate.account_label is None:
            continue
        key = (estimate.provider, estimate.account_label)
        current = index.get(key)
        if current is not None and _runway_rank(estimate) <= _runway_rank(current):
            continue
        index[key] = estimate
    return index


def _evaluate_role(
    role: SelectionRole,
    catalog: Mapping[str, SelectionCandidate],
    promoted: set[str],
    runway_index: Mapping[tuple[str, str], RunwayEstimate],
    policy: SelectionPolicy,
    now: datetime,
) -> tuple[list[SelectionCandidate], list[str]]:
    """Return eligible candidates in selection order plus per-candidate exclusion reasons."""
    expected_mode = role.expected_mode()
    max_age = timedelta(seconds=policy.max_observation_age_seconds)
    eligible: list[tuple[int, float, str, SelectionCandidate]] = []
    failures: list[str] = []
    for ref in role.candidates:
        candidate = catalog.get(ref)
        if candidate is None:
            failures.append(f"{ref}: unknown")
            continue
        if not candidate.available:
            failures.append(f"{ref}: unavailable")
            continue
        if candidate.qualification_expires_at is not None and candidate.qualification_expires_at < now:
            failures.append(f"{ref}: expired")
            continue
        if candidate.mode is not expected_mode:
            failures.append(f"{ref}: wrong-mode")
            continue
        if ref not in promoted:
            failures.append(f"{ref}: unpromoted")
            continue
        if expected_mode is EvaluationMode.STRICT_LOCAL:
            eligible.append((candidate.priority, 0.0, candidate.id, candidate))
            continue
        estimate = runway_index.get((candidate.provider, candidate.account))
        if estimate is None:
            failures.append(f"{ref}: unknown")
            continue
        if estimate.quota_unit is not policy.quota_unit:
            failures.append(f"{ref}: mismatched-unit")
            continue
        if estimate.freshness_time is None or now - estimate.freshness_time > max_age:
            failures.append(f"{ref}: stale")
            continue
        maximum = policy.runway.get(f"{candidate.provider}/{candidate.account}")
        if maximum is None:
            failures.append(f"{ref}: unknown")
            continue
        used = estimate.quota_used
        if used is None:
            failures.append(f"{ref}: no-usage")
            continue
        if used / maximum.maximum > policy.max_quota_used:
            failures.append(f"{ref}: quota-exceeded")
            continue
        eligible.append((candidate.priority, used / maximum.maximum, candidate.id, candidate))
    eligible.sort(key=lambda item: (item[0], item[1], item[2]))
    return [item[3] for item in eligible], failures


def select_models(request: SelectionRequest) -> SelectionPlan:
    """Select per-role candidates and merge them into the current maps."""
    policy = request.policy
    catalog = {candidate.id: candidate for candidate in policy.candidates}
    promoted = _promoted_ids(policy.promotions)
    runway_index = _runway_index(request.runway)
    model_roles: dict[str, str] = dict(request.current_model_roles)
    fallback_chains: dict[str, list[str]] = {
        role: list(chain) for role, chain in request.current_fallback_chains.items()
    }
    changed_roles: list[str] = []
    blocked_roles: list[str] = []
    decisions: list[SelectionDecision] = []
    for role_name, role in policy.roles.items():
        ordered, failures = _evaluate_role(
            role, catalog, promoted, runway_index, policy, request.now
        )
        eligible_ids = [candidate.id for candidate in ordered]
        previous = model_roles.get(role_name)
        selected: str | None
        # Stick only among equal-priority peers, so a recovered higher-priority candidate reclaims the role.
        top_priority = ordered[0].priority if ordered else None
        if previous is not None and any(c.id == previous and c.priority == top_priority for c in ordered):
            selected = previous
            reason = "incumbent"
        elif ordered:
            selected = ordered[0].id
            prefix = "; ".join(failures)
            reason = f"{prefix}; selected {selected}" if prefix else f"selected {selected}"
        else:
            selected = None
            reason = "; ".join(failures) or "no eligible candidates"
        if selected is None:
            blocked_roles.append(role_name)
        else:
            model_roles[role_name] = selected
            fallback_chains[role_name] = [candidate_id for candidate_id in eligible_ids if candidate_id != selected]
            if selected != previous:
                changed_roles.append(role_name)
        decisions.append(
            SelectionDecision(
                role=role_name,
                workloadClass=role.workload_class,
                previous=previous,
                selected=selected,
                changed=selected is not None and selected != previous,
                blocked=selected is None,
                reason=reason,
            )
        )
    return SelectionPlan(
        modelRoles=model_roles,
        fallbackChains=fallback_chains,
        changedRoles=changed_roles,
        blockedRoles=blocked_roles,
        decisions=decisions,
    )
