"""Evaluation gates, canary promotion, and durable decision records."""
from __future__ import annotations

import os
from collections.abc import Mapping
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from pydantic import ConfigDict, Field, field_validator

from modelctl.domain.workload import DomainModel
from modelctl.evals.canary import (
    CanaryDecision,
    CanaryMetrics,
    CanaryPolicy,
    CanaryRouteTable,
    CanaryRunner,
)
from modelctl.evals.contracts import (
    Candidate,
    ContractResult,
    ContractSuite,
    EvaluationClass,
    EvaluationMode,
    StructuredOutput,
    evaluate_contracts,
    standard_contract_suite,
)
from modelctl.evals.judges import Judge, JudgeAssessment, JudgePanel, judges_pass
from modelctl.policy.signing import bundle_id


class EgressApproval(DomainModel):
    """Approval for one provider and exact destination pair."""

    provider: str = Field(min_length=1)
    destination: str = Field(min_length=1)
    approval_id: str = Field(min_length=1, alias="approvalId")
    approved: bool = True


class HardFitRequirements(DomainModel):
    """Non-negotiable candidate requirements checked before response evaluation."""

    required_capabilities: list[str] = Field(default_factory=list, alias="requiredCapabilities")
    minimum_context_window_tokens: int = Field(
        default=1,
        ge=1,
        alias="minimumContextWindowTokens",
    )
    allowed_modes: list[EvaluationMode] = Field(
        default_factory=lambda: [EvaluationMode.STRICT_LOCAL, EvaluationMode.CLOUD],
        alias="allowedModes",
    )

    @field_validator("required_capabilities")
    @classmethod
    def validate_required_capabilities(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("required capabilities must not be blank")
        if len(values) != len(set(values)):
            raise ValueError("required capabilities must be unique")
        return values


def hard_fit_failures(candidate: Candidate, requirements: HardFitRequirements) -> list[str]:
    """Return deterministic reasons that make a catalog candidate ineligible."""

    failures: list[str] = []
    if not candidate.available:
        failures.append("unavailable")
    if candidate.mode not in requirements.allowed_modes:
        failures.append("evaluation-mode")
    if candidate.context_window_tokens < requirements.minimum_context_window_tokens:
        failures.append("context-window")
    missing = sorted(set(requirements.required_capabilities) - set(candidate.capabilities))
    failures.extend(f"missing-capability:{capability}" for capability in missing)
    return failures

class PromotionOutcome(str, Enum):
    PROMOTED = "promoted"
    ROLLED_BACK = "rolled-back"
    BLOCKED = "blocked"


class PromotionDecision(DomainModel):
    """The complete record for one promotion attempt."""

    version: int = Field(default=1, ge=1)
    inputs: Mapping[str, Any]
    reason: str = Field(min_length=1)
    cohort: str = Field(min_length=1)
    outcome: PromotionOutcome
    provenance: Mapping[str, str]
    rollback_target: str | None = Field(default=None, alias="rollbackTarget")



class DecisionSink(Protocol):
    """Durable sink required at every promotion decision boundary."""

    def append(self, decision: PromotionDecision) -> None: ...


class JsonlDecisionLog:
    """Append promotion decisions to a durable JSONL audit log."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, decision: PromotionDecision) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        encoded = (decision.model_dump_json(by_alias=True) + "\n").encode("utf-8")
        with self.path.open("ab") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())

    def records(self) -> list[PromotionDecision]:
        if not self.path.exists():
            return []
        records: list[PromotionDecision] = []
        for line_number, line in enumerate(self.path.read_text(encoding="utf-8").splitlines(), start=1):
            try:
                records.append(PromotionDecision.model_validate_json(line))
            except ValueError as exc:
                raise ValueError(f"invalid promotion decision at line {line_number}") from exc
        return records

class EvaluationResult(DomainModel):
    """Evaluation receipts before canary and promotion."""

    contract: ContractResult
    judge_assessments: list[JudgeAssessment] = Field(default_factory=list, alias="judgeAssessments")
    judges_run: int = Field(ge=0, alias="judgesRun")
    reserved_capacity_consumed: int = Field(ge=0, alias="reservedCapacityConsumed")
    passed: bool


class PromotionRequest(DomainModel):
    """All inputs needed for one candidate promotion attempt."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    candidate: Candidate
    suite: ContractSuite
    outputs: list[StructuredOutput] = Field(min_length=1)
    catalog: list[Candidate]
    hard_fit: HardFitRequirements = Field(alias="hardFit")
    judges: list[Judge] = Field(default_factory=list)
    known_providers: list[str] = Field(default_factory=list, alias="knownProviders")
    egress_approvals: list[EgressApproval] = Field(default_factory=list, alias="egressApprovals")
    canary_policy: CanaryPolicy = Field(alias="canaryPolicy")
    baseline_metrics: CanaryMetrics = Field(alias="baselineMetrics")
    candidate_metrics: CanaryMetrics = Field(alias="candidateMetrics")
    rollback_target: str = Field(min_length=1, alias="rollbackTarget")
    provenance: Mapping[str, str]

    @classmethod
    def from_fixture(cls, data: Mapping[str, Any]) -> PromotionRequest:
        """Load the repository fixture shape into the public request contract."""

        evaluation_class = EvaluationClass(data["evaluationClass"])
        return cls(
            candidate=Candidate.model_validate(data["candidate"]),
            suite=standard_contract_suite(evaluation_class),
            outputs=[StructuredOutput.model_validate(item) for item in data["outputs"]],
            catalog=[Candidate.model_validate(item) for item in data["catalog"]],
            hardFit=data.get("hardFit", {}),
            knownProviders=data.get("knownProviders", []),
            egressApprovals=data.get("egressApprovals", []),
            canaryPolicy=data["canaryPolicy"],
            baselineMetrics=data["baselineMetrics"],
            candidateMetrics=data["candidateMetrics"],
            rollbackTarget=data["rollbackTarget"],
            provenance=data["provenance"],
        )


class PromotionResult(DomainModel):
    """All receipts produced by one promotion attempt."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    decision: PromotionDecision
    evaluation: EvaluationResult
    canary: CanaryDecision | None = None
    events: list[str] = Field(default_factory=list)


class PromotionPipeline:
    """Run the ordered egress, contract, judge, canary, and route gates."""

    def __init__(self, routes: CanaryRouteTable, *, decisions: DecisionSink) -> None:
        self.routes = routes
        self.decisions = decisions

    @staticmethod
    def _egress_allowed(request: PromotionRequest) -> bool:
        candidate = request.candidate
        if candidate.mode is EvaluationMode.STRICT_LOCAL or candidate.provider in request.known_providers:
            return True
        return any(
            approval.approved
            and approval.provider == candidate.provider
            and approval.destination == candidate.destination
            for approval in request.egress_approvals
        )

    @staticmethod
    def _inputs(request: PromotionRequest) -> dict[str, Any]:
        return {
            "candidate": request.candidate.model_dump(mode="json", by_alias=True),
            "catalogCandidate": request.candidate.model_dump(mode="json", by_alias=True),
            "hardFit": request.hard_fit.model_dump(mode="json", by_alias=True),
            "contractSuite": request.suite.model_dump(mode="json", by_alias=True),
            "outputDigests": [
                bundle_id(output.model_dump(mode="json", by_alias=True))
                for output in request.outputs
            ],
            "judges": [
                {"name": judge.name, "family": judge.family}
                for judge in request.judges
            ],
            "knownProviders": sorted(request.known_providers),
            "egressApprovals": [
                approval.model_dump(mode="json", by_alias=True)
                for approval in request.egress_approvals
            ],
            "canaryPolicy": request.canary_policy.model_dump(mode="json", by_alias=True),
            "baselineMetrics": request.baseline_metrics.model_dump(mode="json", by_alias=True),
            "candidateMetrics": request.candidate_metrics.model_dump(mode="json", by_alias=True),
            "rollbackTarget": request.rollback_target,
        }

    def _result(
        self,
        request: PromotionRequest,
        outcome: PromotionOutcome,
        reason: str,
        evaluation: EvaluationResult,
        *,
        canary: CanaryDecision | None = None,
        events: list[str],
    ) -> PromotionResult:
        result = PromotionResult(
            decision=PromotionDecision(
                inputs=self._inputs(request),
                reason=reason,
                cohort=request.canary_policy.cohort,
                outcome=outcome,
                provenance=request.provenance,
                rollbackTarget=request.rollback_target,
            ),
            evaluation=evaluation,
            canary=canary,
            events=events,
        )
        self.decisions.append(result.decision)
        return result

    def run(self, request: PromotionRequest) -> PromotionResult:
        reserved_capacity = 0 if request.candidate.mode is EvaluationMode.STRICT_LOCAL else len(request.outputs)
        empty_contract = ContractResult(passed=False, checked=0, failures=[])
        empty_evaluation = EvaluationResult(
            contract=empty_contract,
            judgesRun=0,
            reservedCapacityConsumed=reserved_capacity,
            passed=False,
        )
        catalog_candidate = next(
            (candidate for candidate in request.catalog if candidate.id == request.candidate.id),
            None,
        )
        if catalog_candidate is None:
            return self._result(
                request,
                PromotionOutcome.BLOCKED,
                "candidate not found in catalog",
                empty_evaluation,
                events=["catalog-candidate-missing"],
            )
        if catalog_candidate != request.candidate:
            return self._result(
                request,
                PromotionOutcome.BLOCKED,
                "candidate does not match catalog",
                empty_evaluation,
                events=["catalog-candidate-mismatch"],
            )
        fit_failures = hard_fit_failures(catalog_candidate, request.hard_fit)
        if fit_failures:
            return self._result(
                request,
                PromotionOutcome.BLOCKED,
                f"hard-fit failure: {'; '.join(fit_failures)}",
                empty_evaluation,
                events=["hard-fit-failed"],
            )
        if not self._egress_allowed(request):
            return self._result(
                request,
                PromotionOutcome.BLOCKED,
                "egress approval required",
                empty_evaluation,
                events=["egress-approval-required"],
            )

        contract = evaluate_contracts(request.outputs, request.suite)
        if not contract.passed:
            evaluation = EvaluationResult(
                contract=contract,
                judgesRun=0,
                reservedCapacityConsumed=reserved_capacity,
                passed=False,
            )
            return self._result(
                request,
                PromotionOutcome.BLOCKED,
                "deterministic contract failure",
                evaluation,
                events=["deterministic-contract-failed"],
            )

        assessments: list[JudgeAssessment] = []
        selected_judges = 0
        if request.suite.evaluation_class is EvaluationClass.SUBJECTIVE:
            panel = JudgePanel(request.judges)
            selected_judges = panel.judge_count
            assessments = panel.evaluate(request.outputs)
            if not judges_pass(assessments, request.suite.minimum_judge_score):
                evaluation = EvaluationResult(
                    contract=contract,
                    judgeAssessments=assessments,
                    judgesRun=selected_judges,
                    reservedCapacityConsumed=reserved_capacity,
                    passed=False,
                )
                return self._result(
                    request,
                    PromotionOutcome.BLOCKED,
                    "subjective judge threshold failure",
                    evaluation,
                    events=["subjective-judge-failed"],
                )

        evaluation = EvaluationResult(
            contract=contract,
            judgeAssessments=assessments,
            judgesRun=selected_judges,
            reservedCapacityConsumed=reserved_capacity,
            passed=True,
        )
        canary_runner = CanaryRunner(self.routes)
        canary = canary_runner.evaluate(
            request.candidate.route,
            request.rollback_target,
            request.baseline_metrics,
            request.candidate_metrics,
            request.canary_policy,
        )
        if not canary.passed:
            result = self._result(
                request,
                PromotionOutcome.ROLLED_BACK,
                "; ".join(canary.reasons),
                evaluation,
                canary=canary,
                events=["canary-rollback"],
            )
            canary_runner.apply(canary)
            return result
        result = self._result(
            request,
            PromotionOutcome.PROMOTED,
            "quality and canary thresholds passed",
            evaluation,
            canary=canary,
            events=["candidate-promoted"],
        )
        canary_runner.apply(canary)
        return result
