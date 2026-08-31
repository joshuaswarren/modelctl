from __future__ import annotations

import json
from pathlib import Path

import pytest

from modelctl.evals.canary import CanaryMetrics, CanaryPolicy, RouteTable
from modelctl.evals.contracts import (
    Candidate,
    ContractAssertion,
    ContractKind,
    ContractSuite,
    EvaluationClass,
    EvaluationMode,
    StructuredOutput,
)
from modelctl.evals.judges import Judge, JudgeAssessment
from modelctl.evals.promotion import (
    EgressApproval,
    HardFitRequirements,
    JsonlDecisionLog,
    PromotionOutcome,
    PromotionPipeline,
    PromotionRequest,
)

FIXTURES = Path(__file__).parents[2] / "fixtures" / "evals"


def suite(evaluation_class: EvaluationClass) -> ContractSuite:
    return ContractSuite(
        name="response-contracts",
        evaluation_class=evaluation_class,
        assertions=[
            ContractAssertion(name="json-format", kind=ContractKind.FORMAT, expected="json"),
            ContractAssertion(
                name="tool-shape",
                kind=ContractKind.TOOL_USE,
                expected={"required": ["lookup"], "forbidden": ["delete"]},
            ),
            ContractAssertion(name="refusal", kind=ContractKind.REFUSAL, expected=False),
            ContractAssertion(
                name="receipt",
                kind=ContractKind.EXACT_RECEIPT,
                expected={"requestId": "fixture-1", "status": "complete"},
            ),
        ],
    )


def output(*, good: bool = True) -> StructuredOutput:
    return StructuredOutput(
        format="json" if good else "text",
        value={"answer": "ready"},
        tool_calls=[{"name": "lookup", "arguments": {}}] if good else [],
        refused=False,
        receipt={"requestId": "fixture-1", "status": "complete"} if good else None,
    )


def request(
    *,
    candidate: Candidate,
    evaluation_class: EvaluationClass,
    outputs: list[StructuredOutput],
    judges: list[Judge] | None = None,
    canary: tuple[CanaryMetrics, CanaryMetrics] | None = None,
) -> PromotionRequest:
    baseline_metrics, candidate_metrics = canary or (
        CanaryMetrics(requests=100, errors=1, latency_p95_ms=100, quota_draw=100),
        CanaryMetrics(requests=100, errors=1, latency_p95_ms=100, quota_draw=100),
    )
    return PromotionRequest(
        candidate=candidate,
        suite=suite(evaluation_class),
        outputs=outputs,
        catalog=[candidate],
        hard_fit=HardFitRequirements(),
        judges=judges or [],
        known_providers=["local"],
        egress_approvals=[],
        canary_policy=CanaryPolicy(
            max_error_rate=0.05,
            max_latency_p95_ms=200,
            max_quota_draw_regression=0.10,
            cohort="fixture-cohort",
        ),
        baseline_metrics=baseline_metrics,
        candidate_metrics=candidate_metrics,
        rollback_target="stable-route",
        provenance={"source": "fixture", "revision": "fixture-1"},
    )


def test_contract_failure_gates_judges(tmp_path: Path) -> None:
    calls: list[str] = []
    judges = [
        Judge(
            name="judge-a",
            family="family-a",
            evaluate=lambda _output: calls.append("called") or JudgeAssessment(score=1.0, passed=True),
        )
    ]
    candidate = Candidate(
        id="bad-contract",
        provider="local",
        destination="local://engine-a",
        route="candidate-route",
        mode=EvaluationMode.STRICT_LOCAL,
    )

    result = PromotionPipeline(
        RouteTable("stable-route"),
        decisions=JsonlDecisionLog(tmp_path / "decisions.jsonl"),
    ).run(
        request(
            candidate=candidate,
            evaluation_class=EvaluationClass.SUBJECTIVE,
            outputs=[output(good=False)],
            judges=judges,
        )
    )

    assert result.decision.outcome is PromotionOutcome.BLOCKED
    assert result.decision.reason == "deterministic contract failure"
    assert calls == []
    assert result.evaluation.judges_run == 0



def test_catalog_detection_and_hard_fit_gate_before_contracts(tmp_path: Path) -> None:
    candidate = Candidate(
        id="missing-vision",
        provider="local",
        destination="local://engine-a",
        route="candidate-route",
        mode=EvaluationMode.STRICT_LOCAL,
        capabilities=["tools"],
        contextWindowTokens=4096,
    )
    promotion_request = request(
        candidate=candidate,
        evaluation_class=EvaluationClass.OBJECTIVE,
        outputs=[output()],
    )
    promotion_request.hard_fit = HardFitRequirements(
        requiredCapabilities=["vision"],
        minimumContextWindowTokens=8192,
    )

    result = PromotionPipeline(
        RouteTable("stable-route"),
        decisions=JsonlDecisionLog(tmp_path / "decisions.jsonl"),
    ).run(promotion_request)

    assert result.decision.outcome is PromotionOutcome.BLOCKED
    assert result.decision.reason == "hard-fit failure: context-window; missing-capability:vision"
    assert result.evaluation.contract.checked == 0
    assert result.events == ["hard-fit-failed"]


def test_candidate_missing_from_catalog_is_blocked(tmp_path: Path) -> None:
    candidate = Candidate(
        id="uncataloged",
        provider="local",
        destination="local://engine-a",
        route="candidate-route",
        mode=EvaluationMode.STRICT_LOCAL,
    )
    promotion_request = request(
        candidate=candidate,
        evaluation_class=EvaluationClass.OBJECTIVE,
        outputs=[output()],
    )
    promotion_request.catalog = []

    result = PromotionPipeline(
        RouteTable("stable-route"),
        decisions=JsonlDecisionLog(tmp_path / "decisions.jsonl"),
    ).run(promotion_request)

    assert result.decision.outcome is PromotionOutcome.BLOCKED
    assert result.decision.reason == "candidate not found in catalog"
    assert result.evaluation.contract.checked == 0
    assert result.events == ["catalog-candidate-missing"]
def test_objective_classes_skip_judges(tmp_path: Path) -> None:
    calls: list[str] = []
    judge = Judge(
        name="judge-a",
        family="family-a",
        evaluate=lambda _output: calls.append("called") or JudgeAssessment(score=0.0, passed=False),
    )
    candidate = Candidate(
        id="objective",
        provider="local",
        destination="local://engine-a",
        route="objective-route",
        mode=EvaluationMode.STRICT_LOCAL,
    )

    result = PromotionPipeline(
        RouteTable("stable-route"),
        decisions=JsonlDecisionLog(tmp_path / "decisions.jsonl"),
    ).run(
        request(
            candidate=candidate,
            evaluation_class=EvaluationClass.OBJECTIVE,
            outputs=[output()],
            judges=[judge],
        )
    )

    assert result.decision.outcome is PromotionOutcome.PROMOTED
    assert result.evaluation.judges_run == 0
    assert calls == []


def test_subjective_judges_are_diverse_and_capped_at_three(tmp_path: Path) -> None:
    families: list[str] = []
    judges = [
        Judge(
            name=f"judge-{index}",
            family=family,
            evaluate=lambda _output, family=family: families.append(family)
            or JudgeAssessment(score=1.0, passed=True),
        )
        for index, family in enumerate(("a", "b", "c", "a"))
    ]
    candidate = Candidate(
        id="subjective",
        provider="local",
        destination="local://engine-a",
        route="subjective-route",
        mode=EvaluationMode.STRICT_LOCAL,
    )

    result = PromotionPipeline(
        RouteTable("stable-route"),
        decisions=JsonlDecisionLog(tmp_path / "decisions.jsonl"),
    ).run(
        request(
            candidate=candidate,
            evaluation_class=EvaluationClass.SUBJECTIVE,
            outputs=[output()],
            judges=judges,
        )
    )

    assert result.decision.outcome is PromotionOutcome.PROMOTED
    assert result.evaluation.judges_run == 3
    assert families == ["a", "b", "c"]


def test_strict_local_evaluation_consumes_zero_reserved_capacity(tmp_path: Path) -> None:
    candidate = Candidate(
        id="strict-local",
        provider="local",
        destination="local://engine-a",
        route="local-route",
        mode=EvaluationMode.STRICT_LOCAL,
    )

    result = PromotionPipeline(
        RouteTable("stable-route"),
        decisions=JsonlDecisionLog(tmp_path / "decisions.jsonl"),
    ).run(
        request(
            candidate=candidate,
            evaluation_class=EvaluationClass.OBJECTIVE,
            outputs=[output()],
        )
    )

    assert result.evaluation.reserved_capacity_consumed == 0

def test_decision_is_durable_before_route_change(tmp_path: Path) -> None:
    decisions = JsonlDecisionLog(tmp_path / "decisions.jsonl")

    class ObservedRoutes(RouteTable):
        expected_outcome = PromotionOutcome.PROMOTED

        def activate(self, route: str) -> None:
            assert decisions.records()[-1].outcome is self.expected_outcome
            super().activate(route)

        def rollback(self, route: str) -> None:
            assert decisions.records()[-1].outcome is self.expected_outcome
            super().rollback(route)

    routes = ObservedRoutes("stable-route")
    pipeline = PromotionPipeline(routes, decisions=decisions)
    candidate = Candidate(
        id="ordered-decision",
        provider="local",
        destination="local://engine-a",
        route="candidate-route",
        mode=EvaluationMode.STRICT_LOCAL,
    )

    promoted = pipeline.run(
        request(
            candidate=candidate,
            evaluation_class=EvaluationClass.OBJECTIVE,
            outputs=[output()],
        )
    )
    routes.expected_outcome = PromotionOutcome.ROLLED_BACK
    rolled_back = pipeline.run(
        request(
            candidate=candidate,
            evaluation_class=EvaluationClass.OBJECTIVE,
            outputs=[output()],
            canary=(
                CanaryMetrics(requests=100, errors=1, latency_p95_ms=100, quota_draw=100),
                CanaryMetrics(requests=100, errors=10, latency_p95_ms=100, quota_draw=100),
            ),
        )
    )

    assert promoted.decision.outcome is PromotionOutcome.PROMOTED
    assert rolled_back.decision.outcome is PromotionOutcome.ROLLED_BACK


def test_first_time_cloud_provider_requires_matching_egress_approval(tmp_path: Path) -> None:
    candidate = Candidate(
        id="cloud-candidate",
        provider="new-cloud",
        destination="https://api.new-cloud.example",
        route="cloud-route",
        mode=EvaluationMode.CLOUD,
    )
    decisions = JsonlDecisionLog(tmp_path / "decisions.jsonl")
    blocked = PromotionPipeline(RouteTable("stable-route"), decisions=decisions).run(
        request(
            candidate=candidate,
            evaluation_class=EvaluationClass.OBJECTIVE,
            outputs=[output()],
        )
    )
    assert blocked.decision.outcome is PromotionOutcome.BLOCKED
    assert blocked.decision.reason == "egress approval required"
    assert "egress-approval-required" in blocked.events

    approved_request = request(candidate=candidate, evaluation_class=EvaluationClass.OBJECTIVE, outputs=[output()])
    approved_request.egress_approvals = [
        EgressApproval(provider="new-cloud", destination="https://api.new-cloud.example", approval_id="egress-1")
    ]
    promoted = PromotionPipeline(RouteTable("stable-route"), decisions=decisions).run(approved_request)
    assert promoted.decision.outcome is PromotionOutcome.PROMOTED


@pytest.mark.parametrize(
    ("candidate_metrics", "reason"),
    [
        (CanaryMetrics(requests=100, errors=10, latency_p95_ms=100, quota_draw=100), "error-rate regression"),
        (CanaryMetrics(requests=100, errors=1, latency_p95_ms=250, quota_draw=100), "latency-p95 regression"),
        (CanaryMetrics(requests=100, errors=1, latency_p95_ms=100, quota_draw=200), "quota-draw regression"),
    ],
)
def test_canary_regression_rolls_back(
    candidate_metrics: CanaryMetrics,
    reason: str,
    tmp_path: Path,
) -> None:
    routes = RouteTable("stable-route")
    candidate = Candidate(
        id="bad-canary",
        provider="local",
        destination="local://engine-a",
        route="bad-route",
        mode=EvaluationMode.STRICT_LOCAL,
    )
    result = PromotionPipeline(
        routes,
        decisions=JsonlDecisionLog(tmp_path / "decisions.jsonl"),
    ).run(
        request(
            candidate=candidate,
            evaluation_class=EvaluationClass.OBJECTIVE,
            outputs=[output()],
            canary=(CanaryMetrics(requests=100, errors=1, latency_p95_ms=100, quota_draw=100), candidate_metrics),
        )
    )

    assert result.decision.outcome is PromotionOutcome.ROLLED_BACK
    assert reason in result.decision.reason
    assert routes.current_route == "stable-route"
    assert result.decision.rollback_target == "stable-route"


def test_fixture_run_promotes_good_and_rolls_back_bad_candidate(tmp_path: Path) -> None:
    good = json.loads((FIXTURES / "good_candidate.json").read_text())
    bad = json.loads((FIXTURES / "bad_candidate.json").read_text())
    routes = RouteTable("stable-route")
    decisions = JsonlDecisionLog(tmp_path / "decisions.jsonl")
    pipeline = PromotionPipeline(routes, decisions=decisions)

    good_result = pipeline.run(PromotionRequest.from_fixture(good))
    bad_result = pipeline.run(PromotionRequest.from_fixture(bad))

    assert good_result.decision.outcome is PromotionOutcome.PROMOTED
    assert bad_result.decision.outcome is PromotionOutcome.ROLLED_BACK
    assert routes.current_route == good["candidate"]["route"]
    assert [record.outcome for record in decisions.records()] == [
        PromotionOutcome.PROMOTED,
        PromotionOutcome.ROLLED_BACK,
    ]
    for result in (good_result, bad_result):
        record = result.decision.model_dump(by_alias=True)
        assert {
            "inputs",
            "reason",
            "cohort",
            "outcome",
            "provenance",
            "rollbackTarget",
        } <= record.keys()
        assert record["version"] == 1
        assert record["inputs"]["contractSuite"]["version"] == 1
        assert record["inputs"]["canaryPolicy"]["cohort"] == "fixture-cohort"
        assert len(record["inputs"]["outputDigests"]) == 1
