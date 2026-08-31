"""Bounded, diverse judge selection for subjective evaluations."""
from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from pydantic import Field

from modelctl.domain.workload import DomainModel
from modelctl.evals.contracts import StructuredOutput


class JudgeAssessment(DomainModel):
    """One judge's normalized assessment."""

    judge: str = ""
    family: str = ""
    score: float = Field(ge=0.0, le=1.0)
    passed: bool
    reason: str = ""


@dataclass(frozen=True)
class Judge:
    """A judge adapter identified by its model family."""

    name: str
    family: str
    evaluate: Callable[[StructuredOutput], JudgeAssessment]

    def __post_init__(self) -> None:
        if not self.name.strip() or not self.family.strip():
            raise ValueError("judge name and family are required")


MAX_JUDGES = 3


def select_diverse_judges(judges: Sequence[Judge], limit: int = MAX_JUDGES) -> tuple[Judge, ...]:
    """Select at most one judge from each family, in declaration order."""

    if limit < 1:
        raise ValueError("judge limit must be positive")
    selected: list[Judge] = []
    families: set[str] = set()
    for judge in judges:
        if judge.family in families:
            continue
        selected.append(judge)
        families.add(judge.family)
        if len(selected) == min(limit, MAX_JUDGES):
            break
    return tuple(selected)


class JudgePanel:
    """Evaluate subjective outputs with a hard diversity and count bound."""

    def __init__(self, judges: Sequence[Judge], limit: int = MAX_JUDGES) -> None:
        self.judges = select_diverse_judges(judges, limit)

    @property
    def judge_count(self) -> int:
        return len(self.judges)

    def evaluate(self, outputs: Sequence[StructuredOutput]) -> list[JudgeAssessment]:
        assessments: list[JudgeAssessment] = []
        for judge in self.judges:
            for output in outputs:
                assessment = judge.evaluate(output)
                if not isinstance(assessment, JudgeAssessment):
                    raise TypeError(f"judge {judge.name} must return JudgeAssessment")
                assessments.append(
                    assessment.model_copy(update={"judge": judge.name, "family": judge.family})
                )
        return assessments


def judges_pass(assessments: Sequence[JudgeAssessment], minimum_score: float) -> bool:
    """Require every bounded assessment to clear the configured quality floor."""

    return bool(assessments) and all(item.passed and item.score >= minimum_score for item in assessments)
