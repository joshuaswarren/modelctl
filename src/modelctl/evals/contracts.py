"""Deterministic contracts for model candidate evaluation."""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Any

from pydantic import Field, field_validator

from modelctl.domain.workload import DomainModel


class EvaluationClass(str, Enum):
    OBJECTIVE = "objective"
    SUBJECTIVE = "subjective"


class EvaluationMode(str, Enum):
    STRICT_LOCAL = "strict-local"
    CLOUD = "cloud"


class ContractKind(str, Enum):
    FORMAT = "format"
    TOOL_USE = "tool-use"
    REFUSAL = "refusal"
    EXACT_RECEIPT = "exact-receipt"


class Candidate(DomainModel):
    """A candidate route and the destination used for its evaluation."""

    id: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    destination: str = Field(min_length=1)
    route: str = Field(min_length=1)
    mode: EvaluationMode
    capabilities: list[str] = Field(default_factory=list)
    context_window_tokens: int = Field(default=1, ge=1, alias="contextWindowTokens")
    available: bool = True

    @field_validator("capabilities")
    @classmethod
    def validate_capabilities(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("candidate capabilities must not be blank")
        if len(values) != len(set(values)):
            raise ValueError("candidate capabilities must be unique")
        return values


class ToolCall(DomainModel):
    """A structured tool invocation in a model response."""

    name: str = Field(min_length=1)
    arguments: Mapping[str, Any] = Field(default_factory=dict)


class StructuredOutput(DomainModel):
    """The response fields that deterministic contracts can inspect."""

    format: str = Field(min_length=1)
    value: Any
    tool_calls: list[ToolCall] = Field(default_factory=list, alias="toolCalls")
    refused: bool = False
    receipt: Mapping[str, Any] | None = None


class ContractAssertion(DomainModel):
    """One deterministic assertion over a structured model response."""

    name: str = Field(min_length=1)
    kind: ContractKind
    expected: Any


class ContractSuite(DomainModel):
    """The deterministic gate and class for one evaluation."""

    version: int = Field(default=1, ge=1)
    name: str = Field(min_length=1)
    evaluation_class: EvaluationClass = Field(alias="evaluationClass")
    assertions: list[ContractAssertion] = Field(min_length=1)
    minimum_judge_score: float = Field(default=0.5, ge=0.0, le=1.0, alias="minimumJudgeScore")


class ContractResult(DomainModel):
    """Receipt from the deterministic contract gate."""

    passed: bool
    checked: int = Field(ge=0)
    failures: list[str] = Field(default_factory=list)


def _tool_failures(assertion: ContractAssertion, output: StructuredOutput) -> list[str]:
    expected = assertion.expected
    if not isinstance(expected, Mapping):
        return [f"{assertion.name}: tool-use expectation must be an object"]
    required = expected.get("required", [])
    forbidden = expected.get("forbidden", [])
    if not isinstance(required, list) or not isinstance(forbidden, list):
        return [f"{assertion.name}: tool-use lists must be arrays"]
    actual = [call.name for call in output.tool_calls]
    failures = [f"{assertion.name}: missing tool {name}" for name in required if name not in actual]
    failures.extend(f"{assertion.name}: forbidden tool {name}" for name in forbidden if name in actual)
    return failures


def _assertion_failures(assertion: ContractAssertion, output: StructuredOutput) -> list[str]:
    if assertion.kind is ContractKind.FORMAT:
        return [] if output.format == assertion.expected else [
            f"{assertion.name}: expected format {assertion.expected!r}, got {output.format!r}"
        ]
    if assertion.kind is ContractKind.TOOL_USE:
        return _tool_failures(assertion, output)
    if assertion.kind is ContractKind.REFUSAL:
        return [] if output.refused == assertion.expected else [
            f"{assertion.name}: expected refusal {assertion.expected!r}, got {output.refused!r}"
        ]
    if output.receipt != assertion.expected:
        return [f"{assertion.name}: receipt does not match the expected receipt"]
    return []


def evaluate_contracts(
    outputs: Sequence[StructuredOutput | Mapping[str, Any]],
    suite: ContractSuite,
) -> ContractResult:
    """Run every deterministic assertion before any judge can run."""

    failures: list[str] = []
    checked = 0
    for index, raw_output in enumerate(outputs):
        output = raw_output if isinstance(raw_output, StructuredOutput) else StructuredOutput.model_validate(raw_output)
        for assertion in suite.assertions:
            checked += 1
            failures.extend(f"case {index}: {failure}" for failure in _assertion_failures(assertion, output))
    return ContractResult(passed=not failures, checked=checked, failures=failures)


def standard_contract_suite(evaluation_class: EvaluationClass) -> ContractSuite:
    """Build the portable fixture contract set used by the end-to-end example."""

    return ContractSuite(
        name="standard-response-contracts",
        evaluationClass=evaluation_class,
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
