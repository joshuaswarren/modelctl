from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from modelctl.domain.budget import Budget
from modelctl.domain.engine import Engine, EngineState, PhysicalEngine
from modelctl.domain.events import Event, EventSeverity
from modelctl.domain.metadata import Metadata, OverrideSource, RequestMetadata
from modelctl.domain.policy import PolicyBundle
from modelctl.domain.reservation import Reservation
from modelctl.domain.runway import Runway, RunwaySource
from modelctl.domain.workload import UnavailableBehavior, WorkloadClass


def test_physical_engine_tracks_aliases_and_reservations() -> None:
    engine = PhysicalEngine(
        id="engine-a",
        host="engine-a.example.test",
        interactive_reserved=1,
        aliases=["tiny", "slow"],
        max_slots=4,
        active_slots=3,
    )

    assert engine.id == "engine-a"
    assert engine.available_slots == 1
    assert engine.reserved_interactive_slots == 1


def test_request_metadata_has_wire_aliases() -> None:
    metadata = RequestMetadata(
        role="researcher",
        agent="agent-a",
        workload_class="researcher",
        direct_cloud=True,
    )

    assert metadata.model_dump(by_alias=True)["workloadClass"] == "researcher"


def test_workload_classes_use_stable_values() -> None:
    workload = WorkloadClass(name="scout-bounded", strict_local=True, unavailable_behavior="block")

    assert workload.name == "scout-bounded"
    assert workload.unavailable_behavior is UnavailableBehavior.BLOCK


def test_reservation_requires_two_hosts_or_explicit_n1_impossible_reason() -> None:
    with pytest.raises(ValidationError):
        Reservation(workload="advisor", prewarm_hosts=["engine-a.example.test"])

    reservation = Reservation(
        workload="advisor",
        prewarm_hosts=[],
        n1_impossible=True,
        n1_impossible_reason="The compatible hardware has one failure domain.",
    )

    assert reservation.n1_impossible is True


def test_domain_models_reject_unknown_fields_and_keep_utc_events() -> None:
    with pytest.raises(ValidationError):
        Engine(host="engine-a.example.test", unexpected=True)

    engine = Engine(host="engine-a.example.test", state="draining")
    event = Event(
        id="evt-1",
        time=datetime(2026, 8, 29, 12, 0, tzinfo=UTC),
        subsystem="routing",
        severity=EventSeverity.WARNING,
        subject="engine-draining",
        detail={"host": engine.host},
    )

    assert engine.state is EngineState.DRAINING
    assert event.time.tzinfo == UTC


def test_request_metadata_and_budget_are_typed() -> None:
    metadata = Metadata(
        role="researcher",
        agent="agent-a",
        explicit_selector=True,
        override_source="frontmatter",
        project="project-a",
        session="session-a",
        direct_cloud=True,
        manual_cloud=False,
    )
    budget = Budget(agent={"agent-a": 10}, project={"project-a": 20}, provider={"provider-a": 30})
    runway = Runway(source=RunwaySource.PROVIDER_DERIVED, remaining_tokens=100, reset_at=None)

    assert metadata.override_source is OverrideSource.FRONTMATTER
    assert budget.agent["agent-a"] == 10
    assert runway.source.value == "provider-derived"


def test_policy_types_omp_runtime_limits() -> None:
    policy = PolicyBundle.model_validate(
        {
            "version": 1,
            "omp": {
                "containment": {"threshold": 2, "windowMs": 120_000},
                "budgets": {"agent": {"agent-a": 5}},
            },
        }
    )

    assert policy.omp is not None
    assert policy.omp.containment.threshold == 2
    assert policy.omp.budgets.agent["agent-a"] == 5
    with pytest.raises(ValidationError):
        PolicyBundle.model_validate({"version": 1, "omp": {"containment": {"threshold": 0}}})
