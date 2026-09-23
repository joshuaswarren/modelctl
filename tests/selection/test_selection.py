"""Tests for the provider-neutral subscription selection engine."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from modelctl.domain.policy import PolicyBundle
from modelctl.domain.workload import WorkloadClass
from modelctl.evals.contracts import EvaluationMode
from modelctl.evals.promotion import PromotionDecision, PromotionOutcome
from modelctl.selection import (
    SelectionRequest,
    select_models,
    selection_policy_from_bundle,
)

NOW = datetime(2026, 9, 1, 12, 0, 0, tzinfo=UTC)


def promotion(candidate_id: str, outcome: PromotionOutcome = PromotionOutcome.PROMOTED) -> PromotionDecision:
    return PromotionDecision(
        inputs={
            "candidate": candidate(candidate_id),
            "catalogCandidate": candidate(candidate_id),
        },
        reason="canary passed",
        cohort="default",
        outcome=outcome,
        provenance={"bundle": "test"},
    )


def candidate(
    candidate_id: str,
    *,
    provider: str = "zai",
    account: str = "main",
    mode: EvaluationMode = EvaluationMode.CLOUD,
    available: bool = True,
    expires_at: datetime | None = None,
) -> dict[str, Any]:
    return {
        "id": candidate_id,
        "provider": provider,
        "account": account,
        "destination": f"https://example.test/{candidate_id}",
        "route": candidate_id,
        "mode": mode.value,
        "available": available,
        "qualificationExpiresAt": expires_at.isoformat() if expires_at else None,
    }


def estimate(
    provider: str,
    account: str,
    *,
    used: float | None = 100.0,
    unit: str = "tokens",
    fresh: datetime | None = NOW,
) -> dict[str, Any]:
    return {
        "sourceClass": "provider-derived",
        "provider": provider,
        "accountLabel": account,
        "quotaUsed": used,
        "quotaUnit": unit,
        "freshnessTime": fresh.isoformat() if fresh else None,
    }


def bundle(section: dict[str, Any], *, strict_local: set[str] | None = None) -> PolicyBundle:
    workloads = [
        WorkloadClass(name=name, strict_local=name in (strict_local or set()))
        for name in ("plan", "task")
    ]
    return PolicyBundle(
        workloads=workloads,
        routes={"omp": {"selection": section}},
    )


def section(
    *,
    candidates: list[dict[str, Any]] | None = None,
    promotions: list[PromotionDecision] | None = None,
    runway: dict[str, dict[str, float]] | None = None,
    roles: dict[str, dict[str, Any]] | None = None,
    max_quota_used: float = 0.9,
    quota_unit: str = "tokens",
) -> dict[str, Any]:
    return {
        "quotaUnit": quota_unit,
        "maxQuotaUsed": max_quota_used,
        "maxObservationAgeSeconds": 3600,
        "runway": runway if runway is not None else {"zai/main": {"maximum": 1000.0}},
        "candidates": candidates if candidates is not None else [candidate("alpha")],
        "promotions": promotions if promotions is not None else [promotion("alpha")],
        "roles": roles if roles is not None else {"plan": {"workloadClass": "plan", "candidates": ["alpha"]}},
    }


def estimates(*items: dict[str, Any]) -> list[Any]:
    from modelctl.telemetry.contracts import RunwayEstimate

    return [RunwayEstimate.model_validate(item) for item in items]


def request(
    policy_section: dict[str, Any],
    runway: list[Any],
    *,
    roles: dict[str, str] | None = None,
    chains: dict[str, list[str]] | None = None,
    strict_local: set[str] | None = None,
) -> SelectionRequest:
    return SelectionRequest(
        policy=selection_policy_from_bundle(bundle(policy_section, strict_local=strict_local)),
        runway=runway,
        currentModelRoles=roles or {},
        currentFallbackChains=chains or {},
        now=NOW,
    )


class TestPolicyParsing:
    def test_parses_typed_selection_section_from_omp_routes(self) -> None:
        policy = selection_policy_from_bundle(
            bundle(
                section(
                    candidates=[candidate("alpha")],
                    promotions=[promotion("alpha")],
                    runway={"zai/main": {"maximum": 5000.0}},
                    roles={"plan": {"workloadClass": "plan", "candidates": ["alpha"]}},
                ),
                strict_local={"plan"},
            )
        )
        assert policy.quota_unit.value == "tokens"
        assert policy.max_quota_used == 0.9
        assert policy.max_observation_age_seconds == 3600
        assert policy.runway["zai/main"].maximum == 5000.0
        assert policy.candidates[0].id == "alpha"
        assert policy.promotions[0].outcome is PromotionOutcome.PROMOTED
        assert policy.roles["plan"].workload_class == "plan"
        assert policy.roles["plan"].candidates == ["alpha"]
        assert policy.roles["plan"].strict_local is True

    def test_rejects_missing_selection_section(self) -> None:
        with pytest.raises(ValueError):
            selection_policy_from_bundle(PolicyBundle(routes={}))

    def test_rejects_non_object_selection_section(self) -> None:
        with pytest.raises(TypeError):
            selection_policy_from_bundle(PolicyBundle(routes={"omp": {"selection": "nope"}}))

    def test_rejects_unknown_workload_class_in_role_mapping(self) -> None:
        with pytest.raises(ValueError, match="workload"):
            selection_policy_from_bundle(
                bundle(section(roles={"plan": {"workloadClass": "nope", "candidates": ["alpha"]}}))
            )

    def test_rejects_malformed_runway_maximum_key(self) -> None:
        with pytest.raises(ValueError, match="provider/account"):
            selection_policy_from_bundle(bundle(section(runway={"zai-main": {"maximum": 10.0}})))

    def test_rejects_non_positive_runway_maximum(self) -> None:
        with pytest.raises(ValidationError):
            selection_policy_from_bundle(bundle(section(runway={"zai/main": {"maximum": 0}})))

    def test_role_without_strict_local_workload_is_cloud(self) -> None:
        policy = selection_policy_from_bundle(bundle(section()))
        assert policy.roles["plan"].strict_local is False


class TestEligibility:
    def test_unknown_candidate_reference_is_excluded(self) -> None:
        req = request(
            section(roles={"plan": {"workloadClass": "plan", "candidates": ["ghost", "alpha"]}}),
            estimates(estimate("zai", "main")),
        )
        plan = select_models(req)
        assert plan.model_roles["plan"] == "alpha"
        reasons = {d.role: d.reason for d in plan.decisions}
        assert "unknown" in reasons["plan"]

    def test_stale_freshness_is_excluded(self) -> None:
        stale = estimate("zai", "main", fresh=NOW - timedelta(seconds=3601))
        req = request(section(), estimates(stale), roles={"plan": "alpha"})
        plan = select_models(req)
        assert plan.blocked_roles == ["plan"]
        assert "stale" in plan.decisions[0].reason

    def test_missing_freshness_time_is_excluded(self) -> None:
        req = request(section(), estimates(estimate("zai", "main", fresh=None)), roles={"plan": "alpha"})
        plan = select_models(req)
        assert plan.blocked_roles == ["plan"]

    def test_mismatched_quota_unit_is_excluded(self) -> None:
        req = request(section(), estimates(estimate("zai", "main", unit="credits")), roles={"plan": "alpha"})
        plan = select_models(req)
        assert plan.blocked_roles == ["plan"]
        assert "mismatched-unit" in plan.decisions[0].reason

    def test_expired_qualification_is_excluded(self) -> None:
        expired = candidate("alpha", expires_at=NOW - timedelta(seconds=1))
        fresh = candidate("beta")
        req = request(
            section(
                candidates=[expired, fresh],
                promotions=[promotion("alpha"), promotion("beta")],
                roles={"plan": {"workloadClass": "plan", "candidates": ["alpha", "beta"]}},
            ),
            estimates(estimate("zai", "main")),
            roles={"plan": "alpha"},
        )
        plan = select_models(req)
        assert plan.model_roles["plan"] == "beta"
        assert "expired" in plan.decisions[0].reason

    def test_unavailable_candidate_is_excluded(self) -> None:
        down = candidate("alpha", available=False)
        fresh = candidate("beta")
        req = request(
            section(
                candidates=[down, fresh],
                promotions=[promotion("alpha"), promotion("beta")],
                roles={"plan": {"workloadClass": "plan", "candidates": ["alpha", "beta"]}},
            ),
            estimates(estimate("zai", "main")),
            roles={"plan": "alpha"},
        )
        plan = select_models(req)
        assert plan.model_roles["plan"] == "beta"
        assert "unavailable" in plan.decisions[0].reason

    def test_unpromoted_candidate_is_excluded(self) -> None:
        promoted = candidate("alpha")
        unpromoted = candidate("beta")
        req = request(
            section(
                candidates=[promoted, unpromoted],
                promotions=[promotion("alpha")],
                roles={"plan": {"workloadClass": "plan", "candidates": ["beta", "alpha"]}},
            ),
            estimates(estimate("zai", "main")),
            roles={"plan": "beta"},
        )
        plan = select_models(req)
        assert plan.model_roles["plan"] == "alpha"
        assert "unpromoted" in plan.decisions[0].reason

    @pytest.mark.parametrize("outcome", [PromotionOutcome.ROLLED_BACK, PromotionOutcome.BLOCKED])
    def test_non_promoted_outcomes_do_not_qualify(self, outcome: PromotionOutcome) -> None:
        promoted = candidate("alpha")
        other = candidate("beta")
        req = request(
            section(
                candidates=[promoted, other],
                promotions=[promotion("alpha"), promotion("beta", outcome)],
                roles={"plan": {"workloadClass": "plan", "candidates": ["beta", "alpha"]}},
            ),
            estimates(estimate("zai", "main")),
            roles={"plan": "beta"},
        )
        plan = select_models(req)
        assert plan.model_roles["plan"] == "alpha"

    def test_wrong_mode_candidate_is_excluded(self) -> None:
        local_only = candidate("alpha", mode=EvaluationMode.STRICT_LOCAL)
        req = request(
            section(candidates=[local_only], promotions=[promotion("alpha")]),
            estimates(estimate("zai", "main")),
        )
        plan = select_models(req)
        assert plan.blocked_roles == ["plan"]
        assert "wrong-mode" in plan.decisions[0].reason

    def test_runway_join_requires_exact_provider_and_account(self) -> None:
        other_account = estimate("zai", "secondary")
        req = request(
            section(runway={"zai/main": {"maximum": 1000.0}, "zai/secondary": {"maximum": 1000.0}}),
            estimates(other_account),
            roles={"plan": "alpha"},
        )
        plan = select_models(req)
        assert plan.blocked_roles == ["plan"]

    def test_equal_timestamp_runway_uses_conservative_value(self) -> None:
        low = estimate("zai", "main", used=100.0)
        high = estimate("zai", "main", used=950.0)
        selection_policy = section()
        plans = [
            select_models(request(selection_policy, estimates(*items), roles={"plan": "alpha"}))
            for items in ((low, high), (high, low))
        ]
        assert all(plan.blocked_roles == ["plan"] for plan in plans)
        assert all("quota-exceeded" in plan.decisions[0].reason for plan in plans)

    def test_above_maximum_quota_used_threshold_is_excluded(self) -> None:
        full = estimate("zai", "main", used=950.0)
        req = request(
            section(max_quota_used=0.9, runway={"zai/main": {"maximum": 1000.0}}),
            estimates(full),
            roles={"plan": "alpha"},
        )
        plan = select_models(req)
        assert plan.blocked_roles == ["plan"]
        assert "quota-exceeded" in plan.decisions[0].reason

    def test_missing_runway_maximum_is_excluded(self) -> None:
        req = request(
            section(runway={}),
            estimates(estimate("zai", "main")),
            roles={"plan": "alpha"},
        )
        plan = select_models(req)
        assert plan.blocked_roles == ["plan"]

    def test_missing_quota_used_is_excluded(self) -> None:
        req = request(section(), estimates(estimate("zai", "main", used=None)), roles={"plan": "alpha"})
        plan = select_models(req)
        assert plan.blocked_roles == ["plan"]
        assert "no-usage" in plan.decisions[0].reason


class TestStrictLocal:
    def test_strict_local_workload_never_selects_cloud(self) -> None:
        cloud = candidate("alpha")
        req = request(
            section(candidates=[cloud], promotions=[promotion("alpha")]),
            estimates(estimate("zai", "main")),
            strict_local={"plan"},
        )
        plan = select_models(req)
        assert plan.blocked_roles == ["plan"]
        assert "wrong-mode" in plan.decisions[0].reason

    def test_strict_local_workload_selects_strict_local_candidate(self) -> None:
        local = candidate("alpha", mode=EvaluationMode.STRICT_LOCAL, provider="local")
        req = request(
            section(candidates=[local], promotions=[promotion("alpha")], runway={}),
            estimates(),
            strict_local={"plan"},
        )
        plan = select_models(req)
        assert plan.model_roles["plan"] == "alpha"


class TestSelectionOrder:
    def test_recovered_primary_reclaims_role_from_fallback(self) -> None:
        req = request(
            section(
                candidates=[candidate("alpha"), candidate("beta")],
                promotions=[promotion("alpha"), promotion("beta")],
                roles={"plan": {"workloadClass": "plan", "candidates": ["beta", "alpha"]}},
            ),
            estimates(estimate("zai", "main")),
            roles={"plan": "alpha"},
        )
        plan = select_models(req)
        assert plan.model_roles["plan"] == "beta"
        assert plan.changed_roles == ["plan"]
        assert plan.fallback_chains["plan"] == ["alpha"]

    def test_each_role_orders_shared_candidates_independently(self) -> None:
        req = request(
            section(
                candidates=[candidate("alpha"), candidate("beta")],
                promotions=[promotion("alpha"), promotion("beta")],
                roles={
                    "plan": {"workloadClass": "plan", "candidates": ["alpha", "beta"]},
                    "second": {"workloadClass": "plan", "candidates": ["beta", "alpha"]},
                },
            ),
            estimates(estimate("zai", "main")),
        )
        plan = select_models(req)
        assert (plan.model_roles["plan"], plan.fallback_chains["plan"]) == ("alpha", ["beta"])
        assert (plan.model_roles["second"], plan.fallback_chains["second"]) == ("beta", ["alpha"])

    def test_falls_back_to_next_eligible_in_role_order(self) -> None:
        req = request(
            section(
                candidates=[candidate("alpha", provider="old"), candidate("beta"), candidate("gamma")],
                promotions=[promotion("alpha"), promotion("beta"), promotion("gamma")],
                runway={"old/main": {"maximum": 1000.0}, "zai/main": {"maximum": 1000.0}},
                roles={"plan": {"workloadClass": "plan", "candidates": ["alpha", "gamma", "beta"]}},
            ),
            estimates(estimate("old", "main", fresh=NOW - timedelta(hours=2)), estimate("zai", "main")),
            roles={"plan": "alpha"},
        )
        plan = select_models(req)
        assert plan.model_roles["plan"] == "gamma"
        assert plan.fallback_chains["plan"] == ["beta"]
        assert "stale" in plan.decisions[0].reason

    def test_no_eligible_candidate_blocks_role_and_keeps_value(self) -> None:
        req = request(
            section(),
            estimates(estimate("zai", "main", fresh=NOW - timedelta(hours=3))),
            roles={"plan": "alpha"},
        )
        plan = select_models(req)
        assert plan.blocked_roles == ["plan"]
        assert plan.changed_roles == []
        assert plan.model_roles["plan"] == "alpha"
        decision = plan.decisions[0]
        assert decision.blocked is True
        assert decision.selected is None

    def test_blocked_role_without_incumbent_keeps_maps_clean(self) -> None:
        req = request(section(), estimates())
        plan = select_models(req)
        assert plan.blocked_roles == ["plan"]
        assert plan.model_roles == {}
        assert plan.fallback_chains == {}


class TestMergeAndPlan:
    def test_managed_role_replaces_and_unmanaged_keys_are_preserved(self) -> None:
        alpha = candidate("alpha")
        req = request(
            section(candidates=[alpha], promotions=[promotion("alpha")]),
            estimates(estimate("zai", "main")),
            roles={"plan": "old-model", "unmanaged-role": "keep-me"},
            chains={"unmanaged-chain": ["keep-1", "keep-2"]},
        )
        plan = select_models(req)
        assert plan.model_roles == {"plan": "alpha", "unmanaged-role": "keep-me"}
        assert plan.fallback_chains == {
            "plan": [],
            "unmanaged-chain": ["keep-1", "keep-2"],
        }

    def test_fallback_chain_is_eligible_candidates_in_selection_order(self) -> None:
        req = request(
            section(
                candidates=[candidate("alpha"), candidate("beta")],
                promotions=[promotion("alpha"), promotion("beta"), promotion("ghost")],
                roles={"plan": {"workloadClass": "plan", "candidates": ["beta", "alpha", "ghost"]}},
            ),
            estimates(estimate("zai", "main")),
        )
        plan = select_models(req)
        assert plan.fallback_chains["plan"] == ["alpha"]

    def test_plan_reports_decision_details(self) -> None:
        req = request(section(), estimates(estimate("zai", "main")), roles={"plan": "alpha"})
        plan = select_models(req)
        assert len(plan.decisions) == 1
        decision = plan.decisions[0]
        assert decision.role == "plan"
        assert decision.workload_class == "plan"
        assert decision.previous == "alpha"
        assert decision.selected == "alpha"
        assert decision.changed is False
        assert decision.blocked is False
        assert decision.reason == "incumbent"

    def test_selection_request_requires_aware_now(self) -> None:
        with pytest.raises(ValidationError):
            SelectionRequest(
                policy=selection_policy_from_bundle(bundle(section())),
                runway=[],
                now=datetime(2026, 9, 1),  # noqa: DTZ001 - fixture exercises naive-now rejection
            )
