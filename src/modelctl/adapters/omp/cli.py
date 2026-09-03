"""CLI for guarded native OMP selection application."""
from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from modelctl.domain.policy import PolicyBundle
from modelctl.selection import (
    SelectionRequest,
    select_models,
    selection_policy_from_bundle,
)
from modelctl.telemetry.contracts import RunwayEstimate

from .apply import ApplyError, SelectionApplier
from .native import MANAGED_CHAIN_KEY, MANAGED_ROLE_KEY, OmpConfigClient
from .receipt import JsonlReceiptSink

_HANDLER_ERRORS = (OSError, ValueError, TypeError, RuntimeError, yaml.YAMLError)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="modelctl-omp")
    parser.add_argument("--policy", type=Path, required=True, help="PolicyBundle path (YAML or JSON)")
    parser.add_argument("--runway", type=Path, help="RunwayEstimate JSON array path")
    parser.add_argument("--omp-binary", default="omp", help="native omp executable")
    parser.add_argument("--receipt", type=Path, help="durable JSONL receipt path")
    parser.add_argument("--apply", action="store_true", help="write the plan to native config")
    parser.add_argument("--check", action="store_true", help="validate the policy and exit")
    arguments = parser.parse_args(argv)
    if arguments.apply and arguments.check:
        parser.error("--check and --apply are mutually exclusive")
    if arguments.apply and arguments.receipt is None:
        parser.error("--apply requires --receipt for a durable audit trail")
    try:
        return _run(arguments)
    except _HANDLER_ERRORS as exc:
        print(f"modelctl-omp: {exc}", file=sys.stderr)
        return 2


def _run(arguments: argparse.Namespace) -> int:
    bundle = _load_bundle(arguments.policy)
    if arguments.check:
        selection_policy_from_bundle(bundle)
        if arguments.runway is not None:
            _load_runway(arguments.runway)
        print("selection policy valid")
        return 0

    client = OmpConfigClient(arguments.omp_binary)
    current_roles = client.get(MANAGED_ROLE_KEY)
    current_chains = client.get(MANAGED_CHAIN_KEY)
    runway = _load_runway(arguments.runway) if arguments.runway else []
    request = SelectionRequest(
        policy=selection_policy_from_bundle(bundle),
        runway=runway,
        currentModelRoles=current_roles,
        currentFallbackChains=current_chains,
        now=datetime.now(UTC),
    )
    plan = select_models(request)
    writes = _planned_writes(plan.model_roles, plan.fallback_chains, current_roles, current_chains)

    if not arguments.apply:
        payload = {"mode": "dry-run", **_plan_payload(plan, writes)}
        print(json.dumps(payload, sort_keys=True))
        if arguments.receipt is not None:
            JsonlReceiptSink(arguments.receipt).append(
                _receipt_record(arguments, "dry-run", "ok", writes, plan, False, None)
            )
        return 0

    receipt_sink = JsonlReceiptSink(arguments.receipt)
    assert arguments.receipt is not None
    try:
        result = SelectionApplier(client).apply(plan.model_roles, plan.fallback_chains)
    except ApplyError as exc:
        receipt_sink.append(
            _receipt_record(
                arguments,
                "apply",
                "rolled-back" if exc.rolled_back else "failed",
                list(exc.written_keys),
                plan,
                exc.rolled_back,
                str(exc),
            )
        )
        raise
    record = _receipt_record(arguments, "apply", "ok", list(result.written_keys), plan, False, None)
    record["overridesBefore"] = result.overrides_before
    record["overridesAfter"] = result.overrides_after
    receipt_sink.append(record)
    print(
        json.dumps(
            {
                "mode": "apply",
                "applied": result.applied,
                "writtenKeys": list(result.written_keys),
                "overridesUnchanged": result.overrides_before == result.overrides_after,
                "receipt": str(arguments.receipt),
            },
            sort_keys=True,
        )
    )
    return 0


def _planned_writes(
    plan_roles: dict[str, str],
    plan_chains: dict[str, list[str]],
    current_roles: dict[str, Any],
    current_chains: dict[str, Any],
) -> list[str]:
    writes: list[str] = []
    if plan_chains != current_chains:
        writes.append(MANAGED_CHAIN_KEY)
    if plan_roles != current_roles:
        writes.append(MANAGED_ROLE_KEY)
    return writes


def _plan_payload(plan: Any, writes: list[str]) -> dict[str, Any]:
    return {
        "modelRoles": dict(plan.model_roles),
        "fallbackChains": {role: list(chain) for role, chain in plan.fallback_chains.items()},
        "changedRoles": list(plan.changed_roles),
        "blockedRoles": list(plan.blocked_roles),
        "decisions": [decision.model_dump(mode="json") for decision in plan.decisions],
        "writes": writes,
    }


def _receipt_record(
    arguments: argparse.Namespace,
    mode: str,
    status: str,
    written_keys: list[str],
    plan: Any,
    rolled_back: bool,
    error: str | None,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "time": datetime.now(UTC).isoformat(),
        "mode": mode,
        "status": status,
        "ompBinary": str(arguments.omp_binary),
        "writtenKeys": written_keys,
        "rolledBack": rolled_back,
        "changedRoles": list(plan.changed_roles),
        "blockedRoles": list(plan.blocked_roles),
    }
    if error is not None:
        record["error"] = error
    return record


def _load_bundle(path: Path) -> PolicyBundle:
    if path.suffix.lower() in (".yaml", ".yml"):
        value: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    else:
        value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError("policy file must contain a mapping")
    return PolicyBundle.model_validate(value)


def _load_runway(path: Path) -> list[RunwayEstimate]:
    value: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, list):
        raise TypeError("runway file must contain a JSON array of estimates")
    try:
        return [RunwayEstimate.model_validate(item) for item in value]
    except ValidationError as exc:
        raise ValueError(f"invalid runway estimate: {exc}") from exc


if __name__ == "__main__":
    raise SystemExit(main())
