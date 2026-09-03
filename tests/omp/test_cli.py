"""CLI surface tests for the guarded OMP selection adapter."""
from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from modelctl.adapters.omp.cli import main

NOW = datetime.now(UTC)

POLICY_YAML = """
version: 1
workloads:
  - name: plan
  - name: task
routes:
  omp:
    selection:
      quotaUnit: tokens
      maxQuotaUsed: 0.9
      maxObservationAgeSeconds: 3600
      runway:
        zai/main:
          maximum: 1000.0
      candidates:
        - id: alpha
          provider: zai
          account: main
          destination: https://example.test/alpha
          route: alpha
          mode: cloud
          priority: 0
          available: true
          qualificationExpiresAt: null
        - id: beta
          provider: zai
          account: main
          destination: https://example.test/beta
          route: beta
          mode: cloud
          priority: 1
          available: true
          qualificationExpiresAt: null
      promotions:
        - inputs:
            candidate:
              id: alpha
              provider: zai
              destination: https://example.test/alpha
              route: alpha
              mode: cloud
              capabilities: []
              contextWindowTokens: 1
              available: true
          reason: canary passed
          cohort: default
          outcome: promoted
          provenance:
            bundle: test
        - inputs:
            candidate:
              id: beta
              provider: zai
              destination: https://example.test/beta
              route: beta
              mode: cloud
              capabilities: []
              contextWindowTokens: 1
              available: true
          reason: canary passed
          cohort: default
          outcome: promoted
          provenance:
            bundle: test
      roles:
        plan:
          workloadClass: plan
          candidates:
            - alpha
            - beta
"""


def write_policy(tmp_path: Path, text: str = POLICY_YAML) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(text, encoding="utf-8")
    return path


def write_runway(tmp_path: Path) -> Path:
    estimate = {
        "sourceClass": "provider-derived",
        "provider": "zai",
        "accountLabel": "main",
        "quotaUsed": 100.0,
        "quotaUnit": "tokens",
        "freshnessTime": NOW.isoformat(),
    }
    path = tmp_path / "runway.json"
    path.write_text(json.dumps([estimate]), encoding="utf-8")
    return path


def test_check_prints_exactly_the_valid_line(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--policy", str(write_policy(tmp_path)), "--check"]) == 0
    assert capsys.readouterr().out == "selection policy valid\n"


def test_check_validates_runway_when_given(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    arguments = [
        "--policy",
        str(write_policy(tmp_path)),
        "--runway",
        str(write_runway(tmp_path)),
    ]

    assert main([*arguments, "--check"]) == 0
    assert capsys.readouterr().out == "selection policy valid\n"


def test_check_rejects_invalid_policy(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    broken = write_policy(tmp_path, "version: 1\nworkloads: []\n")

    assert main(["--policy", str(broken)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip() != ""

    missing = tmp_path / "absent.yaml"
    assert main(["--policy", str(missing)]) == 2


def test_dry_run_prints_plan_without_writes(tmp_path: Path, seeded_fake, capsys: pytest.CaptureFixture[str]) -> None:
    keys = ("modelRoles", "retry.fallbackChains", "task.agentModelOverrides")
    before = {key: seeded_fake.record(key) for key in keys}
    arguments = [
        "--policy",
        str(write_policy(tmp_path)),
        "--runway",
        str(write_runway(tmp_path)),
        "--omp-binary",
        str(seeded_fake.binary),
    ]

    assert main(arguments) == 0

    plan: dict[str, Any] = json.loads(capsys.readouterr().out)
    assert plan["mode"] == "dry-run"
    assert plan["modelRoles"]["plan"] == "alpha"
    assert plan["modelRoles"]["unmanaged-role"] == "native/keeper"
    assert plan["fallbackChains"]["plan"] == ["beta"]
    assert plan["fallbackChains"]["unmanaged-chain"] == ["keep/me"]
    assert plan["changedRoles"] == ["plan"]
    assert plan["blockedRoles"] == []
    assert plan["writes"] == ["retry.fallbackChains", "modelRoles"]
    assert plan["decisions"][0]["role"] == "plan"
    assert seeded_fake.config_calls() == [
        ("get", "modelRoles"),
        ("get", "retry.fallbackChains"),
    ]
    assert {key: seeded_fake.record(key) for key in keys} == before


def test_apply_writes_native_records_and_durable_receipt(
    tmp_path: Path, seeded_fake, capsys: pytest.CaptureFixture[str]
) -> None:
    receipt = tmp_path / "receipts" / "apply.jsonl"
    arguments = [
        "--policy",
        str(write_policy(tmp_path)),
        "--runway",
        str(write_runway(tmp_path)),
        "--omp-binary",
        str(seeded_fake.binary),
        "--receipt",
        str(receipt),
        "--apply",
    ]

    assert main(arguments) == 0

    result: dict[str, Any] = json.loads(capsys.readouterr().out)
    assert result["mode"] == "apply"
    assert result["applied"] is True
    assert result["writtenKeys"] == ["retry.fallbackChains", "modelRoles"]
    assert result["overridesUnchanged"] is True
    assert seeded_fake.record("modelRoles")["plan"] == "alpha"
    assert seeded_fake.record("modelRoles")["unmanaged-role"] == "native/keeper"
    assert seeded_fake.record("retry.fallbackChains")["plan"] == ["beta"]
    assert seeded_fake.record("task.agentModelOverrides") == {"reviewer": "@smol"}

    lines = receipt.read_text(encoding="utf-8").splitlines()
    record: dict[str, Any] = json.loads(lines[0])
    assert record["mode"] == "apply"
    assert record["status"] == "ok"
    assert record["writtenKeys"] == ["retry.fallbackChains", "modelRoles"]
    assert record["rolledBack"] is False
    assert record["overridesBefore"] == record["overridesAfter"]
    assert record["changedRoles"] == ["plan"]


def test_apply_failure_rolls_back_and_receipts_error(
    tmp_path: Path, seeded_fake, capsys: pytest.CaptureFixture[str]
) -> None:
    seeded_fake.seed(failSetForKey={"modelRoles": 1})
    receipt = tmp_path / "receipts.jsonl"
    keys = ("modelRoles", "retry.fallbackChains", "task.agentModelOverrides")
    before = seeded_fake.reload()
    before = {key: before.get(key) for key in keys}
    arguments = [
        "--policy",
        str(write_policy(tmp_path)),
        "--runway",
        str(write_runway(tmp_path)),
        "--omp-binary",
        str(seeded_fake.binary),
        "--receipt",
        str(receipt),
        "--apply",
    ]

    assert main(arguments) == 2

    captured = capsys.readouterr()
    assert "rolled back" in captured.err
    record: dict[str, Any] = json.loads(receipt.read_text(encoding="utf-8").splitlines()[0])
    assert record["status"] == "rolled-back"
    assert record["rolledBack"] is True
    assert record["error"]
    after = seeded_fake.reload()
    assert {key: after.get(key) for key in keys} == before


def test_apply_rollback_failure_receipts_unrestored_state(
    tmp_path: Path, seeded_fake, capsys: pytest.CaptureFixture[str]
) -> None:
    seeded_fake.seed(failSetForKey={"modelRoles": 2})
    receipt = tmp_path / "receipts.jsonl"
    arguments = [
        "--policy",
        str(write_policy(tmp_path)),
        "--runway",
        str(write_runway(tmp_path)),
        "--omp-binary",
        str(seeded_fake.binary),
        "--receipt",
        str(receipt),
        "--apply",
    ]

    assert main(arguments) == 2

    captured = capsys.readouterr()
    assert "rollback failed" in captured.err
    record: dict[str, Any] = json.loads(receipt.read_text(encoding="utf-8").splitlines()[0])
    assert record["status"] == "failed"
    assert record["rolledBack"] is False


def test_apply_requires_durable_receipt_path(
    tmp_path: Path, seeded_fake, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as error:
        main(
            [
                "--policy",
                str(write_policy(tmp_path)),
                "--omp-binary",
                str(seeded_fake.binary),
                "--apply",
            ]
        )

    assert error.value.code == 2
    assert "--receipt" in capsys.readouterr().err
