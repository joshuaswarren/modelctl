"""Guarded OMP native config client and rollback-safe apply tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from modelctl.adapters.omp.apply import ApplyError, SelectionApplier
from modelctl.adapters.omp.native import (
    MANAGED_CHAIN_KEY,
    MANAGED_ROLE_KEY,
    OVERRIDES_KEY,
    OmpConfigClient,
    OmpConfigError,
)
from modelctl.adapters.omp.receipt import JsonlReceiptSink

ORIGINAL_ROLES = {"default": "native/default:high", "unmanaged-role": "native/keeper"}
ORIGINAL_CHAINS = {"default": ["native/one", "native/two"], "unmanaged-chain": ["keep/me"]}
MANAGED_ROLES = {"default": "zai/glm-5.3-flash", "unmanaged-role": "native/keeper"}
MANAGED_CHAINS = {"default": ["zai/glm-5.3-flash", "fallback/x"], "unmanaged-chain": ["keep/me"]}


def test_client_get_returns_record_and_missing_key_is_empty(seeded_fake) -> None:
    client = OmpConfigClient(seeded_fake.binary)

    assert client.get(MANAGED_ROLE_KEY) == ORIGINAL_ROLES
    assert client.get(OVERRIDES_KEY) == {"reviewer": "@smol"}
    assert client.get("retry.unrelated") == {}


def test_client_set_persists_whole_record_and_failure_raises(seeded_fake) -> None:
    client = OmpConfigClient(seeded_fake.binary)

    client.set(MANAGED_ROLE_KEY, MANAGED_ROLES)
    assert seeded_fake.record(MANAGED_ROLE_KEY) == MANAGED_ROLES

    seeded_fake.seed(failSetForKey={MANAGED_CHAIN_KEY: 1})
    with pytest.raises(OmpConfigError, match="refused"):
        client.set(MANAGED_CHAIN_KEY, MANAGED_CHAINS)
    assert seeded_fake.record(MANAGED_CHAIN_KEY) == ORIGINAL_CHAINS


def test_apply_writes_chains_first_roles_second_and_preserves_unmanaged(seeded_fake) -> None:
    applier = SelectionApplier(OmpConfigClient(seeded_fake.binary))

    result = applier.apply(MANAGED_ROLES, MANAGED_CHAINS)

    assert result.applied is True
    assert result.written_keys == (MANAGED_CHAIN_KEY, MANAGED_ROLE_KEY)
    assert result.overrides_before == result.overrides_after
    assert seeded_fake.config_calls() == [
        ("get", OVERRIDES_KEY),
        ("get", MANAGED_ROLE_KEY),
        ("get", MANAGED_CHAIN_KEY),
        ("set", MANAGED_CHAIN_KEY),
        ("set", MANAGED_ROLE_KEY),
        ("get", MANAGED_CHAIN_KEY),
        ("get", MANAGED_ROLE_KEY),
        ("get", OVERRIDES_KEY),
    ]
    assert seeded_fake.record(MANAGED_ROLE_KEY) == MANAGED_ROLES
    assert seeded_fake.record(MANAGED_CHAIN_KEY) == MANAGED_CHAINS
    assert seeded_fake.record(OVERRIDES_KEY) == {"reviewer": "@smol"}


def test_apply_skips_writes_when_native_already_matches(seeded_fake) -> None:
    applier = SelectionApplier(OmpConfigClient(seeded_fake.binary))
    keys = (MANAGED_ROLE_KEY, MANAGED_CHAIN_KEY, OVERRIDES_KEY)
    before = {key: seeded_fake.record(key) for key in keys}

    result = applier.apply(before[MANAGED_ROLE_KEY], before[MANAGED_CHAIN_KEY])

    assert result.applied is False
    assert result.written_keys == ()
    assert ("set", MANAGED_ROLE_KEY) not in seeded_fake.config_calls()
    assert ("set", MANAGED_CHAIN_KEY) not in seeded_fake.config_calls()
    assert {key: seeded_fake.record(key) for key in keys} == before


def test_failed_second_write_rolls_back_both_original_role_keys(seeded_fake) -> None:
    seeded_fake.seed(failSetForKey={MANAGED_ROLE_KEY: 1})
    applier = SelectionApplier(OmpConfigClient(seeded_fake.binary))

    with pytest.raises(ApplyError, match="rolled back") as caught:
        applier.apply(MANAGED_ROLES, MANAGED_CHAINS)

    assert caught.value.written_keys == (MANAGED_CHAIN_KEY, MANAGED_ROLE_KEY)
    assert seeded_fake.config_calls() == [
        ("get", OVERRIDES_KEY),
        ("get", MANAGED_ROLE_KEY),
        ("get", MANAGED_CHAIN_KEY),
        ("set", MANAGED_CHAIN_KEY),
        ("set", MANAGED_ROLE_KEY),  # fails
        ("set", MANAGED_ROLE_KEY),  # restore
        ("get", MANAGED_ROLE_KEY),
        ("set", MANAGED_CHAIN_KEY),  # restore
        ("get", MANAGED_CHAIN_KEY),
    ]
    assert seeded_fake.record(MANAGED_CHAIN_KEY) == ORIGINAL_CHAINS
    assert seeded_fake.record(OVERRIDES_KEY) == {"reviewer": "@smol"}


def test_readback_mismatch_rolls_back_both_original_role_keys(seeded_fake) -> None:
    seeded_fake.seed(tamperReadback=True)
    applier = SelectionApplier(OmpConfigClient(seeded_fake.binary))

    with pytest.raises(ApplyError, match="readback"):
        applier.apply(MANAGED_ROLES, MANAGED_CHAINS)

    assert seeded_fake.record(MANAGED_ROLE_KEY) == ORIGINAL_ROLES
    assert seeded_fake.record(MANAGED_CHAIN_KEY) == ORIGINAL_CHAINS


def test_override_disturbance_rolls_back_and_never_writes_overrides(seeded_fake) -> None:
    seeded_fake.seed(tamperOverridesOnSet=True)
    applier = SelectionApplier(OmpConfigClient(seeded_fake.binary))

    with pytest.raises(ApplyError, match=OVERRIDES_KEY):
        applier.apply(MANAGED_ROLES, MANAGED_CHAINS)

    assert ("set", OVERRIDES_KEY) not in seeded_fake.config_calls()
    assert seeded_fake.record(MANAGED_ROLE_KEY) == ORIGINAL_ROLES
    assert seeded_fake.record(MANAGED_CHAIN_KEY) == ORIGINAL_CHAINS


def test_receipt_append_is_fsynced_jsonl(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    syncs: list[int] = []
    real_fsync = os.fsync

    def counting_fsync(fd: int) -> None:
        syncs.append(fd)
        real_fsync(fd)

    monkeypatch.setattr(os, "fsync", counting_fsync)
    path = tmp_path / "receipts.jsonl"
    sink = JsonlReceiptSink(path)
    first: dict[str, Any] = {"mode": "apply", "status": "ok"}
    second: dict[str, Any] = {"mode": "dry-run", "status": "ok"}

    sink.append(first)
    sink.append(second)

    assert len(syncs) == 3
    lines = path.read_text(encoding="utf-8").splitlines()
    assert [json.loads(line) for line in lines] == [first, second]


def test_receipt_append_creates_parent_directories(tmp_path: Path) -> None:
    sink = JsonlReceiptSink(tmp_path / "nested" / "dir" / "receipts.jsonl")

    sink.append({"status": "ok"})

    assert (tmp_path / "nested" / "dir" / "receipts.jsonl").exists()
