"""Guarded, rollback-safe application of selection plans to native omp config."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .native import (
    MANAGED_CHAIN_KEY,
    MANAGED_ROLE_KEY,
    OVERRIDES_KEY,
    OmpConfigClient,
    OmpConfigError,
)


class ApplyError(RuntimeError):
    """The guarded apply failed."""

    def __init__(
        self,
        message: str,
        *,
        rolled_back: bool = False,
        written_keys: tuple[str, ...] = (),
    ) -> None:
        super().__init__(message)
        self.rolled_back = rolled_back
        self.written_keys = written_keys


@dataclass(frozen=True)
class ApplyResult:
    """Outcome of one guarded apply."""

    applied: bool
    written_keys: tuple[str, ...]
    overrides_before: str
    overrides_after: str


def record_digest(record: Mapping[str, Any]) -> str:
    """Return the sha256 of the canonical JSON encoding for audit digests."""
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class SelectionApplier:
    """Write fallback chains first, roles second, and restore originals on failure.

    The whole merged record is written for each managed key, so unmanaged keys
    survive. `task.agentModelOverrides` is read before and after the writes and
    never written; any disturbance fails the apply.
    """

    def __init__(self, client: OmpConfigClient) -> None:
        self.client = client

    def apply(
        self, model_roles: Mapping[str, Any], fallback_chains: Mapping[str, Any]
    ) -> ApplyResult:
        overrides_before = self.client.get(OVERRIDES_KEY)
        roles_before = self.client.get(MANAGED_ROLE_KEY)
        chains_before = self.client.get(MANAGED_CHAIN_KEY)
        target_roles = dict(model_roles)
        target_chains = {role: list(chain) for role, chain in fallback_chains.items()}
        overrides_digest = record_digest(overrides_before)

        writes: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
        if target_chains != chains_before:
            writes.append((MANAGED_CHAIN_KEY, target_chains, chains_before))
        if target_roles != roles_before:
            writes.append((MANAGED_ROLE_KEY, target_roles, roles_before))
        written_keys = tuple(key for key, _target, _original in writes)
        if not writes:
            return ApplyResult(False, (), overrides_digest, overrides_digest)

        try:
            for key, target, _original in writes:
                self.client.set(key, target)
            for key, target, _original in writes:
                if self.client.get(key) != target:
                    raise ApplyError(f"readback of {key} did not match the written record")
            overrides_after = record_digest(self.client.get(OVERRIDES_KEY))
            if overrides_after != overrides_digest:
                raise ApplyError(f"{OVERRIDES_KEY} changed during apply")
        except (ApplyError, OmpConfigError) as exc:
            try:
                self._rollback(writes)
            except ApplyError as rollback_error:
                raise ApplyError(
                    f"apply failed; {rollback_error}", written_keys=written_keys
                ) from exc
            raise ApplyError(
                f"apply failed and rolled back: {exc}",
                rolled_back=True,
                written_keys=written_keys,
            ) from exc
        return ApplyResult(True, written_keys, overrides_digest, overrides_after)

    def _rollback(self, writes: list[tuple[str, dict[str, Any], dict[str, Any]]]) -> None:
        failures: list[str] = []
        for key, _target, original in reversed(writes):
            try:
                self.client.set(key, original)
                if self.client.get(key) != original:
                    failures.append(key)
            except OmpConfigError as exc:
                failures.append(f"{key}: {exc}")
        if failures:
            raise ApplyError(f"rollback failed for: {', '.join(failures)}")
