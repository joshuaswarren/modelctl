"""Guarded, rollback-safe LiteLLM configuration application."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import AbstractContextManager, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from modelctl.domain.policy import PolicyBundle

from .core import Distribution, LiteLLMRoute, bundle_id, render_receipt

_OPERATION_ERRORS = (OSError, RuntimeError, TypeError, ValueError, subprocess.SubprocessError)


class ConfigStore(Protocol):
    """File operations needed by the guarded apply transaction."""

    def read(self, path: Path) -> bytes: ...

    def backup(self, source: Path, destination: Path) -> None: ...

    def atomic_write(self, path: Path, content: bytes) -> None: ...

    def restore(self, source: Path, backup: Path) -> None: ...


class LockProvider(Protocol):
    """Exclusive lock acquisition for one config path."""

    def acquire(self, path: Path) -> AbstractContextManager[None]: ...


class RuntimeController(Protocol):
    """Runtime update and optional restart decision."""

    def update(self, config_path: Path, bundle_id: str) -> RuntimeDecision: ...

    def restart_service(self) -> None: ...


class SmokeVerifier(Protocol):
    """Verify the distribution that the renderer compiled."""

    def verify(self, distributions: Mapping[str, Mapping[str, int]]) -> None: ...


class ReceiptSink(Protocol):
    """Durable apply and event receipt sink."""

    def append(self, receipt: Mapping[str, object]) -> None: ...


class ApplyError(RuntimeError):
    """The guarded apply failed or rolled back."""


class RuntimeDecision:
    """Decision returned by the injected runtime updater."""

    def __init__(self, *, restart: bool) -> None:
        self.restart = restart


class SubprocessRuntimeController:
    """Reload LiteLLM through an exact restart command."""

    def __init__(self, restart_command: Sequence[str]) -> None:
        self.restart_command = _command(restart_command)

    def update(self, config_path: Path, bundle_id: str) -> RuntimeDecision:
        return RuntimeDecision(restart=True)

    def restart_service(self) -> None:
        subprocess.run(self.restart_command, check=True)


class SubprocessSmokeVerifier:
    """Run a smoke command with the expected distribution in its environment."""

    def __init__(self, command: Sequence[str]) -> None:
        self.command = _command(command)

    def verify(self, distributions: Mapping[str, Mapping[str, int]]) -> None:
        environment = os.environ.copy()
        environment["MODELCTL_EXPECTED_DISTRIBUTION"] = json.dumps(
            distributions,
            sort_keys=True,
            separators=(",", ":"),
        )
        subprocess.run(self.command, check=True, env=environment)


class FileConfigStore:
    """Concrete local filesystem implementation for production use."""

    def read(self, path: Path) -> bytes:
        return path.read_bytes()

    def backup(self, source: Path, destination: Path) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    def atomic_write(self, path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        original = path.stat()
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(descriptor, original.st_mode & 0o7777)
            if original.st_uid != os.geteuid() or original.st_gid != os.getegid():
                os.fchown(descriptor, original.st_uid, original.st_gid)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        finally:
            temporary_path.unlink(missing_ok=True)

    def restore(self, source: Path, backup: Path) -> None:
        self.atomic_write(source, backup.read_bytes())


class FileLockProvider:
    """Concrete POSIX advisory lock provider."""

    def acquire(self, path: Path) -> AbstractContextManager[None]:
        return _file_lock(path)


@contextmanager
def _file_lock(path: Path) -> Iterator[None]:
    import fcntl

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+b") as handle:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        try:
            yield None
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class JsonlReceiptSink:
    """Append durable JSON receipts with a flush and fsync."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, receipt: Mapping[str, object]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        encoded = (
            json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
        ).encode()
        with self.path.open("ab") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())


class ApplyReceipt:
    """Result of a dry-run or completed guarded apply."""

    def __init__(
        self,
        *,
        dry_run: bool,
        bundle_id: str,
        original_digest: str,
        rendered_digest: str,
        distributions: Distribution,
        diff: str,
        backup_path: Path | None,
        restart_performed: bool,
    ) -> None:
        self.dry_run = dry_run
        self.bundle_id = bundle_id
        self.original_digest = original_digest
        self.rendered_digest = rendered_digest
        self.distributions = distributions
        self.diff = diff
        self.backup_path = backup_path
        self.restart_performed = restart_performed

    def as_dict(self) -> dict[str, object]:
        return {
            "kind": "modelctl.litellm.apply",
            "dryRun": self.dry_run,
            "bundleId": self.bundle_id,
            "originalDigest": self.original_digest,
            "renderedDigest": self.rendered_digest,
            "distributions": self.distributions,
            "diff": self.diff,
            "backupPath": str(self.backup_path) if self.backup_path is not None else None,
            "restartPerformed": self.restart_performed,
        }


def apply(
    config_path: Path,
    policy: PolicyBundle,
    *,
    expected_original_digest: str,
    routes: Sequence[LiteLLMRoute | Mapping[str, object]] | None = None,
    dry_run: bool = False,
    store: ConfigStore | None = None,
    lock: LockProvider | None = None,
    runtime: RuntimeController | None = None,
    smoke: SmokeVerifier | None = None,
    receipts: ReceiptSink | None = None,
    now: Callable[[], datetime] | None = None,
) -> ApplyReceipt:
    """Apply one bundle with lock, CAS, backup, atomic write, and rollback."""
    if not expected_original_digest:
        raise ValueError("expected_original_digest is required")
    file_store = store or FileConfigStore()
    bundle = bundle_id(policy, routes)
    clock = now or (lambda: datetime.now(UTC))

    if dry_run:
        original = file_store.read(config_path)
        if _digest(original) != expected_original_digest:
            raise ApplyError("expected original digest does not match config")
        rendered = render_receipt(original, policy, routes=routes)
        return ApplyReceipt(
            dry_run=True,
            bundle_id=bundle,
            original_digest=rendered.original_digest,
            rendered_digest=rendered.rendered_digest,
            distributions=rendered.distributions,
            diff=rendered.diff,
            backup_path=None,
            restart_performed=False,
        )

    if runtime is None or smoke is None:
        raise ValueError("runtime and smoke are required for a non-dry apply")
    lock_provider = lock or FileLockProvider()
    receipt_sink = receipts or JsonlReceiptSink(
        config_path.with_name(f"{config_path.name}.modelctl-events.jsonl")
    )
    lock_path = config_path.with_name(f"{config_path.name}.lock")
    date = clock().astimezone(UTC).date().isoformat()
    backup = config_path.with_name(f"{config_path.name}.modelctl-{date}-{bundle}.bak")

    with lock_provider.acquire(lock_path):
        original = file_store.read(config_path)
        if _digest(original) != expected_original_digest:
            raise ApplyError("expected original digest does not match config")
        rendered = render_receipt(original, policy, routes=routes)
        file_store.backup(config_path, backup)
        runtime_attempted = False
        try:
            file_store.atomic_write(config_path, rendered.rendered)
            runtime_attempted = True
            decision = runtime.update(config_path, bundle)
            if decision.restart:
                runtime.restart_service()
            smoke.verify(rendered.distributions)
            result = ApplyReceipt(
                dry_run=False,
                bundle_id=bundle,
                original_digest=rendered.original_digest,
                rendered_digest=rendered.rendered_digest,
                distributions=rendered.distributions,
                diff=rendered.diff,
                backup_path=backup,
                restart_performed=decision.restart,
            )
            receipt_sink.append(result.as_dict())
            return result
        except Exception as exc:
            rollback_errors: list[str] = []
            restored = False
            try:
                file_store.restore(config_path, backup)
                restored = True
            except _OPERATION_ERRORS as restore_error:
                rollback_errors.append(f"config restore failed: {restore_error}")
            if restored and runtime_attempted:
                try:
                    rollback_decision = runtime.update(config_path, rendered.original_digest)
                    if rollback_decision.restart:
                        runtime.restart_service()
                except _OPERATION_ERRORS as runtime_error:
                    rollback_errors.append(f"runtime restore failed: {runtime_error}")
            failure: dict[str, object] = {
                "kind": "modelctl.litellm.apply",
                "status": "rollback_failed" if rollback_errors else "rolled_back",
                "bundleId": bundle,
                "originalDigest": rendered.original_digest,
                "error": str(exc),
            }
            if rollback_errors:
                failure["rollbackErrors"] = rollback_errors
            receipt_error: Exception | None = None
            try:
                receipt_sink.append(failure)
            except _OPERATION_ERRORS as failed_receipt:
                receipt_error = failed_receipt
            if rollback_errors:
                detail = "; ".join(rollback_errors)
                if receipt_error is not None:
                    detail = f"{detail}; failure receipt failed: {receipt_error}"
                raise ApplyError(f"apply failed and rollback failed: {detail}") from exc
            detail = str(exc)
            if receipt_error is not None:
                detail = f"{detail}; failure receipt failed: {receipt_error}"
            raise ApplyError(f"apply failed and rolled back: {detail}") from exc


def _command(value: Sequence[str]) -> tuple[str, ...]:
    if isinstance(value, str) or not value or any(not item.strip() for item in value):
        raise ValueError("command must contain nonempty argument strings")
    return tuple(value)


def _digest(value: bytes) -> str:
    import hashlib

    return hashlib.sha256(value).hexdigest()
