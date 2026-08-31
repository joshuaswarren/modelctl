"""Durable sequence allocation for signed operator actions."""
from __future__ import annotations

import fcntl
import json
import os
import tempfile
from pathlib import Path
from threading import Lock


class SequenceAllocator:
    """Allocate strictly increasing sequences with durable filesystem commits."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._thread_lock = Lock()

    def allocate(self) -> int:
        """Persist and return the next sequence before the caller sends data."""

        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_name(f".{self.path.name}.lock")
        with self._thread_lock, lock_path.open("a+") as lock_file:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            current = self._load()
            next_sequence = current + 1
            self._write(next_sequence)
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        return next_sequence

    def _load(self) -> int:
        if not self.path.exists():
            return 0
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("invalid operator sequence file") from exc
        if not isinstance(value, dict):
            raise TypeError("invalid operator sequence file")
        sequence = value.get("sequence")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 0:
            raise ValueError("invalid operator sequence value")
        return sequence

    def _write(self, sequence: int) -> None:
        encoded = json.dumps({"sequence": sequence}, separators=(",", ":")).encode("utf-8")
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{self.path.name}.", dir=self.path.parent)
        temporary_path = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, self.path)
            directory_descriptor = os.open(self.path.parent, os.O_DIRECTORY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except BaseException:
            temporary_path.unlink(missing_ok=True)
            raise
