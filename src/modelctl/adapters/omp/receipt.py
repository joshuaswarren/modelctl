"""Durable JSONL receipt sink for adapter runs."""
from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path


class JsonlReceiptSink:
    """Append durable JSON receipts with a flush and fsync."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def append(self, receipt: Mapping[str, object]) -> None:
        created = not self.path.exists()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        encoded = (
            json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
        ).encode()
        with self.path.open("ab") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if created:
            directory = os.open(self.path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
