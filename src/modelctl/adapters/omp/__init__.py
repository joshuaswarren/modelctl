"""Guarded OMP native selection adapter public API."""

from .apply import ApplyError, ApplyResult, SelectionApplier, record_digest
from .cli import main
from .native import (
    MANAGED_CHAIN_KEY,
    MANAGED_ROLE_KEY,
    OVERRIDES_KEY,
    OmpConfigClient,
    OmpConfigError,
)
from .receipt import JsonlReceiptSink

__all__ = [
    "MANAGED_CHAIN_KEY",
    "MANAGED_ROLE_KEY",
    "OVERRIDES_KEY",
    "ApplyError",
    "ApplyResult",
    "JsonlReceiptSink",
    "OmpConfigClient",
    "OmpConfigError",
    "SelectionApplier",
    "main",
    "record_digest",
]
