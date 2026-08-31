"""Fenced controller promotion contracts."""
from __future__ import annotations

from collections.abc import Callable
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field


class FencingReceipt(BaseModel):
    """External fencing proof supplied by the promotion caller."""

    model_config = ConfigDict(extra="allow")

    epoch: int = Field(ge=0)
    token: str | None = Field(default=None, min_length=1)


class FencingVerifier(Protocol):
    """Verifier for an externally issued fencing receipt."""

    def verify(self, receipt: FencingReceipt) -> bool: ...


def verify_fencing(
    verifier: FencingVerifier | Callable[[FencingReceipt], bool] | None,
    receipt: FencingReceipt,
) -> bool:
    """Verify the receipt with the injected verifier."""

    if verifier is None:
        return False
    if callable(verifier):
        return bool(verifier(receipt))
    return bool(verifier.verify(receipt))
