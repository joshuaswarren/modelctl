"""Independent loop runners with per-loop circuit breakers."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from modelctl.controller.api import Controller


@dataclass
class CircuitBreaker:
    """Track failures for one loop without affecting other loops."""

    failure_limit: int = 1
    failures: int = 0
    open: bool = False

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.failure_limit:
            self.open = True

    def reset(self) -> None:
        self.failures = 0
        self.open = False


class LoopRunner:
    """Run one controller subsystem and contain its failures."""

    def __init__(
        self,
        name: str,
        controller: Controller,
        callback: Callable[[], Any],
        *,
        failure_limit: int = 1,
    ) -> None:
        if not name or failure_limit < 1:
            raise ValueError("loop name and failure limit are required")
        self.name = name
        self.controller = controller
        self.callback = callback
        self.breaker = CircuitBreaker(failure_limit=failure_limit)

    def run_once(self) -> Any:
        if self.breaker.open:
            return None
        try:
            result = self.callback()
        except Exception as exc:  # noqa: BLE001
            self.breaker.record_failure()
            self.controller.store.append_event(
                now=self.controller.now(),
                subsystem=self.name,
                severity="error",
                subject=self.name,
                detail={"error": type(exc).__name__, "message": str(exc)},
            )
            return None
        self.breaker.reset()
        return result
