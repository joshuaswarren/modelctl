"""Production route table backed by the guarded LiteLLM adapter."""
from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from modelctl.adapters.litellm.apply import (
    ApplyReceipt,
    ConfigStore,
    LockProvider,
    ReceiptSink,
    RuntimeController,
    SmokeVerifier,
)
from modelctl.adapters.litellm.apply import (
    apply as apply_litellm,
)
from modelctl.adapters.litellm.core import LiteLLMRoute
from modelctl.domain.policy import PolicyBundle


@dataclass(frozen=True)
class LiteLLMRouteTarget:
    """Complete policy and optional LiteLLM route for one route identifier."""

    policy: PolicyBundle
    route: LiteLLMRoute | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.policy, PolicyBundle):
            raise TypeError("route target policy must be a PolicyBundle")
        if self.route is not None and not isinstance(self.route, LiteLLMRoute):
            raise TypeError("route target route must be a LiteLLMRoute")


class LiteLLMRouteTable:
    """Apply route changes through the guarded LiteLLM adapter."""

    def __init__(
        self,
        current_route: str,
        routes: Mapping[str, LiteLLMRouteTarget],
        *,
        config_path: Path,
        expected_config_digest: str,
        store: ConfigStore,
        lock: LockProvider,
        runtime: RuntimeController,
        smoke: SmokeVerifier,
        receipts: ReceiptSink,
        now: Callable[[], datetime],
    ) -> None:
        if not current_route.strip():
            raise ValueError("current route is required")
        if not expected_config_digest:
            raise ValueError("expected_config_digest is required")
        for route_id, target in routes.items():
            if not isinstance(route_id, str) or not route_id.strip():
                raise ValueError("route identifiers must be nonempty strings")
            if not isinstance(target, LiteLLMRouteTarget):
                raise TypeError("route map values must be LiteLLMRouteTarget instances")
        if current_route not in routes:
            raise ValueError(f"route is not configured: {current_route}")

        self.current_route = current_route
        self.history: list[str] = []
        self.last_receipt: ApplyReceipt | None = None
        self._routes = dict(routes)
        self._config_path = config_path
        self._expected_config_digest = expected_config_digest
        self._store = store
        self._lock = lock
        self._runtime = runtime
        self._smoke = smoke
        self._receipts = receipts
        self._now = now

    @property
    def expected_config_digest(self) -> str:
        """Digest required by the next guarded apply."""

        return self._expected_config_digest

    def activate(self, route: str) -> None:
        """Apply a configured candidate and make it current after success."""

        target = self._target(route)
        receipt = self._apply(target)
        self.history.append(self.current_route)
        self.current_route = route
        self._record_success(receipt)

    def rollback(self, route: str) -> None:
        """Apply a configured rollback target and make it current after success."""

        target = self._target(route)
        receipt = self._apply(target)
        self.current_route = route
        self._record_success(receipt)

    def _target(self, route: str) -> LiteLLMRouteTarget:
        if not route.strip():
            raise ValueError("route is required")
        if route not in self._routes:
            raise ValueError(f"route is not configured: {route}")
        return self._routes[route]

    def _apply(self, target: LiteLLMRouteTarget) -> ApplyReceipt:
        route_values: Sequence[LiteLLMRoute] | None = None
        if target.route is not None:
            route_values = [target.route]
        return apply_litellm(
            self._config_path,
            target.policy,
            expected_original_digest=self._expected_config_digest,
            routes=route_values,
            store=self._store,
            lock=self._lock,
            runtime=self._runtime,
            smoke=self._smoke,
            receipts=self._receipts,
            now=self._now,
        )

    def _record_success(self, receipt: ApplyReceipt) -> None:
        self._expected_config_digest = receipt.rendered_digest
        self.last_receipt = receipt
