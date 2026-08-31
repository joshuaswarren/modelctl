"""Shared parsing and timing helpers for provider collectors."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from modelctl.agents.host.report import Clock, EngineObservation
from modelctl.agents.host.transport import HttpTransport
from modelctl.domain.engine import EngineHealth


class CollectorError(RuntimeError):
    """A collector could not produce a complete observation."""

    def __init__(self, endpoint: str, message: str) -> None:
        super().__init__(message)
        self.endpoint = endpoint


def endpoint_url(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}/{path.lstrip('/')}"


def read_object(transport: HttpTransport, url: str) -> dict[str, Any]:
    try:
        response = transport.get(url)
    except Exception as exc:
        raise CollectorError(url, f"GET failed: {exc}") from exc
    if response.status_code < 200 or response.status_code >= 300:
        raise CollectorError(url, f"GET returned HTTP {response.status_code}")
    if not isinstance(response.body, Mapping):
        raise CollectorError(url, "GET returned a non-object JSON value")
    return dict(response.body)


def integer(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, float) and value.is_integer() and value >= 0:
        return int(value)
    return default


def number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)) and value >= 0:
        return float(value)
    return None


def text(value: Any) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def health(value: Any, *, successful_request: bool = False) -> EngineHealth:
    status = value.lower() if isinstance(value, str) else ""
    if status in {"ok", "healthy", "ready", "running", "available"}:
        return EngineHealth.HEALTHY
    if status in {"degraded", "loading", "starting", "busy"}:
        return EngineHealth.DEGRADED
    if status in {"error", "failed", "unhealthy", "offline"}:
        return EngineHealth.UNHEALTHY
    return EngineHealth.HEALTHY if successful_request else EngineHealth.UNKNOWN


def metric(data: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in data:
            return data[name]
    return None


def finish_observation(
    *,
    clock: Clock,
    started: float,
    engine_id: str,
    base_url: str,
    aliases: list[str],
    resident_models: list[str],
    in_flight: int,
    queue_depth: int,
    engine_health: EngineHealth,
    latency_samples: list[float],
) -> EngineObservation:
    elapsed = max(0.0, (clock.monotonic() - started) * 1000)
    return EngineObservation(
        engine_id=engine_id,
        base_url=base_url,
        aliases=aliases,
        resident_models=sorted(set(resident_models)),
        in_flight=in_flight,
        queue_depth=queue_depth,
        health=engine_health,
        collection_time_ms=elapsed,
        short_request_latency_ms=latency_samples[0] if latency_samples else None,
        short_request_latency_samples_ms=latency_samples,
    )
