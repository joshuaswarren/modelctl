"""Read-only llama.cpp telemetry collection."""
from __future__ import annotations

from collections.abc import Mapping

from modelctl.agents.host.common import (
    CollectorError,
    endpoint_url,
    finish_observation,
    health,
    metric,
    number,
    read_object,
    text,
)
from modelctl.agents.host.report import Clock, EngineObservation, SystemClock
from modelctl.agents.host.transport import HttpTransport, UrllibTransport


class LlamaCppCollector:
    """Collect health, model, slot, queue, and latency state from llama.cpp."""

    def __init__(
        self,
        engine_id: str,
        base_url: str,
        aliases: list[str],
        transport: HttpTransport | None = None,
        *,
        clock: Clock | None = None,
    ) -> None:
        self.engine_id = engine_id
        self.base_url = base_url
        self.aliases = list(aliases)
        self.endpoint = endpoint_url(base_url, "/health")
        self.transport = transport or UrllibTransport()
        self.clock = clock or SystemClock()

    def collect(self) -> EngineObservation:
        started = self.clock.monotonic()
        health_url = endpoint_url(self.base_url, "/health")
        props_url = endpoint_url(self.base_url, "/props")
        slots_url = endpoint_url(self.base_url, "/slots")
        health_data = read_object(self.transport, health_url)
        props = read_object(self.transport, props_url)
        try:
            slots_response = self.transport.get(slots_url)
        except Exception as exc:
            raise CollectorError(slots_url, f"GET failed: {exc}") from exc
        if slots_response.status_code < 200 or slots_response.status_code >= 300:
            raise CollectorError(slots_url, f"GET returned HTTP {slots_response.status_code}")
        if not isinstance(slots_response.body, list):
            raise CollectorError(slots_url, "GET returned a non-array JSON value")
        slots = [dict(item) for item in slots_response.body if isinstance(item, Mapping)]
        in_flight = sum(1 for slot in slots if slot.get("is_processing") is True)
        queue_depth = 0
        model_name = text(metric(props, "model", "modelPath", "model_path", "id"))
        latency_samples = [
            value
            for value in (
                number(metric(health_data, "shortRequestLatencyMs", "short_request_latency_ms", "latencyMs")),
                number(metric(props, "shortRequestLatencyMs", "short_request_latency_ms", "latencyMs")),
                *(number(metric(slot, "shortRequestLatencyMs", "short_request_latency_ms", "latencyMs")) for slot in slots),
            )
            if value is not None
        ]
        return finish_observation(
            clock=self.clock,
            started=started,
            engine_id=self.engine_id,
            base_url=self.base_url,
            aliases=self.aliases,
            resident_models=[model_name] if model_name is not None else [],
            in_flight=in_flight,
            queue_depth=queue_depth,
            engine_health=health(metric(health_data, "health", "status"), successful_request=True),
            latency_samples=latency_samples,
        )


__all__ = ["LlamaCppCollector"]
