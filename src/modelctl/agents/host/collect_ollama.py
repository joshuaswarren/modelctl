"""Read-only Ollama telemetry collection."""
from __future__ import annotations

from collections.abc import Mapping

from modelctl.agents.host.common import (
    CollectorError,
    endpoint_url,
    finish_observation,
    health,
    integer,
    metric,
    number,
    read_object,
    text,
)
from modelctl.agents.host.report import Clock, EngineObservation, SystemClock
from modelctl.agents.host.transport import HttpTransport, UrllibTransport


class OllamaCollector:
    """Collect resident models and queue metrics from Ollama `/api/ps`."""

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
        self.endpoint = endpoint_url(base_url, "/api/ps")
        self.transport = transport or UrllibTransport()
        self.clock = clock or SystemClock()

    def collect(self) -> EngineObservation:
        started = self.clock.monotonic()
        data = read_object(self.transport, self.endpoint)
        raw_models = data.get("models")
        if not isinstance(raw_models, list):
            raise CollectorError(self.endpoint, "Ollama response must contain a models list")
        models = [dict(item) for item in raw_models if isinstance(item, Mapping)]
        resident_models = [
            model_name
            for model in models
            if (model_name := text(metric(model, "name", "model", "id"))) is not None
        ]
        in_flight = integer(metric(data, "inFlight", "in_flight", "activeSlots", "active_slots"))
        if in_flight == 0:
            in_flight = sum(integer(metric(model, "inFlight", "in_flight", "activeSlots")) for model in models)
        queue_depth = integer(metric(data, "queueDepth", "queue_depth"))
        if queue_depth == 0:
            queue_depth = sum(integer(metric(model, "queueDepth", "queue_depth")) for model in models)
        latency_samples = [
            value
            for value in (
                number(metric(data, "shortRequestLatencyMs", "short_request_latency_ms", "latencyMs")),
                *(number(metric(model, "shortRequestLatencyMs", "short_request_latency_ms", "latencyMs")) for model in models),
            )
            if value is not None
        ]
        return finish_observation(
            clock=self.clock,
            started=started,
            engine_id=self.engine_id,
            base_url=self.base_url,
            aliases=self.aliases,
            resident_models=resident_models,
            in_flight=in_flight,
            queue_depth=queue_depth,
            engine_health=health(metric(data, "health", "status"), successful_request=True),
            latency_samples=latency_samples,
        )


__all__ = ["OllamaCollector"]
