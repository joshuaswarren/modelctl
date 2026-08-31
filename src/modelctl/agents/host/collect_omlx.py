"""Read-only oMLX telemetry collection."""
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


class OmlxCollector:
    """Collect health and served model state from oMLX."""

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
        models_url = endpoint_url(self.base_url, "/v1/models")
        health_data = read_object(self.transport, health_url)
        models_data = read_object(self.transport, models_url)
        raw_models = models_data.get("data", models_data.get("models", []))
        if not isinstance(raw_models, list):
            raise CollectorError(models_url, "oMLX response must contain a model list")
        models = [dict(item) for item in raw_models if isinstance(item, Mapping)]
        resident_models = [
            model_name
            for model in models
            if (model_name := text(metric(model, "id", "name", "model"))) is not None
        ]
        in_flight = integer(metric(health_data, "inFlight", "in_flight", "activeSlots", "active_slots"))
        queue_depth = integer(metric(health_data, "queueDepth", "queue_depth"))
        latency_samples = [
            value
            for value in (
                number(metric(health_data, "shortRequestLatencyMs", "short_request_latency_ms", "latencyMs")),
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
            engine_health=health(metric(health_data, "health", "status"), successful_request=True),
            latency_samples=latency_samples,
        )


__all__ = ["OmlxCollector"]
