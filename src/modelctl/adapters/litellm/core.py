"""Deterministic LiteLLM managed-region rendering."""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from difflib import unified_diff
from typing import Any

from modelctl.domain.engine import EngineHealth, EngineState, PhysicalEngine
from modelctl.domain.policy import PolicyBundle

BEGIN_MARKER = "# BEGIN modelctl managed"
END_MARKER = "# END modelctl managed"

Distribution = dict[str, dict[str, int]]


@dataclass(frozen=True)
class LiteLLMRoute:
    """One automatic or manual LiteLLM alias route."""

    alias: str
    engine_id: str
    model: str
    weight: int = 1
    manual: bool = False
    interactive: bool = False

    def __post_init__(self) -> None:
        if not self.alias.strip() or not self.engine_id.strip() or not self.model.strip():
            raise ValueError("LiteLLM routes require nonempty alias, engine_id, and model")
        if self.weight < 1:
            raise ValueError("LiteLLM route weight must be positive")

    @classmethod
    def from_value(cls, value: LiteLLMRoute | Mapping[str, object]) -> LiteLLMRoute:
        if isinstance(value, cls):
            return value
        if not isinstance(value, Mapping):
            raise TypeError("LiteLLM route must be an object")
        alias = _required_text(value, "alias")
        engine_id = _required_text(value, "engine_id", "engineId")
        model = _required_text(value, "model")
        weight = value.get("weight", 1)
        if not isinstance(weight, int) or isinstance(weight, bool):
            raise TypeError("LiteLLM route weight must be an integer")
        manual = value.get("manual", False)
        if not isinstance(manual, bool):
            raise TypeError("LiteLLM route manual must be a boolean")
        interactive = value.get("interactive", False)
        if not isinstance(interactive, bool):
            raise TypeError("LiteLLM route interactive must be a boolean")
        return cls(alias, engine_id, model, weight=weight, manual=manual, interactive=interactive)


def render_config(
    source: str | bytes,
    policy: PolicyBundle,
    *,
    routes: Sequence[LiteLLMRoute | Mapping[str, object]] | None = None,
) -> str | bytes:
    """Replace the exact managed region and preserve every other byte."""
    source_bytes = source.encode() if isinstance(source, str) else source
    begin, end = _marker_lines(source_bytes)
    managed = render_managed_region(policy, routes=routes).encode()
    output = source_bytes[: begin[1]] + managed + source_bytes[end[0] :]
    if isinstance(source, str):
        return output.decode("utf-8")
    return output


def render_managed_region(
    policy: PolicyBundle,
    *,
    routes: Sequence[LiteLLMRoute | Mapping[str, object]] | None = None,
) -> str:
    """Render deterministic LiteLLM list entries without marker lines."""
    engine_by_id = _engines_by_id(policy.engines)
    normalized_routes = _routes(policy, routes)
    by_engine: dict[str, list[LiteLLMRoute]] = {}
    for route in normalized_routes:
        if route.manual:
            continue
        if route.engine_id not in engine_by_id:
            raise ValueError(f"route references unknown engine: {route.engine_id}")
        by_engine.setdefault(route.engine_id, []).append(route)

    entries: list[tuple[str, str, str]] = []
    for engine_id in sorted(by_engine):
        engine = engine_by_id[engine_id]
        if not _eligible(engine):
            continue
        engine_routes = sorted(by_engine[engine_id], key=lambda route: (route.alias, route.model))
        allocations = _engine_distribution(engine, engine_routes)
        for route in engine_routes:
            slots = allocations[route.alias]
            if slots == 0:
                continue
            entries.append((engine_id, route.alias, _render_entry(route, slots, engine)))

    return "\n".join(entry for _, _, entry in entries) + ("\n" if entries else "")


def render_receipt(
    source: str | bytes,
    policy: PolicyBundle,
    *,
    routes: Sequence[LiteLLMRoute | Mapping[str, object]] | None = None,
) -> RenderReceipt:
    """Return the rendered bytes, distribution, and deterministic diff."""
    source_bytes = source.encode() if isinstance(source, str) else source
    rendered_value = render_config(source_bytes, policy, routes=routes)
    if not isinstance(rendered_value, bytes):
        raise TypeError("byte rendering returned non-byte content")
    return RenderReceipt(
        original_digest=_digest(source_bytes),
        rendered_digest=_digest(rendered_value),
        rendered=rendered_value,
        distributions=calculate_distribution(policy, routes=routes),
        diff=_diff(source_bytes, rendered_value),
    )


def calculate_distribution(
    policy: PolicyBundle,
    *,
    routes: Sequence[LiteLLMRoute | Mapping[str, object]] | None = None,
) -> Distribution:
    """Calculate each physical engine's alias capacities exactly once."""
    engine_by_id = _engines_by_id(policy.engines)
    by_engine: dict[str, list[LiteLLMRoute]] = {}
    for route in _routes(policy, routes):
        if route.manual:
            continue
        if route.engine_id not in engine_by_id:
            raise ValueError(f"route references unknown engine: {route.engine_id}")
        by_engine.setdefault(route.engine_id, []).append(route)

    distributions: Distribution = {}
    for engine_id in sorted(by_engine):
        engine = engine_by_id[engine_id]
        if not _eligible(engine):
            continue
        engine_routes = sorted(by_engine[engine_id], key=lambda route: route.alias)
        distributions[engine_id] = _engine_distribution(engine, engine_routes)
    return distributions


@dataclass(frozen=True)
class RenderReceipt:
    original_digest: str
    rendered_digest: str
    rendered: bytes
    distributions: Distribution
    diff: str

    def as_dict(self) -> dict[str, object]:
        return {
            "originalDigest": self.original_digest,
            "renderedDigest": self.rendered_digest,
            "distributions": self.distributions,
            "diff": self.diff,
        }


def bundle_id(
    policy: PolicyBundle,
    routes: Sequence[LiteLLMRoute | Mapping[str, object]] | None = None,
) -> str:
    """Hash canonical policy and route inputs for receipts and backups."""
    route_values = [asdict(route) for route in _routes(policy, routes)]
    route_values.sort(key=lambda value: (value["engine_id"], value["alias"], value["model"]))
    payload = {"policy": policy.model_dump(mode="json", by_alias=True), "routes": route_values}
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


def _routes(
    policy: PolicyBundle,
    routes: Sequence[LiteLLMRoute | Mapping[str, object]] | None,
) -> list[LiteLLMRoute]:
    if routes is not None:
        result = [LiteLLMRoute.from_value(route) for route in routes]
    else:
        result = _routes_from_policy(policy.routes, policy.engines)
    manual_aliases = _manual_aliases(policy.routes)
    return [
        LiteLLMRoute(
            route.alias,
            route.engine_id,
            route.model,
            route.weight,
            route.manual or route.alias in manual_aliases,
            route.interactive,
        )
        for route in result
    ]


def _routes_from_policy(routes: Mapping[str, Any], engines: Sequence[PhysicalEngine]) -> list[LiteLLMRoute]:
    aliases = routes.get("aliases", {})
    result: list[LiteLLMRoute] = []
    if aliases:
        if not isinstance(aliases, Mapping):
            raise TypeError("policy.routes.aliases must be an object")
        for alias in sorted(aliases):
            spec = aliases[alias]
            if isinstance(spec, str):
                result.append(LiteLLMRoute(alias, spec, alias))
                continue
            if not isinstance(spec, Mapping):
                raise TypeError(f"policy route {alias} must be an object or engine id")
            value = dict(spec)
            value.setdefault("alias", alias)
            result.append(LiteLLMRoute.from_value(value))
        return result
    for engine in engines:
        model = engine.resident_models[0] if engine.resident_models else ""
        if not model:
            raise ValueError(f"engine has no resident model: {engine.id}")
        result.extend(LiteLLMRoute(alias, engine.id or engine.host, model) for alias in sorted(engine.aliases))
    return result


def _manual_aliases(routes: Mapping[str, Any]) -> set[str]:
    value = routes.get("manualAliases", routes.get("manual_aliases", []))
    if not isinstance(value, list) or not all(isinstance(alias, str) and alias.strip() for alias in value):
        raise TypeError("policy.routes.manualAliases must be a list of nonempty strings")
    return set(value)


def _engines_by_id(engines: Sequence[PhysicalEngine]) -> dict[str, PhysicalEngine]:
    result: dict[str, PhysicalEngine] = {}
    for engine in engines:
        engine_id = engine.id or engine.host
        if engine_id in result:
            raise ValueError(f"duplicate physical engine: {engine_id}")
        result[engine_id] = engine
    return result


def _eligible(engine: PhysicalEngine) -> bool:
    return engine.state is EngineState.ACTIVE and engine.health in {
        EngineHealth.HEALTHY,
        EngineHealth.DEGRADED,
    }


def _engine_distribution(engine: PhysicalEngine, routes: Sequence[LiteLLMRoute]) -> dict[str, int]:
    unique_routes = _unique_aliases(routes)
    interactive = [route for route in unique_routes if route.interactive]
    serving = [route for route in unique_routes if not route.interactive]
    interactive_capacity = min(engine.available_slots, engine.reserved_interactive_slots)
    serving_capacity = engine.available_slots - interactive_capacity
    return {
        **_weighted_split(interactive_capacity, interactive),
        **_weighted_split(serving_capacity, serving),
    }


def _unique_aliases(routes: Sequence[LiteLLMRoute]) -> list[LiteLLMRoute]:
    seen: set[str] = set()
    result: list[LiteLLMRoute] = []
    for route in routes:
        if route.alias in seen:
            raise ValueError(f"duplicate alias on physical engine: {route.alias}")
        seen.add(route.alias)
        result.append(route)
    return result


def _weighted_split(capacity: int, routes: Sequence[LiteLLMRoute]) -> dict[str, int]:
    if capacity < 0:
        raise ValueError("engine capacity must not be negative")
    total_weight = sum(route.weight for route in routes)
    if total_weight == 0:
        return {}
    base = {route.alias: capacity * route.weight // total_weight for route in routes}
    remainder = capacity - sum(base.values())
    ranked = sorted(
        routes,
        key=lambda route: (-((capacity * route.weight) % total_weight), route.alias),
    )
    for route in ranked[:remainder]:
        base[route.alias] += 1
    return base


def _render_entry(route: LiteLLMRoute, slots: int, engine: PhysicalEngine) -> str:
    if engine.base_url is None:
        raise ValueError(f"engine has no baseUrl: {engine.id}")
    alias = json.dumps(route.alias, ensure_ascii=False)
    model = json.dumps(route.model, ensure_ascii=False)
    api_base = json.dumps(engine.base_url, ensure_ascii=False)
    model_id = json.dumps(f"{engine.id}:{route.alias}", ensure_ascii=False)
    return (
        f"- model_name: {alias}\n"
        "  litellm_params:\n"
        f"    api_base: {api_base}\n"
        f"    max_parallel_requests: {slots}\n"
        f"    model: {model}\n"
        f"    weight: {route.weight}\n"
        "  model_info:\n"
        f"    id: {model_id}"
    )


def _required_text(value: Mapping[str, object], *names: str) -> str:
    for name in names:
        candidate = value.get(name)
        if isinstance(candidate, str) and candidate.strip():
            return candidate
    raise ValueError(f"LiteLLM route requires {names[0]}")


def _marker_lines(source: bytes) -> tuple[tuple[int, int], tuple[int, int]]:
    begin_marker = BEGIN_MARKER.encode()
    end_marker = END_MARKER.encode()
    if source.count(begin_marker) != 1 or source.count(end_marker) != 1:
        raise ValueError("config must contain exactly one BEGIN and END modelctl managed marker")
    lines = source.splitlines(keepends=True)
    spans: list[tuple[bytes, int, int]] = []
    offset = 0
    for line in lines:
        spans.append((line, offset, offset + len(line)))
        offset += len(line)
    begin = next((span for span in spans if _marker_line(span[0], begin_marker)), None)
    end = next((span for span in spans if _marker_line(span[0], end_marker)), None)
    if begin is None or end is None or begin[1] >= end[1]:
        raise ValueError("config has malformed modelctl managed markers")
    return (begin[1], begin[2]), (end[1], end[2])


def _marker_line(line: bytes, marker: bytes) -> bool:
    return line.rstrip(b"\r\n") == marker


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _diff(original: bytes, rendered: bytes) -> str:
    before = original.decode("utf-8").splitlines(keepends=True)
    after = rendered.decode("utf-8").splitlines(keepends=True)
    return "".join(unified_diff(before, after, fromfile="original", tofile="rendered", lineterm="\n"))
