"""Allow-listed controller actions for operator tooling."""
from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


@dataclass(frozen=True)
class ActionSpec:
    """The controller endpoint and signing scope for one action kind."""

    kind: str
    endpoint: str
    scope: str


ACTION_SPECS: dict[str, ActionSpec] = {
    "policy": ActionSpec("policy", "/v1/policies", "policy:write"),
}

ALLOWED_ACTION_ENDPOINTS = frozenset(spec.endpoint for spec in ACTION_SPECS.values())


def action_spec(kind: str) -> ActionSpec:
    """Return the allow-listed action specification for a kind."""

    try:
        return ACTION_SPECS[kind]
    except KeyError as exc:
        raise ValueError(f"unsupported action kind: {kind}") from exc


def action_endpoint(kind: str, controller_url: str) -> str:
    """Build one allow-listed endpoint from a controller origin."""

    spec = action_spec(kind)
    parsed = urlsplit(controller_url)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("controller URL must be an HTTPS origin")
    return urlunsplit((parsed.scheme, parsed.netloc, spec.endpoint, "", ""))


def action_endpoint_allowed(endpoint: str) -> bool:
    """Check that a relative endpoint names an existing mutation."""

    parsed = urlsplit(endpoint)
    return (
        not parsed.scheme
        and not parsed.netloc
        and not parsed.query
        and not parsed.fragment
        and parsed.path in ALLOWED_ACTION_ENDPOINTS
    )
