"""Production and fixture host-agent commands."""
from __future__ import annotations

import argparse
import base64
import json
import stat
import sys
import tempfile
import time
from collections.abc import Mapping
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from modelctl.agents.host.collect_llamacpp import LlamaCppCollector
from modelctl.agents.host.collect_ollama import OllamaCollector
from modelctl.agents.host.collect_omlx import OmlxCollector
from modelctl.agents.host.common import endpoint_url
from modelctl.agents.host.report import (
    Clock,
    HostAgent,
    HostConfig,
    MaintenanceState,
    MaintenanceStateStore,
    SystemClock,
)
from modelctl.agents.host.transport import (
    HttpResponse,
    HttpTransport,
    UrllibTransport,
    build_mtls_context,
)
from modelctl.policy.signing import PolicySigner
from modelctl.policy.store import PublicKey
from modelctl.policy.verify import PolicyVerifier

_CONFIG_HELP = """Production YAML keys: hostId, signing.keyId, signing.privateKeyPath,
controllers, engines[{id, collector, baseUrl, aliases}], statePath, sequencePath,
eventsPath, timeoutSeconds, intervalSeconds, reportTtlSeconds, maintenanceState,
n1Impossible, and n1ImpossibleReason. Controllers may be base URLs or full
/v1/host-reports URLs. The private key must be an unencrypted Ed25519 PEM file.
"""


class FixtureTransport:
    """Serve only responses embedded in one synthetic fixture."""

    def __init__(self, responses: Mapping[str, Any]) -> None:
        self.responses = responses

    def get(self, url: str) -> HttpResponse:
        if url not in self.responses:
            raise OSError(f"fixture has no response for {url}")
        return HttpResponse(status_code=200, body=self.responses[url])

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> HttpResponse:
        raise OSError(f"fixture mode forbids controller POST: {url}")


def _collector(
    engine: Mapping[str, Any], transport: HttpTransport, clock: Clock
) -> OllamaCollector | LlamaCppCollector | OmlxCollector:
    engine_id = engine.get("id")
    base_url = engine.get("baseUrl")
    aliases = engine.get("aliases", [])
    collector_name = engine.get("collector")
    if not isinstance(engine_id, str) or not isinstance(base_url, str):
        raise TypeError("engine requires string id and baseUrl")
    if not isinstance(aliases, list) or not all(isinstance(alias, str) for alias in aliases):
        raise TypeError("engine aliases must be a list of strings")
    if collector_name == "ollama":
        return OllamaCollector(engine_id, base_url, aliases, transport, clock=clock)
    if collector_name in {"llamacpp", "llama.cpp"}:
        return LlamaCppCollector(engine_id, base_url, aliases, transport, clock=clock)
    if collector_name == "omlx":
        return OmlxCollector(engine_id, base_url, aliases, transport, clock=clock)
    raise ValueError(f"unsupported collector: {collector_name}")


def _load_fixture(path: Path) -> tuple[HostConfig, FixtureTransport]:
    value: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError("fixture must contain a JSON object")
    host_id = value.get("hostId")
    engines = value.get("engines")
    if not isinstance(host_id, str) or not isinstance(engines, list):
        raise TypeError("fixture requires hostId and engines")
    responses: dict[str, Any] = {}
    transport = FixtureTransport(responses)
    clock = SystemClock()
    collectors: list[OllamaCollector | LlamaCppCollector | OmlxCollector] = []
    for raw_engine in engines:
        if not isinstance(raw_engine, Mapping):
            raise TypeError("fixture engines must contain objects")
        raw_responses = raw_engine.get("responses", {})
        if not isinstance(raw_responses, Mapping):
            raise TypeError("fixture engine responses must be an object")
        base_url = raw_engine.get("baseUrl")
        if not isinstance(base_url, str):
            raise TypeError("fixture engine requires baseUrl")
        for path_name, response in raw_responses.items():
            if not isinstance(path_name, str):
                raise TypeError("fixture response paths must be strings")
            responses[endpoint_url(base_url, path_name)] = response
        collectors.append(_collector(raw_engine, transport, clock))
    state_value = value.get("state", MaintenanceState.ACTIVE.value)
    state = MaintenanceState(state_value)
    reason = value.get("n1ImpossibleReason")
    n1_impossible = value.get("n1Impossible", False)
    if not isinstance(n1_impossible, bool) or (reason is not None and not isinstance(reason, str)):
        raise TypeError("fixture N+1 fields have invalid types")
    return (
        HostConfig(
            host_id=host_id,
            engines=collectors,
            maintenance_state=state,
            n1_impossible=n1_impossible,
            n1_impossible_reason=reason,
        ),
        transport,
    )


def _public_key_text(public_key: PublicKey) -> str:
    if isinstance(public_key, bytes):
        raw = public_key
    else:
        raw = public_key.public_bytes_raw()
    return base64.b64encode(raw).decode("ascii")


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be an object")
    return value


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TypeError(f"{label} must be a nonempty string")
    return value


def _number(value: Any, label: str, default: float) -> float:
    result = default if value is None else value
    if isinstance(result, bool) or not isinstance(result, (int, float)) or result <= 0:
        raise ValueError(f"{label} must be positive")
    return float(result)


def _string_list(value: Any, label: str) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise TypeError(f"{label} must be a list of nonempty strings")
    return value


def _config_path(config_path: Path, value: Any, label: str) -> Path:
    candidate = Path(_text(value, label)).expanduser()
    return candidate if candidate.is_absolute() else config_path.parent / candidate


def _controller_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"controller URL is invalid: {value}")
    if parsed.path.rstrip("/") == "/v1/host-reports":
        return value.rstrip("/")
    return endpoint_url(value, "/v1/host-reports")


def _load_signer(config_path: Path, signing: Mapping[str, Any]) -> PolicySigner:
    key_id = _text(signing.get("keyId", signing.get("key_id")), "signing.keyId")
    key_path = _config_path(
        config_path,
        signing.get("privateKeyPath", signing.get("private_key_path")),
        "signing.privateKeyPath",
    )
    if stat.S_IMODE(key_path.stat().st_mode) & 0o077:
        raise ValueError(f"signing key permissions must be 0600 at {key_path}")
    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise ValueError(f"could not load signing key at {key_path}") from exc
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise TypeError("signing key must be an Ed25519 private key")
    return PolicySigner(key, key_id)



def _tls_context(config_path: Path, value: Any) -> Any:
    if value is None:
        return None
    tls = _mapping(value, "tls")
    if set(tls) != {"caPath", "clientCertPath", "clientKeyPath"}:
        raise ValueError("tls must contain only caPath, clientCertPath, and clientKeyPath")
    return build_mtls_context(
        _config_path(config_path, tls.get("caPath"), "tls.caPath"),
        _config_path(config_path, tls.get("clientCertPath"), "tls.clientCertPath"),
        _config_path(config_path, tls.get("clientKeyPath"), "tls.clientKeyPath"),
    )

def _load_production(path: Path) -> tuple[HostAgent, float]:
    try:
        value: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"could not load config at {path}") from exc
    root = _mapping(value, "config")
    host_id = _text(root.get("hostId", root.get("host_id")), "hostId")
    signing = _mapping(root.get("signing"), "signing")
    controllers = [_controller_url(item) for item in _string_list(root.get("controllers"), "controllers")]
    if not controllers:
        raise ValueError("controllers must not be empty")
    engine_values = root.get("engines")
    if not isinstance(engine_values, list) or not engine_values:
        raise ValueError("engines must not be empty")
    clock = SystemClock()
    transport = UrllibTransport(
        timeout=_number(root.get("timeoutSeconds"), "timeoutSeconds", 10.0),
        ssl_context=_tls_context(path, root.get("tls")),
    )
    collectors = [
        _collector(_mapping(item, "engine"), transport, clock)
        for item in engine_values
    ]
    state_value = root.get("maintenanceState", root.get("state", MaintenanceState.ACTIVE.value))
    try:
        state = MaintenanceState(_text(state_value, "maintenanceState"))
    except ValueError as exc:
        raise ValueError(f"unsupported maintenanceState: {state_value}") from exc
    reason = root.get("n1ImpossibleReason")
    n1_impossible = root.get("n1Impossible", False)
    if not isinstance(n1_impossible, bool) or (reason is not None and not isinstance(reason, str)):
        raise TypeError("N+1 fields have invalid types")
    config = HostConfig(
        host_id=host_id,
        engines=collectors,
        controllers=controllers,
        maintenance_state=state,
        n1_impossible=n1_impossible,
        n1_impossible_reason=reason,
    )
    state_path = _config_path(path, root.get("statePath", root.get("state_path", "state.json")), "statePath")
    state_store = MaintenanceStateStore(state_path, host_id=host_id)
    if not state_store.path.exists():
        state_store.set_state(state, clock.now())
    sequence_path = _config_path(
        path,
        root.get("sequencePath", root.get("sequence_path", "sequence.json")),
        "sequencePath",
    )
    events_path = _config_path(path, root.get("eventsPath", root.get("events_path", "events.jsonl")), "eventsPath")
    agent = HostAgent(
        config,
        signer=_load_signer(path, signing),
        state_store=state_store,
        sequence_path=sequence_path,
        events_path=events_path,
        transport=transport,
        clock=clock,
        report_ttl=timedelta(seconds=_number(root.get("reportTtlSeconds"), "reportTtlSeconds", 600.0)),
    )
    return agent, _number(root.get("intervalSeconds"), "intervalSeconds", 60.0)


def _run_production(path: Path, once: bool) -> int:
    agent, interval = _load_production(path)
    try:
        while True:
            envelope = agent.collect_envelope()
            controllers = agent.publish(envelope)
            if once:
                print(
                    json.dumps(
                        {"controllers": controllers, "sequence": envelope.sequence},
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
                return 0 if any(controllers.values()) else 3
            time.sleep(interval)
    except KeyboardInterrupt:
        return 0


def _run_fixture(path: Path) -> int:
    config, transport = _load_fixture(path)
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    signer = PolicySigner(private_key, "fixture-host-key")
    clock = SystemClock()
    with tempfile.TemporaryDirectory(prefix="modelctl-host-fixture-") as directory:
        agent = HostAgent(
            config,
            signer=signer,
            transport=transport,
            clock=clock,
            events_path=Path(directory) / "events.jsonl",
        )
        envelope = agent.collect_envelope()
    verifier = PolicyVerifier({"fixture-host-key": public_key}, now=clock.now)
    if not verifier.verify(envelope):
        raise RuntimeError("fixture envelope failed self-verification")
    output = {
        "envelope": json.loads(envelope.model_dump_json(by_alias=True, exclude_none=True)),
        "publicKey": _public_key_text(public_key),
    }
    print(json.dumps(output, sort_keys=True, separators=(",", ":")))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="modelctl-host-agent",
        description="Collect, sign, and publish host telemetry.",
        epilog=_CONFIG_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("command", nargs="?")
    parser.add_argument("--config", type=Path)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--once", action="store_true")
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "run":
            if arguments.fixture is not None or arguments.config is None:
                parser.error("run requires --config PATH and does not accept --fixture")
            return _run_production(arguments.config, arguments.once)
        if arguments.command is not None or arguments.config is not None or arguments.fixture is None or not arguments.once:
            parser.error("use 'run --config PATH [--once]' or '--fixture PATH --once'")
        return _run_fixture(arguments.fixture)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RuntimeError, TypeError, ValueError, yaml.YAMLError) as exc:
        print(f"host agent failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
