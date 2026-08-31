from __future__ import annotations

import base64
import json
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Self

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from modelctl.agents.host.collect_llamacpp import LlamaCppCollector
from modelctl.agents.host.collect_ollama import OllamaCollector
from modelctl.agents.host.collect_omlx import OmlxCollector
from modelctl.agents.host.report import (
    HostAgent,
    HostConfig,
    HttpResponse,
    MaintenanceState,
    MaintenanceStateStore,
    SystemClock,
)
from modelctl.agents.host.transport import UrllibTransport, build_mtls_context
from modelctl.domain.engine import EngineHealth
from modelctl.domain.events import EventSeverity
from modelctl.policy.signing import PolicySigner
from modelctl.policy.verify import PolicyVerifier


class FakeTransport:
    def __init__(self, responses: dict[str, Any], failures: set[str] | None = None) -> None:
        self.responses = responses
        self.failures = failures or set()
        self.gets: list[str] = []
        self.posts: list[tuple[str, bytes]] = []

    def get(self, url: str) -> HttpResponse:
        self.gets.append(url)
        if url in self.failures:
            raise OSError(f"unavailable: {url}")
        return HttpResponse(status_code=200, body=self.responses[url])

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> HttpResponse:
        self.posts.append((url, body))
        if url in self.failures:
            raise OSError(f"unavailable: {url}")
        return HttpResponse(status_code=202, body={})


class FakeClock(SystemClock):
    def __init__(self) -> None:
        self.current = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)
        self.ticks = 0.0

    def now(self) -> datetime:
        return self.current

    def monotonic(self) -> float:
        self.ticks += 0.010
        return self.ticks


def test_collectors_use_read_only_endpoints_and_aggregate_aliases() -> None:
    transport = FakeTransport(
        {
            "http://ollama-a/api/ps": {
                "models": [{"name": "model-a", "inFlight": 1, "queueDepth": 2, "latencyMs": 18.5}]
            },
            "http://ollama-b/api/ps": {
                "models": [{"name": "model-a", "inFlight": 2, "queueDepth": 1, "latencyMs": 21.0}]
            },
            "http://llama/health": {"status": "ok"},
            "http://llama/props": {"model": "model-b", "shortRequestLatencyMs": 11.0},
            "http://llama/slots": [{"id": 0, "is_processing": True}, {"id": 1, "is_processing": False}],
            "http://omlx/health": {"status": "ok", "inFlight": 1, "queueDepth": 3, "latencyMs": 9.0},
            "http://omlx/v1/models": {"data": [{"id": "model-c"}]},
        }
    )

    ollama_a = OllamaCollector("engine-a", "http://ollama-a", ["tiny"], transport)
    ollama_b = OllamaCollector("engine-a", "http://ollama-b", ["slow"], transport)
    llama = LlamaCppCollector("engine-b", "http://llama", ["researcher"], transport)
    omlx = OmlxCollector("engine-c", "http://omlx", ["advisor"], transport)

    agent = HostAgent(
        HostConfig(host_id="host-test", engines=[ollama_a, ollama_b, llama, omlx]),
        signer=PolicySigner(ed25519.Ed25519PrivateKey.generate(), "host-test-key"),
        clock=FakeClock(),
    )
    report = agent.collect_report()

    engine_a = next(engine for engine in report.engines if engine.id == "engine-a")
    assert engine_a.aliases == ["slow", "tiny"]
    assert engine_a.in_flight == 3
    assert engine_a.queue_depth == 3
    assert engine_a.short_request_latency_ms == 18.5
    assert engine_a.health is EngineHealth.HEALTHY
    engine_b = next(engine for engine in report.engines if engine.id == "engine-b")
    assert engine_b.in_flight == 1
    assert engine_b.queue_depth == 0
    assert transport.gets == [
        "http://ollama-a/api/ps",
        "http://ollama-b/api/ps",
        "http://llama/health",
        "http://llama/props",
        "http://llama/slots",
        "http://omlx/health",
        "http://omlx/v1/models",
    ]

    assert transport.posts == []
    assert all(method not in endpoint for endpoint in transport.gets for method in ("POST", "PUT", "DELETE"))


def test_maintenance_state_is_atomic_and_draining_survives_controller_loss(tmp_path: Path) -> None:
    state_path = tmp_path / "state.json"
    store = MaintenanceStateStore(state_path, host_id="host-test")
    store.set_state(MaintenanceState.DRAINING, datetime(2026, 8, 29, 12, 0, tzinfo=UTC))

    restarted = MaintenanceStateStore(state_path, host_id="host-test")
    assert restarted.load().state is MaintenanceState.DRAINING
    assert not list(tmp_path.glob("*.tmp"))

    transport = FakeTransport({}, failures={"https://controller-a/report"})
    collector = OllamaCollector("engine-a", "http://ollama", ["tiny"], FakeTransport({"http://ollama/api/ps": {"models": []}}))
    agent = HostAgent(
        HostConfig(host_id="host-test", engines=[collector], controllers=["https://controller-a/report"]),
        signer=PolicySigner(ed25519.Ed25519PrivateKey.generate(), "host-test-key"),
        state_store=restarted,
        transport=transport,
        clock=FakeClock(),
    )
    report = agent.collect_report()
    assert report.engines[0].state is MaintenanceState.DRAINING


def test_failed_collection_is_stale_and_writes_durable_event(tmp_path: Path) -> None:
    events_path = tmp_path / "events.jsonl"
    transport = FakeTransport({}, failures={"http://ollama/api/ps"})
    collector = OllamaCollector("engine-a", "http://ollama", ["tiny"], transport)
    agent = HostAgent(
        HostConfig(host_id="host-test", engines=[collector]),
        signer=PolicySigner(ed25519.Ed25519PrivateKey.generate(), "host-test-key"),
        events_path=events_path,
        clock=FakeClock(),
    )

    report = agent.collect_report()
    events = events_path.read_text(encoding="utf-8").splitlines()
    assert report.stale is True
    assert len(events) == 1
    event = json.loads(events[0])
    assert event["severity"] == EventSeverity.ERROR
    assert event["subject"] == "collector-failed"
    assert "http://ollama/api/ps" in event["detail"]["endpoint"]


def test_n1_impossibility_requires_a_nonempty_reason() -> None:
    config = HostConfig(
        host_id="host-test",
        engines=[],
        n1_impossible=True,
        n1_impossible_reason="Only one compatible failure domain is configured.",
    )
    agent = HostAgent(config, signer=PolicySigner(ed25519.Ed25519PrivateKey.generate(), "host-test-key"), clock=FakeClock())
    report = agent.collect_report()
    assert report.n1_impossible is True
    assert report.n1_impossible_reason


def test_signed_envelope_is_identical_for_each_controller_and_verifiable() -> None:
    source = FakeTransport({"http://ollama/api/ps": {"models": []}})
    delivery = FakeTransport({})
    private = ed25519.Ed25519PrivateKey.generate()
    agent = HostAgent(
        HostConfig(
            host_id="host-test",
            engines=[OllamaCollector("engine-a", "http://ollama", ["tiny"], source)],
            controllers=["https://controller-a/report", "https://controller-b/report"],
        ),
        signer=PolicySigner(private, "host-test-key"),
        transport=delivery,
        clock=FakeClock(),
    )

    envelope = agent.collect_and_publish()
    assert len(delivery.posts) == 2
    assert delivery.posts[0][1] == delivery.posts[1][1]
    wire = json.loads(delivery.posts[0][1])
    assert wire["payload"]["kind"] == "host-report"
    assert wire["payload"]["schemaVersion"] == 1
    verifier = PolicyVerifier({"host-test-key": private.public_key()}, now=lambda: datetime(2026, 8, 29, 12, 0, tzinfo=UTC))
    assert verifier.verify(envelope) is True


def test_fixture_cli_emits_only_signed_envelope_and_public_key(capsys: Any) -> None:
    from modelctl.agents.host.__main__ import main

    assert main(["--fixture", "fixtures/host/sample.json", "--once"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert set(output) == {"envelope", "publicKey"}
    assert "privateKey" not in output
    assert output["envelope"]["payload"]["kind"] == "host-report"
    assert base64.b64decode(output["publicKey"])



def test_report_sequence_is_allocated_before_an_ambiguous_delivery(tmp_path: Path) -> None:
    sequence_path = tmp_path / "sequence.json"

    class AmbiguousTransport(FakeTransport):
        def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> HttpResponse:
            self.posts.append((url, body))
            raise OSError("connection closed after request")

    private_key = ed25519.Ed25519PrivateKey.generate()
    first = HostAgent(
        HostConfig(host_id="host-test", engines=[], controllers=["http://controller/v1/host-reports"]),
        signer=PolicySigner(private_key, "host-test-key"),
        sequence_path=sequence_path,
        events_path=tmp_path / "first-events.jsonl",
        transport=AmbiguousTransport({}),
        clock=FakeClock(),
    )
    ambiguous_envelope = first.collect_and_publish()
    assert ambiguous_envelope.sequence == 1
    assert json.loads(sequence_path.read_text(encoding="utf-8")) == {"sequence": 1}

    second = HostAgent(
        HostConfig(host_id="host-test", engines=[]),
        signer=PolicySigner(private_key, "host-test-key"),
        sequence_path=sequence_path,
        events_path=tmp_path / "second-events.jsonl",
        clock=FakeClock(),
    )
    next_envelope = second.collect_envelope()
    assert next_envelope.sequence == 2
    assert json.loads(sequence_path.read_text(encoding="utf-8")) == {"sequence": 2}


def test_urllib_transport_passes_a_finite_configurable_timeout(monkeypatch: Any) -> None:
    captured: dict[str, float] = {}

    class Response:
        status = 200

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return b"{}"

    def fake_urlopen(request: Any, *, timeout: float) -> Response:
        captured["timeout"] = timeout
        return Response()

    monkeypatch.setattr("modelctl.agents.host.transport.urlopen", fake_urlopen)
    assert UrllibTransport(timeout=2.5).get("https://engine.example/health").status_code == 200
    assert captured["timeout"] == 2.5

def test_urllib_transport_uses_supplied_ssl_context(monkeypatch: Any) -> None:
    import ssl

    context = ssl.create_default_context()
    captured: dict[str, object] = {}

    class Response:
        status = 200

        def __enter__(self) -> Self:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def read(self) -> bytes:
            return b"{}"

    def fake_urlopen(request: Any, *, timeout: float, context: ssl.SSLContext) -> Response:
        captured["context"] = context
        return Response()

    monkeypatch.setattr("modelctl.agents.host.transport.urlopen", fake_urlopen)

    assert UrllibTransport(timeout=2.5, ssl_context=context).get("https://engine.example/health").status_code == 200
    assert captured["context"] is context


def test_mtls_context_loads_ca_and_client_chain_and_rejects_open_key_permissions(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    ca_path = tmp_path / "ca.pem"
    cert_path = tmp_path / "client.pem"
    key_path = tmp_path / "client-key.pem"
    for path in (ca_path, cert_path, key_path):
        path.write_text("fixture", encoding="utf-8")
    key_path.chmod(0o600)
    captured: dict[str, object] = {}

    class Context:
        def load_cert_chain(self, certfile: str, keyfile: str) -> None:
            captured["chain"] = (certfile, keyfile)

    context = Context()

    def create_default_context(*, cafile: str) -> Context:
        captured["ca"] = cafile
        return context

    monkeypatch.setattr("modelctl.agents.host.transport.ssl.create_default_context", create_default_context)

    assert build_mtls_context(ca_path, cert_path, key_path) is context
    assert captured == {
        "ca": str(ca_path),
        "chain": (str(cert_path), str(key_path)),
    }

    key_path.chmod(0o644)
    try:
        build_mtls_context(ca_path, cert_path, key_path)
    except ValueError as exc:
        assert "0600" in str(exc)
    else:
        raise AssertionError("open client key permissions were accepted")

def test_production_cli_loads_yaml_key_collects_and_posts_full_report_url(tmp_path: Path, capsys: Any) -> None:
    from modelctl.agents.host.__main__ import main

    received: list[tuple[str, bytes]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path != "/api/ps":
                self.send_response(404)
                self.end_headers()
                return
            body = b'{"models": [{"name": "model-a", "inFlight": 1}]}'
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self) -> None:
            size = int(self.headers["content-length"] or "0")
            received.append((self.path, self.rfile.read(size)))
            self.send_response(202)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        private_key = ed25519.Ed25519PrivateKey.generate()
        key_path = tmp_path / "host-key.pem"
        key_path.write_bytes(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        key_path.chmod(0o600)
        config_path = tmp_path / "host.yaml"
        config_path.write_text(
            "\n".join(
                (
                    "hostId: host-production",
                    "signing:",
                    "  keyId: host-key",
                    f"  privateKeyPath: {key_path}",
                    "controllers:",
                    f"  - http://127.0.0.1:{server.server_port}/v1/host-reports",
                    "statePath: " + str(tmp_path / "state.json"),
                    "sequencePath: " + str(tmp_path / "sequence.json"),
                    "eventsPath: " + str(tmp_path / "events.jsonl"),
                    "timeoutSeconds: 2",
                    "engines:",
                    "  - id: engine-a",
                    "    collector: ollama",
                    f"    baseUrl: http://127.0.0.1:{server.server_port}",
                    "    aliases: [tiny]",
                )
            ),
            encoding="utf-8",
        )
        assert main(["run", "--config", str(config_path), "--once"]) == 0
    finally:
        server.shutdown()
        thread.join(timeout=2)

    output = json.loads(capsys.readouterr().out)
    assert output["sequence"] == 1
    assert received and received[0][0] == "/v1/host-reports"
    wire = json.loads(received[0][1])
    assert wire["payload"]["hostId"] == "host-production"


def test_production_signing_key_rejects_group_or_other_access(tmp_path: Path) -> None:
    from modelctl.agents.host.__main__ import _load_signer

    key_path = tmp_path / "host-key.pem"
    key_path.write_bytes(
        ed25519.Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o644)
    try:
        _load_signer(tmp_path / "host.yaml", {"keyId": "host-key", "privateKeyPath": str(key_path)})
    except ValueError as exc:
        assert "permissions" in str(exc)
    else:
        raise AssertionError("insecure signing-key permissions were accepted")


def test_production_once_succeeds_when_one_controller_accepts(
    tmp_path: Path, capsys: Any, monkeypatch: Any
) -> None:
    from modelctl.agents.host import __main__ as host_main

    class PartialAgent:
        def collect_envelope(self) -> Any:
            return type("Envelope", (), {"sequence": 7})()

        def publish(self, envelope: Any) -> dict[str, bool]:
            return {"https://active/v1/host-reports": True, "https://standby/v1/host-reports": False}

    monkeypatch.setattr(host_main, "_load_production", lambda path: (PartialAgent(), 5.0))

    assert host_main.main(["run", "--config", str(tmp_path / "host.yaml"), "--once"]) == 0
    assert json.loads(capsys.readouterr().out)["controllers"] == {
        "https://active/v1/host-reports": True,
        "https://standby/v1/host-reports": False,
    }


def test_production_once_fails_when_no_controller_accepts(
    tmp_path: Path, monkeypatch: Any
) -> None:
    from modelctl.agents.host import __main__ as host_main

    class FailedAgent:
        def collect_envelope(self) -> Any:
            return type("Envelope", (), {"sequence": 7})()

        def publish(self, envelope: Any) -> dict[str, bool]:
            return {"https://active/v1/host-reports": False}

    monkeypatch.setattr(host_main, "_load_production", lambda path: (FailedAgent(), 5.0))
    assert host_main.main(["run", "--config", str(tmp_path / "host.yaml"), "--once"]) == 3
