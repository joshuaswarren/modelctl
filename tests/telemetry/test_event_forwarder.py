import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from modelctl.agents.host.report import EventStore, ReportSequenceStore
from modelctl.agents.host.transport import HttpResponse
from modelctl.domain.events import Event
from modelctl.policy.signing import PolicySigner, SignedEnvelope
from modelctl.telemetry import event_cli
from modelctl.telemetry.event_forwarder import (
    EventForwarder,
    ExtensionEvent,
    ForwardResult,
    load_event_forwarder_config,
)

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)


class RecordingTransport:
    def __init__(self, responses: list[int | BaseException]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, bytes, Mapping[str, str]]] = []

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> HttpResponse:
        self.requests.append((url, body, headers))
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        return HttpResponse(response, {"accepted": 200 <= response < 300})


def make_event(*, event_id: str = "event-1") -> dict[str, object]:
    return {
        "id": event_id,
        "time": "2026-08-30T12:00:00Z",
        "subsystem": "omp",
        "severity": "warning",
        "subject": "request-blocked",
        "detail": {"provider": "local", "attempts": 2, "manual": False, "tags": ["safe"], "note": None},
    }


def make_forwarder(
    tmp_path: Path,
    *,
    event_lines: list[str],
    responses: list[int | BaseException],
    sink: list[Event],
    signer: PolicySigner | None = None,
) -> tuple[EventForwarder, RecordingTransport, ReportSequenceStore, Path, Path]:
    events_path = tmp_path / "modelctl-events.jsonl"
    events_path.write_text("\n".join(event_lines) + "\n", encoding="utf-8")
    sequence_store = ReportSequenceStore(tmp_path / "sequence.json")
    transport = RecordingTransport(responses)
    cursor_path = tmp_path / "cursor.json"
    pending_path = tmp_path / "pending.json"
    forwarder = EventForwarder(
        events_path=events_path,
        cursor_path=cursor_path,
        pending_path=pending_path,
        signer=signer or PolicySigner(ed25519.Ed25519PrivateKey.generate(), "omp-host"),
        controllers=["https://active.example/", "https://standby.example/v1/events"],
        sequence_store=sequence_store,
        transport=transport,
        event_sink=sink.append,
        now=lambda: NOW,
        ttl=timedelta(minutes=5),
    )
    return forwarder, transport, sequence_store, cursor_path, pending_path


def test_forwards_valid_event_to_both_normalized_endpoints_with_exact_payload(tmp_path: Path) -> None:
    events: list[Event] = []
    forwarder, transport, sequence_store, cursor_path, pending_path = make_forwarder(
        tmp_path, event_lines=[json.dumps(make_event())], responses=[200, 200], sink=events
    )

    result = forwarder.forward()

    assert result.forwarded == 1
    assert result.failed == 0
    assert sequence_store.load() == 1
    assert json.loads(cursor_path.read_text(encoding="utf-8"))["cursor"] > 0
    assert not pending_path.exists()
    assert [request[0] for request in transport.requests] == [
        "https://active.example/v1/events",
        "https://standby.example/v1/events",
    ]
    envelopes = [SignedEnvelope.model_validate(json.loads(request[1])) for request in transport.requests]
    assert envelopes[0].model_dump(mode="json", by_alias=True) == envelopes[1].model_dump(mode="json", by_alias=True)
    assert envelopes[0].sequence == 1
    assert envelopes[0].payload == make_event()
    assert "secret" not in transport.requests[0][1].decode("utf-8")
    assert events == []

def test_forwards_usage_event_with_consumed_tokens(tmp_path: Path) -> None:
    usage_event = make_event()
    usage_event["subject"] = "usage_observed"
    usage_event["detail"] = {
        "provider": "provider-a",
        "accountLabel": "primary",
        "consumedTokens": 11,
        "attribution": "direct",
    }
    forwarder, transport, _, _, _ = make_forwarder(
        tmp_path,
        event_lines=[json.dumps(usage_event)],
        responses=[200, 200],
        sink=[],
    )

    result = forwarder.forward()

    assert result.forwarded == 1
    assert SignedEnvelope.model_validate_json(transport.requests[0][1]).payload == usage_event


@pytest.mark.parametrize(
    "detail",
    [
        {"accountEmail": "owner@example.invalid"},
        {"accountId": "provider-account-123"},
        {"accountLabel": "owner@example.invalid"},
    ],
)
def test_rejects_raw_provider_identity(detail: dict[str, object]) -> None:
    event = make_event()
    event["detail"] = detail

    with pytest.raises(ValueError, match="identity"):
        ExtensionEvent.model_validate(event)


def test_allocates_before_network_and_retries_exact_pending_envelope_after_restart(tmp_path: Path) -> None:
    signer = PolicySigner(ed25519.Ed25519PrivateKey.generate(), "omp-host")
    first_events: list[Event] = []
    first, failed_transport, sequence_store, cursor_path, pending_path = make_forwarder(
        tmp_path,
        event_lines=[json.dumps(make_event())],
        responses=[503, 503],
        sink=first_events,
        signer=signer,
    )

    first_result = first.forward()
    first_body = failed_transport.requests[0][1]

    assert first_result.forwarded == 0
    assert first_result.failed == 2
    assert sequence_store.load() == 1
    assert (json.loads(cursor_path.read_text(encoding="utf-8"))["cursor"] if cursor_path.exists() else 0) == 0
    assert pending_path.exists()

    second_events: list[Event] = []
    second, restarted_transport, restarted_sequence, _, _ = make_forwarder(
        tmp_path,
        event_lines=[json.dumps(make_event())],
        responses=[503, 200],
        sink=second_events,
        signer=signer,
    )

    second_result = second.forward()

    assert second_result.forwarded == 1
    assert second_result.failed == 1
    assert restarted_sequence.load() == 1
    assert restarted_transport.requests[0][1] == first_body
    assert json.loads(cursor_path.read_text(encoding="utf-8"))["cursor"] == len(
        (json.dumps(make_event()) + "\n").encode("utf-8")
    )
    assert not pending_path.exists()
    assert [event.subject for event in first_events + second_events] == [
        "event-delivery-failed",
        "event-delivery-failed",
        "event-delivery-failed",
    ]


def test_malformed_line_does_not_advance_and_emits_secret_free_durable_error(tmp_path: Path) -> None:
    events_path = tmp_path / "modelctl-events.jsonl"
    secret = "sk-live-value-must-not-leak"
    events_path.write_text(
        json.dumps({"id": "bad", "detail": {"token": secret}}) + "\n",
        encoding="utf-8",
    )
    local_events = EventStore(tmp_path / "local-errors.jsonl")
    forwarder = EventForwarder(
        events_path=events_path,
        cursor_path=tmp_path / "cursor.json",
        pending_path=tmp_path / "pending.json",
        signer=PolicySigner(ed25519.Ed25519PrivateKey.generate(), "omp-host"),
        controllers=["https://active.example", "https://standby.example"],
        sequence_store=ReportSequenceStore(tmp_path / "sequence.json"),
        transport=RecordingTransport([200, 200]),
        event_sink=local_events.append,
        now=lambda: NOW,
    )

    result = forwarder.forward()

    emitted = local_events.events()
    assert result.forwarded == 0
    assert result.failed == 1
    assert not (tmp_path / "cursor.json").exists()
    assert not (tmp_path / "sequence.json").exists()
    assert len(emitted) == 1
    assert emitted[0].subject == "event-parse-failed"
    assert emitted[0].detail == {"line": 1, "reason": "invalid-extension-event"}
    assert secret not in (tmp_path / "local-errors.jsonl").read_text(encoding="utf-8")
    assert not (tmp_path / "pending.json").exists()


def test_loads_production_config_and_forwards_events(tmp_path: Path) -> None:
    key = ed25519.Ed25519PrivateKey.generate()
    key_path = tmp_path / "signing.pem"
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    key_path.chmod(0o600)
    events_path = tmp_path / "omp-events.jsonl"
    events_path.write_text(json.dumps(make_event()) + "\n", encoding="utf-8")
    config_path = tmp_path / "event-forwarder.yaml"
    config_path.write_text(
        """signing:
  keyId: omp-host
  privateKeyPath: signing.pem
controllers:
  - https://active.example
  - https://standby.example
eventsPath: omp-events.jsonl
cursorPath: cursor.json
pendingPath: pending.json
sequencePath: sequence.json
localEventsPath: local-events.jsonl
timeoutSeconds: 2
recordTtlSeconds: 300
""",
        encoding="utf-8",
    )
    transport = RecordingTransport([200, 200])

    forwarder = load_event_forwarder_config(config_path, transport=transport, now=lambda: NOW)
    result = forwarder.forward()

    assert result.forwarded == 1
    assert [request[0] for request in transport.requests] == [
        "https://active.example/v1/events",
        "https://standby.example/v1/events",
    ]
    assert json.loads((tmp_path / "sequence.json").read_text(encoding="utf-8"))["sequence"] == 1

def test_event_forwarder_cli_emits_machine_readable_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class LoadedForwarder:
        def forward(self) -> ForwardResult:
            return ForwardResult(forwarded=2, failed=0, cursor=42, pending=False)

    monkeypatch.setattr(event_cli, "load_event_forwarder_config", lambda _: LoadedForwarder())

    exit_code = event_cli.main(["forward", "--config", str(tmp_path / "forwarder.yaml")])

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) == {
        "cursor": 42,
        "failed": 0,
        "forwarded": 2,
        "pending": False,
    }
