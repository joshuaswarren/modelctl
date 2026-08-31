import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ed25519

from modelctl.agents.host.report import EventStore, ReportSequenceStore
from modelctl.agents.host.transport import HttpResponse
from modelctl.policy.signing import PolicySigner, SignedEnvelope
from modelctl.telemetry import QuotaRecord, QuotaSourceClass

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)


class RecordingTransport:
    def __init__(self, *, status_code: int = 200) -> None:
        self.status_code = status_code
        self.requests: list[tuple[str, bytes, Mapping[str, str]]] = []

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> HttpResponse:
        self.requests.append((url, body, headers))
        return HttpResponse(self.status_code, {"accepted": self.status_code == 200})


def record(*, used: int = 100) -> QuotaRecord:
    return QuotaRecord(
        provider="openai",
        accountLabel="primary-prod",
        quotaUsed=used,
        resetTime=NOW + timedelta(days=1),
        sourceClass="provider-derived",
        freshnessTime=NOW,
    )


def test_snapshot_origin_maps_to_all_runway_source_classes() -> None:
    from modelctl.telemetry.collector_client import QuotaSnapshot, snapshot_record
    snapshot = QuotaSnapshot(
        provider="openai",
        accountLabel="primary-prod",
        quotaUsed=100,
        resetTime=NOW + timedelta(days=1),
        capturedAt=NOW - timedelta(hours=6),
    )

    assert snapshot_record(snapshot, "provider-derived").source_class is QuotaSourceClass.PROVIDER_DERIVED
    assert snapshot_record(snapshot, "delayed-dashboard").source_class is QuotaSourceClass.DELAYED_DASHBOARD
    assert snapshot_record(snapshot, "consumption-estimated").source_class is QuotaSourceClass.CONSUMPTION_ESTIMATED
    assert snapshot_record(snapshot, "unknown").source_class is QuotaSourceClass.UNKNOWN


def test_collector_allocates_sequence_before_failed_delivery_and_never_reuses_it(tmp_path: Path) -> None:
    from modelctl.telemetry.collector_client import QuotaCollectorClient
    signer = PolicySigner(ed25519.Ed25519PrivateKey.generate(), "quota-collector")
    sequence_store = ReportSequenceStore(tmp_path / "quota-sequence.json")
    failed_transport = RecordingTransport(status_code=503)
    events = EventStore(tmp_path / "collector-events.jsonl")
    failed = QuotaCollectorClient(
        signer=signer,
        controllers=["https://active.example", "https://standby.example/v1/quota"],
        sequence_store=sequence_store,
        transport=failed_transport,
        now=lambda: NOW,
        event_store=events,
    )

    first = failed.publish([record(used=100)])

    assert first[0].envelope.sequence == 1
    assert first[0].deliveries == {
        "https://active.example/v1/quota": False,
        "https://standby.example/v1/quota": False,
    }
    assert sequence_store.load() == 1
    assert [event.subject for event in events.events()] == [
        "quota-delivery-failed",
        "quota-delivery-failed",
    ]
    assert all("payload" not in event.detail for event in events.events())

    good_transport = RecordingTransport()
    restarted = QuotaCollectorClient(
        signer=signer,
        controllers=["https://active.example"],
        sequence_store=ReportSequenceStore(tmp_path / "quota-sequence.json"),
        transport=good_transport,
        event_store=EventStore(tmp_path / "restarted-events.jsonl"),
        now=lambda: NOW,
    )
    second = restarted.publish([record(used=200)])

    assert second[0].envelope.sequence == 2
    wire = SignedEnvelope.model_validate(json.loads(good_transport.requests[0][1]))
    assert wire.sequence == 2
    assert wire.payload["quotaUsed"] == 200
    assert good_transport.requests[0][2]["x-modelctl-kind"] == "quota"
