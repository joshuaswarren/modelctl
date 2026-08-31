from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from pydantic import ValidationError

from modelctl.policy.signing import PolicySigner
from modelctl.policy.verify import PolicyVerifier
from modelctl.telemetry import (
    OmpSpendEvent,
    ProxySpendReceipt,
    QuotaRecord,
    QuotaSourceClass,
    QuotaTelemetry,
    SpendRecord,
)

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)


def signed_quota(signer: PolicySigner, payload: dict[str, object], sequence: int = 1):
    return signer.sign(
        payload,
        issued_at=NOW - timedelta(minutes=1),
        expires_at=NOW + timedelta(hours=1),
        nonce=f"nonce-{sequence}",
        sequence=sequence,
    )


def make_telemetry() -> tuple[QuotaTelemetry, PolicySigner]:
    private = ed25519.Ed25519PrivateKey.generate()
    signer = PolicySigner(private, "broker-key")
    verifier = PolicyVerifier({"broker-key": private.public_key()}, now=lambda: NOW)
    return QuotaTelemetry(verifier, now=lambda: NOW), signer


def quota_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "provider": "openai",
        "accountLabel": "primary-prod",
        "quotaUsed": 1200,
        "resetTime": "2026-09-01T00:00:00Z",
        "sourceClass": "provider-derived",
        "freshnessTime": "2026-08-30T11:59:00Z",
        "quotaUnit": "tokens",
        "sourceDomain": "broker-host",
    }
    payload.update(overrides)
    return payload


def test_signed_broker_quota_is_sanitized_and_accepted() -> None:
    telemetry, signer = make_telemetry()

    result = telemetry.ingest(signed_quota(signer, quota_payload()))

    assert result.accepted is True
    assert result.record is not None
    assert result.record.provider == "openai"
    assert result.record.account_label == "primary-prod"
    assert telemetry.events == []


def test_quota_schema_rejects_identity_fields_and_email_values() -> None:
    with pytest.raises(ValidationError):
        QuotaRecord.model_validate({**quota_payload(), "accountId": "acct-raw"})
    with pytest.raises(ValidationError):
        QuotaRecord.model_validate({**quota_payload(), "accountLabel": "owner@example.com"})
    with pytest.raises(ValidationError):
        QuotaRecord.model_validate({**quota_payload(), "provider": "owner@example.com"})


def test_six_hour_dashboard_snapshot_has_delayed_source_class() -> None:
    telemetry, signer = make_telemetry()
    payload = quota_payload(
        sourceClass="dashboard",
        freshnessTime="2026-08-30T06:00:00Z",
    )

    result = telemetry.ingest(signed_quota(signer, payload))

    assert result.accepted is True
    assert result.record is not None
    assert result.record.source_class is QuotaSourceClass.DELAYED_DASHBOARD


def test_bad_signature_is_rejected_with_secret_free_audit_event() -> None:
    telemetry, signer = make_telemetry()
    envelope = signed_quota(signer, quota_payload())
    bad = envelope.model_copy(update={"signature": "A" * len(envelope.signature)})

    result = telemetry.ingest(bad)

    assert result.accepted is False
    assert result.record is None
    assert len(telemetry.events) == 1
    event = telemetry.events[0]
    assert event.subject == "quota-envelope-rejected"
    assert event.detail["reason"] == "invalid-signature"
    assert "payload" not in event.detail
    assert "signature" not in event.detail


def test_runway_prefers_provider_and_records_conflicting_sources() -> None:
    telemetry, signer = make_telemetry()
    telemetry.ingest(signed_quota(signer, quota_payload(quotaUsed=1000), sequence=1))
    telemetry.ingest(
        signed_quota(
            signer,
            quota_payload(
                quotaUsed=1800,
                sourceClass="delayed-dashboard",
                freshnessTime="2026-08-30T11:58:00Z",
            ),
            sequence=2,
        )
    )

    runway = telemetry.runway("openai", "primary-prod")

    assert runway.source_class is QuotaSourceClass.PROVIDER_DERIVED
    assert runway.quota_used == 1000
    assert any(event.subject == "quota-source-conflict" for event in telemetry.events)


def test_runway_becomes_unknown_after_fifteen_minutes_of_silence() -> None:
    telemetry, signer = make_telemetry()
    telemetry.ingest(
        signed_quota(
            signer,
            quota_payload(freshnessTime="2026-08-30T11:44:59Z"),
        )
    )

    runway = telemetry.runway("openai", "primary-prod")

    assert runway.source_class is QuotaSourceClass.UNKNOWN
    assert runway.quota_used is None
    assert any(event.subject == "quota-telemetry-silent" for event in telemetry.events)


def test_runway_counts_omp_direct_manual_and_proxy_spend() -> None:
    telemetry, signer = make_telemetry()
    telemetry.ingest(signed_quota(signer, quota_payload()))
    telemetry.add_spend(
        OmpSpendEvent(
            provider="openai",
            account_label="primary-prod",
            amount=20,
            occurred_at=NOW,
            attribution="direct",
        )
    )
    telemetry.add_spend(
        OmpSpendEvent(
            provider="openai",
            account_label="primary-prod",
            amount=5,
            occurred_at=NOW,
            attribution="manual",
        )
    )
    telemetry.add_spend(
        ProxySpendReceipt(
            provider="openai",
            account_label="primary-prod",
            amount=10,
            occurred_at=NOW,
        )
    )

    runway = telemetry.runway("openai", "primary-prod")

    assert runway.direct_spend == 20
    assert runway.manual_spend == 5
    assert runway.proxy_spend == 10
    assert runway.total_spend == 35
    assert runway.quota_used == 1200
    assert runway.projected_quota_used == 1235


def test_unclassifiable_spend_stays_unknown_and_emits_event() -> None:
    telemetry, signer = make_telemetry()
    telemetry.ingest(signed_quota(signer, quota_payload()))
    telemetry.add_spend(
        SpendRecord(
            provider="openai",
            account_label="primary-prod",
            amount=10,
            occurred_at=NOW,
            source="scheduler",
            attribution="unknown",
        )
    )

    runway = telemetry.runway("openai", "primary-prod")

    assert runway.source_class is QuotaSourceClass.PROVIDER_DERIVED
    assert runway.total_spend == 0
    assert any(event.subject == "spend-source-unclassifiable" for event in telemetry.events)


def test_non_broker_source_domain_is_rejected() -> None:
    with pytest.raises(ValidationError):
        QuotaRecord.model_validate({**quota_payload(), "sourceDomain": "controller-host"})


def test_same_source_observations_do_not_create_source_conflict() -> None:
    telemetry, signer = make_telemetry()
    telemetry.ingest(signed_quota(signer, quota_payload(quotaUsed=1000), sequence=1))
    telemetry.ingest(
        signed_quota(
            signer,
            quota_payload(quotaUsed=1100, freshnessTime="2026-08-30T11:59:30Z"),
            sequence=2,
        )
    )

    telemetry.runway("openai", "primary-prod")

    assert not any(event.subject == "quota-source-conflict" for event in telemetry.events)


def test_runway_adds_only_spend_after_the_selected_observation() -> None:
    telemetry, signer = make_telemetry()
    telemetry.ingest(signed_quota(signer, quota_payload()))
    telemetry.add_spend(
        OmpSpendEvent(
            provider="openai",
            account_label="primary-prod",
            amount=20,
            occurred_at=NOW - timedelta(minutes=2),
            attribution="direct",
        )
    )
    telemetry.add_spend(
        OmpSpendEvent(
            provider="openai",
            account_label="primary-prod",
            amount=5,
            occurred_at=NOW,
            attribution="direct",
        )
    )

    runway = telemetry.runway("openai", "primary-prod")

    assert runway.direct_spend == 5
    assert runway.quota_used == 1200
    assert runway.projected_quota_used == 1205



def test_percent_quota_does_not_add_token_spend_to_percent_used() -> None:
    telemetry, signer = make_telemetry()
    telemetry.ingest(
        signed_quota(
            signer,
            quota_payload(quotaUsed=25, quotaUnit="percent"),
        )
    )
    telemetry.add_spend(
        OmpSpendEvent(
            provider="openai",
            account_label="primary-prod",
            amount=20,
            occurred_at=NOW,
            attribution="direct",
        )
    )

    runway = telemetry.runway("openai", "primary-prod")

    assert runway.quota_used == 25
    assert runway.quota_unit == "percent"
    assert runway.projected_quota_used is None
    assert runway.direct_spend == 20