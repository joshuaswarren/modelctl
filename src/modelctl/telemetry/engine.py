"""Signed quota ingestion and source-aware runway calculation."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

from modelctl.domain.events import Event, EventSeverity
from modelctl.policy.signing import SignedEnvelope
from modelctl.policy.verify import PolicyVerifier
from modelctl.telemetry.contracts import (
    IngestionResult,
    OmpSpendEvent,
    ProxySpendReceipt,
    QuotaRecord,
    QuotaSourceClass,
    QuotaUnit,
    RunwayEstimate,
    SpendAttribution,
    SpendRecord,
)


class QuotaTelemetry:
    """Keep verified observations and derive a source-aware runway."""

    def __init__(
        self,
        verifier: PolicyVerifier | None,
        *,
        now: Callable[[], datetime] | None = None,
        silence_window: timedelta = timedelta(minutes=15),
    ) -> None:
        if silence_window <= timedelta(0):
            raise ValueError("silence_window must be positive")
        self._verifier = verifier
        self._now = now or (lambda: datetime.now(UTC))
        self._silence_window = silence_window
        self._records: list[QuotaRecord] = []
        self._spend: list[SpendRecord] = []
        self._events: list[Event] = []
        self._event_keys: set[str] = set()

    @property
    def records(self) -> list[QuotaRecord]:
        return list(self._records)

    @property
    def spend(self) -> list[SpendRecord]:
        return list(self._spend)

    @property
    def events(self) -> list[Event]:
        return list(self._events)

    def add_verified_record(self, record: QuotaRecord) -> None:
        """Add a record already verified by the controller mutation boundary."""

        self._records.append(record)

    def ingest(self, envelope: SignedEnvelope | Mapping[str, Any]) -> IngestionResult:
        if self._verifier is None:
            raise RuntimeError("signed ingestion requires a verifier")
        parsed = self._parse_envelope(envelope)
        if parsed is None:
            event = self._emit(
                "envelope-shape",
                "quota-envelope-rejected",
                EventSeverity.ERROR,
                {"reason": "invalid-envelope-shape"},
            )
            return IngestionResult(False, None, event)
        if not self._verifier.verify(parsed):
            event = self._emit(
                f"signature:{parsed.key_id}:{parsed.nonce}",
                "quota-envelope-rejected",
                EventSeverity.ERROR,
                {"reason": "invalid-signature", "keyId": parsed.key_id, "sequence": parsed.sequence},
            )
            return IngestionResult(False, None, event)
        try:
            record = QuotaRecord.model_validate(parsed.payload)
        except ValidationError:
            event = self._emit(
                f"schema:{parsed.key_id}:{parsed.nonce}",
                "quota-record-rejected",
                EventSeverity.ERROR,
                {"reason": "invalid-quota-record"},
            )
            return IngestionResult(False, None, event)
        self.add_verified_record(record)
        return IngestionResult(True, record, None)

    def add_spend(self, spend: SpendRecord | OmpSpendEvent | ProxySpendReceipt) -> bool:
        valid_omp = spend.source == "omp" and spend.attribution in (
            SpendAttribution.DIRECT,
            SpendAttribution.MANUAL,
        )
        valid_proxy = spend.source == "proxy" and spend.attribution is SpendAttribution.PROXY
        if not (valid_omp or valid_proxy):
            self._emit_unclassifiable_spend(spend)
            return False
        self._spend.append(spend)
        return True

    def runway(self, provider: str, account_label: str) -> RunwayEstimate:
        now = self._utc_now()
        matching = [
            record
            for record in self._records
            if record.provider == provider and record.account_label == account_label
        ]
        fresh = [record for record in matching if now - record.freshness_time <= self._silence_window]
        self._emit_conflict_if_needed(fresh, provider, account_label)
        if any(record.source_class is QuotaSourceClass.UNKNOWN for record in fresh):
            self._emit_once(
                f"unknown-source:{provider}:{account_label}",
                "quota-source-unclassifiable",
                EventSeverity.WARNING,
                {"provider": provider, "accountLabel": account_label},
            )
        if not fresh:
            self._emit_once(
                f"silent:{provider}:{account_label}",
                "quota-telemetry-silent",
                EventSeverity.ERROR,
                {"provider": provider, "accountLabel": account_label, "silenceMinutes": 15},
            )
            return self._estimate_unknown(provider, account_label)
        selected = self._select_record(fresh)
        if selected is None:
            return self._estimate_unknown(provider, account_label)
        direct, manual, proxy = self._spend_totals(
            provider,
            account_label,
            after=selected.freshness_time,
        )
        total = direct + manual + proxy
        projected_quota_used = selected.quota_used + total if selected.quota_unit is QuotaUnit.TOKENS else None
        return RunwayEstimate(
            sourceClass=selected.source_class,
            provider=provider,
            accountLabel=account_label,
            quotaUsed=selected.quota_used,
            quotaUnit=selected.quota_unit,
            projectedQuotaUsed=projected_quota_used,
            resetTime=selected.reset_time,
            freshnessTime=selected.freshness_time,
            directSpend=direct,
            manualSpend=manual,
            proxySpend=proxy,
            totalSpend=total,
        )

    def _parse_envelope(self, envelope: SignedEnvelope | Mapping[str, Any]) -> SignedEnvelope | None:
        if isinstance(envelope, SignedEnvelope):
            return envelope
        try:
            return SignedEnvelope.model_validate(envelope)
        except ValidationError:
            return None

    def _select_record(self, records: list[QuotaRecord]) -> QuotaRecord | None:
        for source_class in (
            QuotaSourceClass.PROVIDER_DERIVED,
            QuotaSourceClass.DELAYED_DASHBOARD,
            QuotaSourceClass.CONSUMPTION_ESTIMATED,
        ):
            candidates = [record for record in records if record.source_class is source_class]
            if candidates:
                return max(candidates, key=lambda record: record.freshness_time)
        return None

    def _emit_conflict_if_needed(
        self,
        records: list[QuotaRecord],
        provider: str,
        account_label: str,
    ) -> None:
        latest_by_source: dict[QuotaSourceClass, QuotaRecord] = {}
        for record in records:
            current = latest_by_source.get(record.source_class)
            if current is None or record.freshness_time > current.freshness_time:
                latest_by_source[record.source_class] = record
        values = {
            (record.quota_used, record.quota_unit, record.reset_time)
            for record in latest_by_source.values()
        }
        if len(latest_by_source) > 1 and len(values) > 1:
            self._emit_once(
                f"conflict:{provider}:{account_label}:{sorted(values, key=str)}",
                "quota-source-conflict",
                EventSeverity.WARNING,
                {"provider": provider, "accountLabel": account_label},
            )

    def _spend_totals(
        self,
        provider: str,
        account_label: str,
        *,
        after: datetime | None = None,
    ) -> tuple[int, int, int]:
        direct = 0
        manual = 0
        proxy = 0
        for spend in self._spend:
            if spend.provider != provider or spend.account_label != account_label:
                continue
            if after is not None and spend.occurred_at <= after:
                continue
            if spend.source == "omp" and spend.attribution is SpendAttribution.DIRECT:
                direct += spend.amount
            elif spend.source == "omp" and spend.attribution is SpendAttribution.MANUAL:
                manual += spend.amount
            elif spend.source == "proxy" and spend.attribution is SpendAttribution.PROXY:
                proxy += spend.amount
        return direct, manual, proxy

    def _emit_unclassifiable_spend(self, spend: SpendRecord) -> None:
        self._emit_once(
            f"spend:{spend.provider}:{spend.account_label}:{spend.source}:{spend.attribution}",
            "spend-source-unclassifiable",
            EventSeverity.WARNING,
            {"source": spend.source, "attribution": spend.attribution.value},
        )

    def _estimate_unknown(self, provider: str, account_label: str) -> RunwayEstimate:
        direct, manual, proxy = self._spend_totals(provider, account_label)
        return RunwayEstimate(
            sourceClass=QuotaSourceClass.UNKNOWN,
            provider=provider,
            accountLabel=account_label,
            resetTime=None,
            freshnessTime=None,
            directSpend=direct,
            manualSpend=manual,
            proxySpend=proxy,
            totalSpend=direct + manual + proxy,
        )

    def _emit_once(
        self,
        key: str,
        subject: str,
        severity: EventSeverity,
        detail: dict[str, Any],
    ) -> Event:
        if key in self._event_keys:
            for event in reversed(self._events):
                if event.subject == subject:
                    return event
        self._event_keys.add(key)
        return self._emit(key, subject, severity, detail)

    def _emit(
        self,
        key: str,
        subject: str,
        severity: EventSeverity,
        detail: dict[str, Any],
    ) -> Event:
        event = Event(
            id=uuid4().hex,
            time=self._utc_now(),
            subsystem="telemetry",
            severity=severity,
            subject=subject,
            detail=detail,
        )
        self._events.append(event)
        self._event_keys.add(key)
        return event

    def _utc_now(self) -> datetime:
        return _utc(self._now())


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("telemetry clock must include a UTC offset")
    return value.astimezone(UTC)
