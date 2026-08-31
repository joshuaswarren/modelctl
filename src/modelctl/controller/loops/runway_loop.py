"""Runway evaluation loop."""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from pydantic import ValidationError

from modelctl.controller.api import Controller
from modelctl.controller.loops.base import LoopRunner
from modelctl.controller.store import fingerprint
from modelctl.telemetry.contracts import OmpSpendEvent, ProxySpendReceipt, QuotaRecord
from modelctl.telemetry.engine import QuotaTelemetry


class RunwayLoop(LoopRunner):
    """Join stored quota and spend records into the current runway view."""

    def __init__(self, controller: Controller, callback: Callable[[], Any] | None = None) -> None:
        self.telemetry = QuotaTelemetry(None, now=controller.now)
        self._seen_quota: set[str] = set()
        self._seen_events: set[str] = set()
        self._seen_receipts: set[str] = set()
        self._persisted_events = 0
        super().__init__("runway", controller, callback or self._evaluate)


    def _load_quotas(self) -> None:
        for payload in self.controller.store.quotas():
            record_id = fingerprint(payload)
            if record_id in self._seen_quota:
                continue
            self._seen_quota.add(record_id)
            try:
                self.telemetry.add_verified_record(QuotaRecord.model_validate(payload))
            except ValidationError:
                self._record_invalid("quota", record_id)

    def _load_events(self) -> None:
        for event in self.controller.store.events():
            event_id = str(event["id"])
            if event_id in self._seen_events:
                continue
            self._seen_events.add(event_id)
            payload = event.get("detail")
            if event.get("subject") != "event" or not isinstance(payload, Mapping):
                continue
            if payload.get("subject") != "usage_observed":
                continue
            detail = payload.get("detail")
            try:
                if not isinstance(detail, Mapping):
                    raise TypeError("usage detail must be an object")
                spend = OmpSpendEvent.model_validate(
                    {
                        "provider": detail.get("provider"),
                        "accountLabel": detail.get("accountLabel"),
                        "amount": detail.get("consumedTokens"),
                        "occurredAt": payload.get("time"),
                        "attribution": detail.get("attribution"),
                    }
                )
            except (TypeError, ValidationError):
                self._record_invalid("omp", event_id)
                continue
            self.telemetry.add_spend(spend)

    def _load_receipts(self) -> None:
        for payload in self.controller.store.apply_receipts():
            receipt_id = fingerprint(payload)
            if receipt_id in self._seen_receipts:
                continue
            self._seen_receipts.add(receipt_id)
            if payload.get("kind") != "modelctl.proxy.spend":
                continue
            try:
                receipt = {key: value for key, value in payload.items() if key != "kind"}
                self.telemetry.add_spend(ProxySpendReceipt.model_validate(receipt))
            except ValidationError:
                self._record_invalid("proxy", receipt_id)

    def _record_invalid(self, source: str, record_id: str) -> None:
        self.controller.store.append_event(
            now=self.controller.now(),
            subsystem="runway",
            severity="warning",
            subject="spend-source-unclassifiable" if source != "quota" else "quota-record-rejected",
            detail={"source": source, "recordId": record_id},
        )

    def _persist_new_events(self) -> None:
        events = self.telemetry.events
        for event in events[self._persisted_events:]:
            self.controller.store.append_event(
                now=event.time,
                subsystem=event.subsystem,
                severity=event.severity.value,
                subject=event.subject,
                detail=event.detail,
            )
        self._persisted_events = len(events)

    def _evaluate(self) -> list[dict[str, Any]]:
        self._load_quotas()
        self._load_events()
        self._load_receipts()
        accounts = {
            (record.provider, record.account_label)
            for record in self.telemetry.records
        } | {
            (spend.provider, spend.account_label)
            for spend in self.telemetry.spend
        }
        estimates = [
            self.telemetry.runway(provider, account_label).model_dump(
                mode="json",
                by_alias=True,
            )
            for provider, account_label in sorted(accounts)
        ]
        self._persist_new_events()
        self.controller.set_runway(estimates)
        return estimates
