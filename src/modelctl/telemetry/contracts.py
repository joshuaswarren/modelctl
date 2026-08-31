"""Public quota, spend, and runway telemetry contracts."""
from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import (
    Field,
    StrictFloat,
    StrictInt,
    StrictStr,
    field_validator,
    model_validator,
)

from modelctl.domain.events import Event
from modelctl.domain.runway import RunwaySource
from modelctl.domain.workload import DomainModel

_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_IDENTITY_KEYS = {
    "accountemail",
    "accountid",
    "accountidentifier",
    "email",
    "rawaccountid",
    "userid",
    "useremail",
}


def _reject_identity_values(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized_key = "".join(character for character in str(key).lower() if character.isalnum())
            if normalized_key in _IDENTITY_KEYS:
                raise ValueError("raw identity fields are not accepted")
            _reject_identity_values(item)
    elif isinstance(value, list):
        for item in value:
            _reject_identity_values(item)
    elif isinstance(value, str) and _EMAIL_PATTERN.fullmatch(value):
        raise ValueError("email values are not accepted")


def _utc(value: datetime, field_name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{field_name} must include a UTC offset")
    return value.astimezone(UTC)


QuotaSourceClass = RunwaySource


class SpendAttribution(str, Enum):
    DIRECT = "direct"
    MANUAL = "manual"
    PROXY = "proxy"
    UNKNOWN = "unknown"

class QuotaUnit(str, Enum):
    TOKENS = "tokens"
    PERCENT = "percent"
    REQUESTS = "requests"
    CREDITS = "credits"
    UNKNOWN = "unknown"


class QuotaRecord(DomainModel):
    """One sanitized quota observation from the broker host domain."""

    provider: StrictStr = Field(min_length=1)
    account_label: StrictStr = Field(min_length=1, max_length=128, alias="accountLabel")
    quota_used: StrictFloat | StrictInt = Field(ge=0, alias="quotaUsed")
    quota_unit: QuotaUnit = Field(default=QuotaUnit.TOKENS, alias="quotaUnit")
    reset_time: datetime = Field(alias="resetTime")
    source_class: QuotaSourceClass = Field(alias="sourceClass")
    freshness_time: datetime = Field(alias="freshnessTime")
    source_domain: Literal["broker-host"] = Field(default="broker-host", alias="sourceDomain")

    @model_validator(mode="before")
    @classmethod
    def reject_identity_fields(cls, value: Any) -> Any:
        _reject_identity_values(value)
        return value

    @field_validator("reset_time", "freshness_time")
    @classmethod
    def normalize_times(cls, value: datetime, info: Any) -> datetime:
        return _utc(value, info.field_name)

    @field_validator("source_class", mode="before")
    @classmethod
    def normalize_dashboard_class(cls, value: object) -> object:
        if value == "dashboard":
            return QuotaSourceClass.DELAYED_DASHBOARD
        return value

    @field_validator("source_domain")
    @classmethod
    def require_broker_host_domain(cls, value: str) -> str:
        if value != "broker-host":
            raise ValueError("sourceDomain must be broker-host")
        return value


class SpendRecord(DomainModel):
    """A usage receipt with explicit source and attribution."""

    provider: StrictStr = Field(min_length=1)
    account_label: StrictStr = Field(min_length=1, max_length=128, alias="accountLabel")
    amount: StrictInt = Field(ge=0)
    occurred_at: datetime = Field(alias="occurredAt")
    source: StrictStr = Field(min_length=1)
    attribution: SpendAttribution

    @model_validator(mode="before")
    @classmethod
    def reject_identity_fields(cls, value: Any) -> Any:
        _reject_identity_values(value)
        return value

    @field_validator("occurred_at")
    @classmethod
    def normalize_occurred_at(cls, value: datetime) -> datetime:
        return _utc(value, "occurredAt")


class OmpSpendEvent(SpendRecord):
    """Direct or manual OMP usage event."""

    source: StrictStr = "omp"

    @model_validator(mode="after")
    def require_omp_attribution(self) -> OmpSpendEvent:
        if self.attribution not in (SpendAttribution.DIRECT, SpendAttribution.MANUAL):
            raise ValueError("OMP spend must be direct or manual")
        return self


class ProxySpendReceipt(SpendRecord):
    """Usage receipt emitted by a proxy."""

    source: StrictStr = "proxy"
    attribution: SpendAttribution = SpendAttribution.PROXY

    @model_validator(mode="after")
    def require_proxy_attribution(self) -> ProxySpendReceipt:
        if self.attribution is not SpendAttribution.PROXY:
            raise ValueError("proxy spend must use proxy attribution")
        return self


class RunwayEstimate(DomainModel):
    """The selected quota observation and attributed spend totals."""

    source_class: QuotaSourceClass = Field(alias="sourceClass")
    provider: StrictStr | None = None
    account_label: StrictStr | None = Field(default=None, alias="accountLabel")
    quota_used: StrictFloat | StrictInt | None = Field(default=None, ge=0, alias="quotaUsed")
    quota_unit: QuotaUnit = Field(default=QuotaUnit.UNKNOWN, alias="quotaUnit")
    projected_quota_used: StrictFloat | StrictInt | None = Field(
        default=None,
        ge=0,
        alias="projectedQuotaUsed",
    )
    reset_time: datetime | None = Field(default=None, alias="resetTime")
    freshness_time: datetime | None = Field(default=None, alias="freshnessTime")
    direct_spend: StrictInt = Field(default=0, ge=0, alias="directSpend")
    manual_spend: StrictInt = Field(default=0, ge=0, alias="manualSpend")
    proxy_spend: StrictInt = Field(default=0, ge=0, alias="proxySpend")
    total_spend: StrictInt = Field(default=0, ge=0, alias="totalSpend")

    @field_validator("reset_time", "freshness_time")
    @classmethod
    def normalize_times(cls, value: datetime | None, info: Any) -> datetime | None:
        if value is None:
            return None
        return _utc(value, info.field_name)


class IngestionResult:
    """Result of one signed quota envelope ingestion."""

    def __init__(self, accepted: bool, record: QuotaRecord | None, event: Event | None) -> None:
        self.accepted = accepted
        self.record = record
        self.event = event
