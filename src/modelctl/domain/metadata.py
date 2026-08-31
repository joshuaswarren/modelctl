"""Request metadata carried across model routing boundaries."""
from __future__ import annotations

from enum import Enum

from pydantic import Field, field_validator

from modelctl.domain.workload import DomainModel, WorkloadName


class OverrideSource(str, Enum):
    FRONTMATTER = "frontmatter"
    AGENT_MODEL_OVERRIDES = "agentModelOverrides"
    NONE = "none"


class RequestMetadata(DomainModel):
    """Attribution and override state for one request."""

    request_id: str | None = Field(default=None, alias="requestId")
    role: str = Field(min_length=1)
    agent: str = Field(min_length=1)
    workload_class: WorkloadName | None = Field(default=None, alias="workloadClass")
    explicit_selector: bool = Field(default=False, alias="explicitSelector")
    selector: str | None = None
    override_source: OverrideSource = Field(default=OverrideSource.NONE, alias="overrideSource")
    project: str | None = None
    session: str | None = None
    client_fallback: list[str] = Field(default_factory=list, alias="clientFallback")
    direct_cloud: bool = Field(default=False, alias="directCloud")
    manual_cloud: bool = Field(default=False, alias="manualCloud")

    @field_validator("request_id", "selector", "project", "session")
    @classmethod
    def reject_blank_optional_values(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError("optional metadata strings must not be blank")
        return value

    @field_validator("client_fallback")
    @classmethod
    def validate_fallbacks(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("clientFallback values must not be blank")
        return values



Metadata = RequestMetadata
