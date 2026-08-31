"""Signed replication messages exchanged by controller peers."""
from __future__ import annotations

from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field

from modelctl.policy.signing import SignedEnvelope

type JsonValue = None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]



class ReplicationMessage(BaseModel):
    """One logical mutation sent from the active controller."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    source_controller: str = Field(min_length=1, alias="sourceController")
    epoch: int = Field(ge=0)
    generation: int = Field(ge=0)
    operation_id: str = Field(min_length=1, alias="operationId")
    payload: JsonObject


class ReplicationError(Exception):
    """The peer did not acknowledge a replicated mutation."""


class ReplicationPeer(Protocol):
    """Minimal durable prepare/commit contract for a replication peer."""

    def prepare_replication(self, message: ReplicationMessage, envelope: SignedEnvelope) -> bool: ...

    def commit_replication(self, operation_id: str) -> bool: ...

    def abort_replication(self, operation_id: str) -> None: ...

    def fence(self, epoch: int) -> bool: ...
