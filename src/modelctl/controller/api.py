"""FastAPI controller with signed writes and synchronous replication."""
from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import RLock
from typing import Annotated, Any, ClassVar, cast
from uuid import uuid4

from fastapi import Body, FastAPI, Header, HTTPException
from pydantic import ValidationError

from modelctl.controller.auth import (
    AuthenticationError,
    EnvelopeAuthenticator,
    FleetBearerToken,
    PrincipalRegistry,
)
from modelctl.controller.promotion import (
    FencingReceipt,
    FencingVerifier,
    verify_fencing,
)
from modelctl.controller.replication import (
    ReplicationError,
    ReplicationMessage,
    ReplicationPeer,
)
from modelctl.controller.store import ControllerStore, envelope_fingerprint, sanitize
from modelctl.dashboard import mount_dashboard
from modelctl.policy.signing import PolicySigner, SignedEnvelope
from modelctl.telemetry.contracts import QuotaRecord

JsonBody = Annotated[Any, Body()]



class MutationError(Exception):
    """A mutation failed after request parsing."""

    def __init__(self, reason: str, status_code: int) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code


class Controller:
    """One active, standby, or fenced follower controller."""

    _SCOPES: ClassVar[dict[str, str]] = {
        "host-report": "host:report",
        "event": "event:write",
        "quota": "quota:write",
        "apply-receipt": "adapter:write",
        "policy": "policy:write",
    }

    def __init__(
        self,
        db_path: str | Path,
        *,
        controller_id: str,
        role: str,
        epoch: int,
        fleet_token: str,
        principals: PrincipalRegistry,
        peer: ReplicationPeer | None = None,
        replication_signer: PolicySigner | None = None,
        fencing_verifier: FencingVerifier | Callable[[FencingReceipt], bool] | None = None,
        now: Callable[[], datetime] | None = None,
        max_future_skew: timedelta = timedelta(0),
        replication_lag_seconds: float = 5.0,
        observe_only: bool = False,
    ) -> None:
        if role not in {"active", "standby", "follower"}:
            raise ValueError("role must be active, standby, or follower")
        if epoch < 0 or not controller_id:
            raise ValueError("controller identity and epoch are required")
        if replication_lag_seconds <= 0:
            raise ValueError("replication_lag_seconds must be positive")
        self.controller_id = controller_id
        self.observe_only = observe_only
        self._fleet_token = fleet_token
        self.peer = peer
        self.replication_signer = replication_signer
        self.fencing_verifier = fencing_verifier
        self.now = now or (lambda: datetime.now(UTC))
        self.replication_lag_seconds = replication_lag_seconds
        self.store = ControllerStore(db_path)
        self.store.initialize_state(role=role, epoch=epoch)
        self.authenticator = EnvelopeAuthenticator(
            principals,
            now=self.now,
            max_future_skew=max_future_skew,
        )
        self._mutation_lock = RLock()
        self._runway: list[dict[str, Any]] = []

    def set_peer(self, peer: ReplicationPeer | None) -> None:
        self.peer = peer

    def replication_message(
        self,
        source_controller: str,
        epoch: int,
        generation: int,
        operation_id: str,
        payload: dict[str, Any],
    ) -> ReplicationMessage:
        return ReplicationMessage(
            sourceController=source_controller,
            epoch=epoch,
            generation=generation,
            operationId=operation_id,
            payload=payload,
        )

    def _sign_replication_payload(self, payload: Mapping[str, Any]) -> SignedEnvelope:
        if self.replication_signer is None:
            raise ReplicationError("replication signer is not configured")
        with self.store.transaction() as cursor:
            sequence = ControllerStore.next_outbound_sequence(cursor, self.replication_signer.key_id)
        issued = self.now()
        return self.replication_signer.sign(
            dict(payload),
            issued_at=issued,
            expires_at=issued + timedelta(minutes=5),
            nonce=f"{self.controller_id}-replication-{uuid4().hex}",
            sequence=sequence,
        )

    def _next_replication_envelope(self, message: ReplicationMessage) -> SignedEnvelope:
        return self._sign_replication_payload(message.model_dump(mode="json", by_alias=True))

    def sign_replication_control(self, payload: dict[str, object]) -> SignedEnvelope:
        return self._sign_replication_payload(payload)

    def _reject(self, reason: str, envelope: SignedEnvelope | None = None) -> None:
        detail: dict[str, Any] = {}
        if envelope is not None:
            detail = {"keyId": envelope.key_id, "nonce": envelope.nonce, "sequence": envelope.sequence}
        self.store.rejected(now=self.now(), reason=reason, detail=detail)

    def _reject_observe_only(self, kind: str) -> None:
        reason = f"observe-only control-plane mutation rejected: {kind}"
        self.store.rejected(now=self.now(), reason=reason, detail={"mode": "observe-only", "kind": kind})

    def _ingest_observation(
        self,
        kind: str,
        required_scope: str,
        envelope: SignedEnvelope,
    ) -> dict[str, Any]:
        try:
            self.authenticator.authenticate(envelope, required_scope)
            with self._mutation_lock, self.store.transaction() as cursor:
                if not ControllerStore.replay_accept(cursor, envelope.key_id, envelope.nonce, envelope.sequence):
                    raise MutationError("replay or stale mutation sequence", 401)
                state = ControllerStore._state(cursor)
                self._apply_payload_tx(cursor, kind, envelope.payload, envelope, int(state["generation"]))
        except AuthenticationError as exc:
            self._reject(exc.reason, envelope)
            raise MutationError(exc.reason, exc.status_code) from exc
        return {"accepted": True, "mode": "observe-only"}

    @staticmethod
    def _expected(payload: Mapping[str, Any], name: str) -> int | None:
        value = payload.get(name)
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise MutationError(f"{name} must be a non-negative integer", 409)
        return value

    @staticmethod
    def _validated_payload(kind: str, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        if kind != "quota":
            return payload
        domain_payload = {
            key: value
            for key, value in payload.items()
            if key not in {"expectedEpoch", "expectedGeneration", "operationId"}
        }
        try:
            record = QuotaRecord.model_validate(domain_payload)
        except ValidationError as exc:
            raise MutationError("invalid quota record", 422) from exc
        return record.model_dump(mode="json", by_alias=True)

    def _apply_payload_tx(
        self,
        cursor: Any,
        kind: str,
        payload: Mapping[str, Any],
        envelope: SignedEnvelope,
        generation: int,
    ) -> None:
        current = self.now()
        validated = self._validated_payload(kind, payload)
        if kind == "host-report":
            self.store.put_host(cursor, validated, current)
        elif kind == "event":
            self.store.append_event_tx(
                cursor,
                now=current,
                subsystem=str(validated.get("subsystem", "controller")),
                severity=str(validated.get("severity", "info")),
                subject="event",
                detail=dict(validated),
            )
        elif kind == "quota":
            self.store.put_record(cursor, "quotas", validated, current)
        elif kind == "apply-receipt":
            self.store.put_record(cursor, "apply_receipts", validated, current)
        elif kind == "policy":
            self.store.put_policy(cursor, envelope, generation, current)
        else:
            raise MutationError("unknown mutation kind", 422)

    def _remove_replay(self, envelope: SignedEnvelope) -> None:
        with self.store.transaction() as cursor:
            ControllerStore.replay_remove(cursor, envelope.key_id, envelope.nonce, envelope.sequence)

    def _mark_replicated(self, message: ReplicationMessage) -> None:
        with self.store.transaction() as cursor:
            ControllerStore.mark_replicated(cursor, message.operation_id)
            ControllerStore.set_state_value(cursor, "last_replication_ack", message.operation_id)
            ControllerStore.set_state_value(cursor, "last_replication_generation", message.generation)
            ControllerStore.set_state_value(
                cursor,
                "last_replication_at",
                self.now().astimezone(UTC).isoformat().replace("+00:00", "Z"),
            )

    def _commit_peer(self, message: ReplicationMessage) -> bool:
        if self.peer is None or not self.peer.commit_replication(message.operation_id):
            return False
        self._mark_replicated(message)
        return True

    def mutate(self, kind: str, required_scope: str, envelope: SignedEnvelope) -> dict[str, Any]:
        if self.observe_only:
            if kind not in {"host-report", "event", "quota"}:
                self._reject_observe_only(kind)
                raise MutationError("observe-only control-plane mutation rejected", 409)
            return self._ingest_observation(kind, required_scope, envelope)
        try:
            self.authenticator.authenticate(envelope, required_scope)
        except AuthenticationError as exc:
            self._reject(exc.reason, envelope)
            raise MutationError(exc.reason, exc.status_code) from exc

        payload = envelope.payload
        try:
            self._validated_payload(kind, payload)
        except MutationError as exc:
            self._reject(exc.reason, envelope)
            raise
        operation_id = str(payload.get("operationId", envelope.nonce))
        operation_fingerprint = envelope_fingerprint(envelope)
        with self._mutation_lock:
            try:
                with self.store.transaction() as cursor:
                    state = ControllerStore._state(cursor)
                    if state["role"] != "active":
                        raise MutationError("controller is not active", 409)
                    operation = ControllerStore.operation(cursor, operation_id)
                    if operation is not None:
                        if operation["fingerprint"] != operation_fingerprint:
                            raise MutationError("operationId belongs to a different signed envelope", 409)
                        if operation["replication_state"] == "committed":
                            return self._mutation_result(operation_id)
                        raise MutationError("operation is pending replication", 503)
                    expected_epoch = self._expected(payload, "expectedEpoch")
                    expected_generation = self._expected(payload, "expectedGeneration")
                    if expected_epoch is not None and expected_epoch != state["epoch"]:
                        raise MutationError("epoch compare-and-swap failed", 409)
                    if expected_generation is not None and expected_generation != state["generation"]:
                        raise MutationError("generation compare-and-swap failed", 409)
                    if not ControllerStore.replay_accept(cursor, envelope.key_id, envelope.nonce, envelope.sequence):
                        raise MutationError("replay or stale sequence", 401)
                    epoch = int(state["epoch"])
                    generation = int(state["generation"]) + (1 if kind == "policy" else 0)

                message = self.replication_message(
                    self.controller_id,
                    epoch,
                    generation,
                    operation_id,
                    {
                        "kind": kind,
                        "payload": dict(payload),
                        "operationFingerprint": operation_fingerprint,
                        "originalEnvelope": envelope.model_dump(mode="json", by_alias=True),
                    },
                )
                replication_envelope = self._next_replication_envelope(message)
                if self.peer is None:
                    raise ReplicationError("replication peer is not configured")
                try:
                    prepared = self.peer.prepare_replication(message, replication_envelope)
                except Exception as exc:
                    raise ReplicationError("replication prepare failed") from exc
                if not prepared:
                    raise ReplicationError("replication peer did not prepare")

                try:
                    with self.store.transaction() as cursor:
                        state = ControllerStore._state(cursor)
                        if state["role"] != "active" or int(state["epoch"]) != epoch:
                            raise MutationError("controller state changed during replication", 409)
                        self._apply_payload_tx(cursor, kind, payload, envelope, generation)
                        ControllerStore.record_operation(
                            cursor,
                            operation_id,
                            self.controller_id,
                            epoch,
                            generation,
                            operation_fingerprint,
                            replication_state="pending",
                        )
                        ControllerStore.record_outbox(
                            cursor,
                            operation_id,
                            message.model_dump(mode="json", by_alias=True),
                            replication_envelope,
                            operation_fingerprint,
                        )
                        ControllerStore.set_state_value(cursor, "generation", generation)
                        self.store.append_event_tx(
                            cursor,
                            now=self.now(),
                            subsystem="controller",
                            severity="info",
                            subject="mutation-committed",
                            detail={"kind": kind, "operationId": operation_id, "generation": generation},
                            operation_id=operation_id,
                        )
                except Exception as exc:
                    self.peer.abort_replication(operation_id)
                    self._remove_replay(envelope)
                    if isinstance(exc, MutationError):
                        raise
                    raise MutationError("local mutation commit failed", 503) from exc

                if not self._commit_peer(message):
                    raise MutationError("replication commit failed", 503)
            except ReplicationError as exc:
                if self.peer is not None:
                    self.peer.abort_replication(operation_id)
                self._remove_replay(envelope)
                error = MutationError(str(exc), 503)
                self._reject(error.reason, envelope)
                raise error from exc
            except MutationError as exc:
                self._reject(exc.reason, envelope)
                raise
        return self._mutation_result(operation_id)

    def _mutation_result(self, operation_id: str) -> dict[str, Any]:
        state = self.store.state()
        return {
            "accepted": True,
            "operationId": operation_id,
            "generation": state["generation"],
            "epoch": state["epoch"],
        }

    def receive_wire_mutation(self, kind: str, required_scope: str, body: Any) -> dict[str, Any]:
        try:
            envelope = SignedEnvelope.model_validate(body)
        except ValidationError as exc:
            self._reject("invalid signed envelope", None)
            raise MutationError("invalid signed envelope", 422) from exc
        return self.mutate(kind, required_scope, envelope)

    def _replication_input(
        self,
        message: ReplicationMessage,
        envelope: SignedEnvelope,
    ) -> tuple[str, dict[str, Any], SignedEnvelope, str]:
        self.authenticator.authenticate(envelope, "replication:write")
        if envelope.payload != message.model_dump(mode="json", by_alias=True):
            raise MutationError("replication envelope payload does not match message", 401)
        inner = message.payload
        kind_value = inner.get("kind")
        if not isinstance(kind_value, str) or kind_value not in self._SCOPES:
            raise MutationError("unknown replicated mutation kind", 422)
        payload_value = inner.get("payload")
        if not isinstance(payload_value, dict):
            raise MutationError("replication payload must be an object", 422)
        original_value = inner.get("originalEnvelope", inner.get("policyEnvelope"))
        original = SignedEnvelope.model_validate(original_value)
        self.authenticator.authenticate(original, self._SCOPES[kind_value])
        if original.payload != payload_value:
            raise MutationError("replicated payload does not match original envelope", 401)
        expected_operation_id = str(original.payload.get("operationId", original.nonce))
        if message.operation_id != expected_operation_id:
            raise MutationError("replication operationId does not match original envelope", 409)
        operation_fingerprint = envelope_fingerprint(original)
        supplied_fingerprint = inner.get("operationFingerprint")
        if supplied_fingerprint is not None and supplied_fingerprint != operation_fingerprint:
            raise MutationError("replication fingerprint does not match original envelope", 409)
        return kind_value, payload_value, original, operation_fingerprint

    def prepare_replication(self, message: ReplicationMessage, envelope: SignedEnvelope) -> bool:
        try:
            kind, payload, original, operation_fingerprint = self._replication_input(message, envelope)
            with self._mutation_lock, self.store.transaction() as cursor:
                state = ControllerStore._state(cursor)
                operation = ControllerStore.operation(cursor, message.operation_id)
                if operation is not None:
                    return str(operation["fingerprint"]) == operation_fingerprint
                prepared = ControllerStore.prepared(cursor, message.operation_id)
                if prepared is not None:
                    return str(prepared["fingerprint"]) == operation_fingerprint
                if message.epoch < int(state["epoch"]) or message.generation < int(state["generation"]):
                    raise MutationError("stale replication state", 409)
                if not ControllerStore.replay_accept(cursor, envelope.key_id, envelope.nonce, envelope.sequence):
                    raise MutationError("replay or stale replication sequence", 401)
                if not ControllerStore.replay_accept(cursor, original.key_id, original.nonce, original.sequence):
                    raise MutationError("replay or stale mutation sequence", 401)
                ControllerStore.record_prepared(
                    cursor,
                    message.operation_id,
                    message.source_controller,
                    message.epoch,
                    message.generation,
                    kind,
                    payload,
                    envelope,
                    original,
                    operation_fingerprint,
                )
            return True
        except (AuthenticationError, MutationError, ValidationError, TypeError, ValueError) as exc:
            reason = exc.reason if isinstance(exc, (AuthenticationError, MutationError)) else "replication prepare failed"
            self._reject(reason, envelope)
            return False

    def commit_replication(self, operation_id: str) -> bool:
        try:
            with self._mutation_lock, self.store.transaction() as cursor:
                operation = ControllerStore.operation(cursor, operation_id)
                if operation is not None:
                    return str(operation["replication_state"]) == "committed"
                prepared = ControllerStore.prepared(cursor, operation_id)
                if prepared is None:
                    return False
                state = ControllerStore._state(cursor)
                if int(prepared["epoch"]) < int(state["epoch"]):
                    return False
                payload = json.loads(prepared["payload"])
                original = SignedEnvelope.model_validate(json.loads(prepared["original_envelope"]))
                generation = int(prepared["generation"])
                epoch = int(prepared["epoch"])
                if epoch > int(state["epoch"]):
                    ControllerStore.set_state_value(cursor, "role", "follower")
                    ControllerStore.set_state_value(cursor, "epoch", epoch)
                self._apply_payload_tx(cursor, str(prepared["kind"]), payload, original, generation)
                ControllerStore.record_operation(
                    cursor,
                    operation_id,
                    str(prepared["source_controller"]),
                    epoch,
                    generation,
                    str(prepared["fingerprint"]),
                )
                ControllerStore.delete_prepared(cursor, operation_id)
                if generation > int(state["generation"]):
                    ControllerStore.set_state_value(cursor, "generation", generation)
                ControllerStore.set_state_value(cursor, "last_replication_ack", operation_id)
                ControllerStore.set_state_value(cursor, "last_replication_generation", generation)
                ControllerStore.set_state_value(
                    cursor,
                    "last_replication_at",
                    self.now().astimezone(UTC).isoformat().replace("+00:00", "Z"),
                )
                self.store.append_event_tx(
                    cursor,
                    now=self.now(),
                    subsystem="replication",
                    severity="info",
                    subject="replication-applied",
                    detail={"sourceController": prepared["source_controller"], "operationId": operation_id},
                    operation_id=operation_id,
                )
            return True
        except (MutationError, ValidationError, TypeError, ValueError):
            return False

    def abort_replication(self, operation_id: str) -> None:
        with self._mutation_lock, self.store.transaction() as cursor:
            prepared = ControllerStore.prepared(cursor, operation_id)
            if prepared is None:
                return
            replication_envelope = SignedEnvelope.model_validate(json.loads(prepared["envelope"]))
            original = SignedEnvelope.model_validate(json.loads(prepared["original_envelope"]))
            ControllerStore.replay_remove(
                cursor,
                replication_envelope.key_id,
                replication_envelope.nonce,
                replication_envelope.sequence,
            )
            ControllerStore.replay_remove(cursor, original.key_id, original.nonce, original.sequence)
            ControllerStore.delete_prepared(cursor, operation_id)

    def apply_replication(self, message: ReplicationMessage, envelope: SignedEnvelope) -> bool:
        return self.prepare_replication(message, envelope) and self.commit_replication(message.operation_id)

    def apply_replication_control(self, action: str, envelope: SignedEnvelope) -> bool:
        try:
            self.authenticator.authenticate(envelope, "replication:write")
            payload = envelope.payload
            if payload.get("action") != action:
                raise MutationError("replication control action does not match route", 422)
            with self._mutation_lock, self.store.transaction() as cursor:
                if not ControllerStore.replay_accept(cursor, envelope.key_id, envelope.nonce, envelope.sequence):
                    raise MutationError("replay or stale replication sequence", 401)
            if action == "fence":
                epoch = self._expected(payload, "epoch")
                return epoch is not None and self.fence(epoch)
            operation_id = payload.get("operationId")
            if not isinstance(operation_id, str) or not operation_id:
                raise MutationError("operationId is required", 422)
            if action == "commit":
                return self.commit_replication(operation_id)
            if action == "abort":
                self.abort_replication(operation_id)
                return True
            raise MutationError("unknown replication control action", 422)
        except (AuthenticationError, MutationError) as exc:
            reason = exc.reason
            self._reject(reason, envelope)
            return False

    def recover_pending_operations(self) -> list[str]:
        recovered: list[str] = []
        with self._mutation_lock:
            for item in self.store.pending_outbox():
                message = ReplicationMessage.model_validate(item["message"])
                envelope = SignedEnvelope.model_validate(item["envelope"])
                if self.peer is None:
                    break
                prepared = self.peer.prepare_replication(message, envelope)
                if prepared and self._commit_peer(message):
                    recovered.append(message.operation_id)
        return recovered

    def outbound_sequence(self, key_id: str) -> int:
        return self.store.outbound_sequence(key_id)

    def fence(self, epoch: int) -> bool:
        with self._mutation_lock, self.store.transaction() as cursor:
            state = ControllerStore._state(cursor)
            current_epoch = int(state["epoch"])
            if epoch < current_epoch:
                return False
            if epoch == current_epoch and state["role"] == "follower":
                return True
            if bool(state.get("lag_degraded", False)):
                return False
            ControllerStore.set_state_value(cursor, "role", "follower")
            ControllerStore.set_state_value(cursor, "epoch", epoch)
            ControllerStore.set_state_value(cursor, "promotion_state", "fenced")
            self.store.append_event_tx(
                cursor,
                now=self.now(),
                subsystem="promotion",
                severity="critical",
                subject="controller-fenced",
                detail={"epoch": epoch, "controllerId": self.controller_id},
            )
            return True

    def promote(self, envelope: SignedEnvelope) -> dict[str, Any]:
        if self.observe_only:
            self._reject("controller is observe-only", envelope)
            raise MutationError("controller is observe-only", 409)
        try:
            self.authenticator.authenticate(envelope, "controller:promote")
            receipt = FencingReceipt.model_validate(envelope.payload.get("fencingReceipt"))
        except (AuthenticationError, ValidationError, TypeError) as exc:
            reason = exc.reason if isinstance(exc, AuthenticationError) else "invalid promotion request"
            self._reject(reason, envelope)
            raise MutationError(reason, 401 if isinstance(exc, AuthenticationError) else 422) from exc

        with self._mutation_lock:
            state = self.store.state()
            if state["role"] == "active":
                self._reject("controller is already active", envelope)
                raise MutationError("controller is already active", 409)
            if receipt.epoch <= int(state["epoch"]):
                self._reject("fencing epoch is not greater than local epoch", envelope)
                raise MutationError("fencing epoch is not greater than local epoch", 409)
            if not verify_fencing(self.fencing_verifier, receipt):
                self._reject("fencing receipt was rejected", envelope)
                raise MutationError("fencing receipt was rejected", 403)
            if self.peer is None or not self.peer.fence(receipt.epoch):
                self._reject("old active could not be fenced", envelope)
                raise MutationError("old active could not be fenced", 409)
            try:
                with self.store.transaction() as cursor:
                    state = ControllerStore._state(cursor)
                    if state["role"] == "active" or receipt.epoch <= int(state["epoch"]):
                        raise MutationError("promotion compare-and-swap failed", 409)
                    if not ControllerStore.replay_accept(cursor, envelope.key_id, envelope.nonce, envelope.sequence):
                        raise MutationError("replay or stale sequence", 401)
                    ControllerStore.set_state_value(cursor, "role", "active")
                    ControllerStore.set_state_value(cursor, "epoch", receipt.epoch)
                    ControllerStore.set_state_value(cursor, "promotion_state", "promoted")
                    self.store.append_event_tx(
                        cursor,
                        now=self.now(),
                        subsystem="promotion",
                        severity="critical",
                        subject="controller-promoted",
                        detail={"epoch": receipt.epoch, "controllerId": self.controller_id},
                    )
            except MutationError as exc:
                self._reject(exc.reason, envelope)
                raise
        state = self.store.state()
        return {"accepted": True, "role": state["role"], "epoch": state["epoch"]}

    def _lag(self) -> tuple[float | None, list[str]]:
        state = self.store.state()
        reasons: list[str] = []
        value = state.get("last_replication_at")
        lag: float | None = None
        if isinstance(value, str):
            acknowledged = datetime.fromisoformat(value)
            lag = max(0.0, (self.now().astimezone(UTC) - acknowledged.astimezone(UTC)).total_seconds())
            if lag > self.replication_lag_seconds:
                reasons.append("replication-lag")
        elif state["role"] == "active":
            reasons.append("replication-unconfigured" if self.peer is None else "replication-unacknowledged")
        if state["role"] == "follower":
            reasons.append("stale-epoch")
        if bool(state.get("lag_degraded", False)) and not reasons:
            reasons.append("replication-degraded")
        return lag, reasons

    def status(self) -> dict[str, Any]:
        state = self.store.state()
        lag, reasons = self._lag()
        hosts = self.store.hosts()
        return {
            "role": state["role"],
            "epoch": state["epoch"],
            "generation": state["generation"],
            "last_replication_ack": state.get("last_replication_ack"),
            "replication_lag_seconds": lag,
            "degraded_reasons": reasons,
            "promotion_state": state["promotion_state"],
            "hosts": sanitize(hosts),
            "quotas": sanitize(self.store.quotas()),
            "runway": sanitize(self.runway()),
            "observe_only": self.observe_only,
            "apply_receipts": sanitize(self.store.apply_receipts()),
            "action_targets": {
                "drained_hosts": sorted(
                    str(host.get("hostId", ""))
                    for host in hosts
                    if host.get("drained")
                ),
            },
        }

    def set_runway(self, estimates: list[dict[str, Any]]) -> None:
        self._runway = [dict(estimate) for estimate in estimates]

    def runway(self) -> list[dict[str, Any]]:
        return [dict(estimate) for estimate in self._runway]

    def health(self) -> dict[str, Any]:
        status = self.status()
        health = {
            key: status[key]
            for key in (
                "role",
                "epoch",
                "generation",
                "replication_lag_seconds",
                "degraded_reasons",
                "promotion_state",
            )
        }
        health["observe_only"] = self.observe_only
        return health

    def policy(self) -> dict[str, Any] | None:
        return self.store.policy()

    def events(self) -> list[dict[str, Any]]:
        return self.store.events()

    def rejected_events(self) -> int:
        return sum(event["subject"] == "mutation-rejected" for event in self.events())

    def replay_state(self) -> dict[str, Any]:
        return self.store.replay_state()

    def operation_count(self, operation_id: str) -> int:
        return self.store.operation_count(operation_id)

    def set_replication_ack(self, operation_id: str, generation: int, at: datetime) -> None:
        self.store.set_replication_ack(operation_id, generation, at)



def create_app(controller: Controller) -> FastAPI:
    """Create the controller HTTP application."""

    app = FastAPI(title="modelctl controller")
    mount_dashboard(app)
    from modelctl.controller.loops.runway_loop import RunwayLoop

    runway_loop = RunwayLoop(controller)
    read_token = FleetBearerToken(controller._fleet_token if hasattr(controller, "_fleet_token") else "")

    def require_read(authorization: str | None) -> None:
        if not read_token.check(authorization):
            raise HTTPException(status_code=401, detail="fleet bearer token required")

    def reject_observe_only(kind: str) -> None:
        if controller.observe_only:
            controller._reject_observe_only(kind)
            raise HTTPException(status_code=409, detail="controller is observe-only")

    def mutation(kind: str, scope: str) -> Callable[[Any], Any]:
        async def handler(body: JsonBody) -> dict[str, Any]:
            if kind not in {"host-report", "event", "quota"}:
                reject_observe_only(kind)
            try:
                return controller.receive_wire_mutation(kind, scope, body)
            except MutationError as exc:
                raise HTTPException(status_code=exc.status_code, detail=exc.reason) from exc

        return handler

    @app.get("/health")
    async def health(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        require_read(authorization)
        return controller.health()

    @app.get("/v1/status")
    async def status(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        require_read(authorization)
        return controller.status()

    @app.get("/v1/actions")
    async def actions(authorization: str | None = Header(default=None)) -> dict[str, Any]:
        require_read(authorization)
        return cast(dict[str, Any], controller.status()["action_targets"])

    @app.get("/v1/policy")
    async def policy(authorization: str | None = Header(default=None)) -> dict[str, Any] | None:
        require_read(authorization)
        return controller.policy()

    @app.get("/v1/runway")
    async def runway(authorization: str | None = Header(default=None)) -> list[dict[str, Any]]:
        require_read(authorization)
        result = runway_loop.run_once()
        if isinstance(result, list):
            return cast(list[dict[str, Any]], result)
        return controller.runway()

    for path, kind, scope in (
        ("/v1/host-reports", "host-report", "host:report"),
        ("/v1/events", "event", "event:write"),
        ("/v1/quota", "quota", "quota:write"),
        ("/v1/apply-receipts", "apply-receipt", "adapter:write"),
        ("/v1/policies", "policy", "policy:write"),
    ):
        app.add_api_route(path, mutation(kind, scope), methods=["POST"])

    @app.post("/v1/replication/prepare")
    async def replication_prepare(body: JsonBody) -> dict[str, Any]:
        reject_observe_only("replication-prepare")
        try:
            envelope = SignedEnvelope.model_validate(body)
            message = ReplicationMessage.model_validate(envelope.payload)
        except (ValidationError, TypeError) as exc:
            controller._reject("invalid replication envelope", None)
            raise HTTPException(status_code=422, detail="invalid replication envelope") from exc
        if controller.prepare_replication(message, envelope):
            return {"accepted": True, "operationId": message.operation_id}
        raise HTTPException(status_code=409, detail="replication prepare rejected")

    def replication_control(action: str) -> Callable[[Any], Any]:
        async def handler(body: JsonBody) -> dict[str, Any]:
            reject_observe_only(f"replication-{action}")
            try:
                envelope = SignedEnvelope.model_validate(body)
            except (ValidationError, TypeError) as exc:
                controller._reject("invalid replication control envelope", None)
                raise HTTPException(status_code=422, detail="invalid replication control envelope") from exc
            if controller.apply_replication_control(action, envelope):
                return {"accepted": True}
            raise HTTPException(status_code=409, detail=f"replication {action} rejected")

        return handler

    for action in ("commit", "abort", "fence"):
        app.add_api_route(
            f"/v1/replication/{action}",
            replication_control(action),
            methods=["POST"],
        )

    @app.post("/v1/promote")
    async def promote(body: JsonBody) -> dict[str, Any]:
        reject_observe_only("promote")
        try:
            envelope = SignedEnvelope.model_validate(body)
            return controller.promote(envelope)
        except MutationError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.reason) from exc

    return app
