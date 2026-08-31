"""Forward signed OMP extension events to both controllers."""
from __future__ import annotations

import json
import os
import re
import threading
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO, Protocol
from urllib.parse import urlsplit
from uuid import uuid4

import yaml
from pydantic import Field, field_validator, model_validator

from modelctl.agents.host.report import (
    EventStore,
    ReportSequenceStore,
    _atomic_json_write,
)
from modelctl.agents.host.transport import HttpResponse, UrllibTransport
from modelctl.domain.events import Event, EventSeverity
from modelctl.policy.signing import PolicySigner, SignedEnvelope
from modelctl.telemetry.config_support import (
    load_ed25519_signer,
    load_mtls_context,
    positive_number,
    require_mapping,
    require_text,
    resolve_path,
)


class PostTransport(Protocol):
    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> HttpResponse: ...


DEFAULT_EVENT_PATH = Path.home() / ".omp" / "logs" / "modelctl-events.jsonl"
_DEFAULT_STATE_DIRECTORY = DEFAULT_EVENT_PATH.parent

_SECRET_FIELD_NAMES = {
    "accesstoken",
    "apikey",
    "authorization",
    "bearertoken",
    "cookie",
    "credential",
    "password",
    "privatekey",
    "refreshtoken",
    "secret",
    "secretkey",
    "signingkey",
    "token",
}
_IDENTITY_FIELD_NAMES = {
    "accountemail",
    "accountid",
    "accountidentifier",
    "email",
    "rawaccountid",
    "userid",
    "useremail",
}
_EMAIL_VALUE_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_SECRET_VALUE_RE = re.compile(
    r"(?i)(?:-----BEGIN [A-Z ]+ PRIVATE KEY-----|\b(?:sk|ghp|github_pat|AKIA)[A-Za-z0-9_-]{8,})"
)


class ExtensionEvent(Event):
    """Validated Python representation of the OMP ExtensionEvent contract."""

    detail: dict[str, Any] = Field(default_factory=dict)

    @field_validator("detail", mode="before")
    @classmethod
    def validate_detail_shape(cls, value: Any) -> dict[str, Any]:
        if not isinstance(value, Mapping):
            raise TypeError("event detail must be an object")
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("event detail keys must be strings")
            if isinstance(item, list):
                if not all(isinstance(element, str) for element in item):
                    raise TypeError("event detail arrays must contain strings")
            elif item is not None and type(item) not in {str, int, float, bool}:
                raise TypeError("event detail values must be JSON primitives or string arrays")
        return dict(value)

    @model_validator(mode="after")
    def reject_secrets(self) -> ExtensionEvent:
        values: list[tuple[str, str]] = [
            ("id", self.id),
            ("subsystem", self.subsystem),
            ("subject", self.subject),
        ]
        for key, item in self.detail.items():
            values.append((key, key))
            if isinstance(item, str):
                values.append((key, item))
            elif isinstance(item, list):
                values.extend((key, element) for element in item)
        for name, value in values:
            normalized_name = re.sub(r"[^a-z0-9]", "", name.casefold())
            if normalized_name in _IDENTITY_FIELD_NAMES or _EMAIL_VALUE_RE.fullmatch(value):
                raise ValueError("event contains raw identity")
            if normalized_name in _SECRET_FIELD_NAMES or _SECRET_VALUE_RE.search(value):
                raise ValueError("event contains a secret")
        return self


@dataclass(frozen=True)
class ForwardResult:
    """Outcome of one forward pass."""

    forwarded: int
    failed: int
    cursor: int
    pending: bool


class EventForwarder:
    """Read, sign, persist, and forward local ExtensionEvent records."""

    def __init__(
        self,
        *,
        signer: PolicySigner,
        controllers: Sequence[str],
        sequence_store: ReportSequenceStore,
        transport: PostTransport,
        event_sink: Callable[[Event], None],
        events_path: Path = DEFAULT_EVENT_PATH,
        cursor_path: Path | None = None,
        pending_path: Path | None = None,
        now: Callable[[], datetime] | None = None,
        ttl: timedelta = timedelta(minutes=5),
    ) -> None:
        if not isinstance(signer, PolicySigner):
            raise TypeError("signer must be a PolicySigner")
        if ttl <= timedelta(0):
            raise ValueError("event envelope ttl must be positive")
        endpoints = list(dict.fromkeys(self._endpoint(value) for value in controllers))
        if not endpoints:
            raise ValueError("at least one controller is required")
        self.signer = signer
        self.controllers = endpoints
        self.sequence_store = sequence_store
        self.transport = transport
        self.event_sink = event_sink
        self.events_path = events_path.expanduser()
        self.cursor_path = (cursor_path or _DEFAULT_STATE_DIRECTORY / "modelctl-events.cursor.json").expanduser()
        self.pending_path = (pending_path or _DEFAULT_STATE_DIRECTORY / "modelctl-events.pending.json").expanduser()
        self.now = now or (lambda: datetime.now(UTC))
        self.ttl = ttl
        self._lock = threading.Lock()

    @staticmethod
    def _endpoint(value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError(f"controller URL is invalid: {value}")
        if parsed.path.rstrip("/") == "/v1/events":
            return value.rstrip("/")
        if parsed.path not in {"", "/"}:
            raise ValueError(f"controller URL has an unsupported path: {value}")
        return f"{value.rstrip('/')}/v1/events"

    def _load_cursor(self) -> int:
        if not self.cursor_path.exists():
            return 0
        try:
            value: Any = json.loads(self.cursor_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid event cursor at {self.cursor_path}") from exc
        if not isinstance(value, dict):
            raise TypeError(f"invalid event cursor at {self.cursor_path}")
        cursor = value.get("cursor")
        if isinstance(cursor, bool) or not isinstance(cursor, int) or cursor < 0:
            raise ValueError(f"invalid event cursor at {self.cursor_path}")
        return cursor

    def _save_cursor(self, cursor: int) -> None:
        _atomic_json_write(self.cursor_path, {"cursor": cursor})

    def _load_pending(self) -> tuple[int, SignedEnvelope, bytes] | None:
        if not self.pending_path.exists():
            return None
        try:
            value: Any = json.loads(self.pending_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid pending event at {self.pending_path}") from exc
        if not isinstance(value, dict):
            raise TypeError(f"invalid pending event at {self.pending_path}")
        cursor = value.get("cursor")
        body_value = value.get("body")
        if isinstance(cursor, bool) or not isinstance(cursor, int) or cursor < 0 or not isinstance(body_value, str):
            raise ValueError(f"invalid pending event at {self.pending_path}")
        body = body_value.encode("utf-8")
        try:
            envelope = SignedEnvelope.model_validate(json.loads(body))
            persisted = SignedEnvelope.model_validate(value["envelope"])
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid pending event at {self.pending_path}") from exc
        if envelope.model_dump(mode="json", by_alias=True) != persisted.model_dump(mode="json", by_alias=True):
            raise ValueError(f"pending event envelope mismatch at {self.pending_path}")
        return cursor, envelope, body

    def _save_pending(self, cursor: int, envelope: SignedEnvelope, body: bytes) -> None:
        _atomic_json_write(
            self.pending_path,
            {
                "cursor": cursor,
                "envelope": envelope.model_dump(mode="json", by_alias=True),
                "body": body.decode("utf-8"),
            },
        )

    def _clear_pending(self) -> None:
        try:
            self.pending_path.unlink()
        except FileNotFoundError:
            return
        directory_descriptor = os.open(self.pending_path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)

    def _next_sequence(self) -> int:
        sequence = self.sequence_store.load() + 1
        self.sequence_store.commit(sequence)
        return sequence

    def _sign(self, event: ExtensionEvent) -> SignedEnvelope:
        issued_at = self.now()
        if issued_at.tzinfo is None or issued_at.utcoffset() is None:
            raise ValueError("event forwarder clock must include a UTC offset")
        return self.signer.sign(
            event.model_dump(mode="json"),
            issued_at=issued_at.astimezone(UTC),
            sequence=self._next_sequence(),
            ttl=self.ttl,
        )

    def _emit_failure(self, subject: str, detail: dict[str, Any]) -> None:
        self.event_sink(
            Event(
                id=uuid4().hex,
                time=self.now(),
                subsystem="event-forwarder",
                severity=EventSeverity.ERROR,
                subject=subject,
                detail=detail,
            )
        )

    def _deliver(self, envelope: SignedEnvelope, body: bytes) -> tuple[bool, int]:
        accepted = False
        failed = 0
        for index, controller in enumerate(self.controllers):
            try:
                response = self.transport.post(
                    controller,
                    body,
                    {"content-type": "application/json", "x-modelctl-kind": "event"},
                )
                if 200 <= response.status_code < 300:
                    accepted = True
                else:
                    failed += 1
                    self._emit_failure(
                        "event-delivery-failed",
                        {"controller": index, "sequence": envelope.sequence, "reason": f"http-{response.status_code}"},
                    )
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                failed += 1
                self._emit_failure(
                    "event-delivery-failed",
                    {"controller": index, "sequence": envelope.sequence, "reason": type(exc).__name__},
                )
        return accepted, failed

    @staticmethod
    def _reject_json_constant(value: str) -> Any:
        raise ValueError(f"invalid JSON constant: {value}")

    def _read_event(self, raw_line: bytes, line_number: int) -> ExtensionEvent:
        try:
            text = raw_line.decode("utf-8").rstrip("\r\n")
            value = json.loads(text, parse_constant=self._reject_json_constant)
            return ExtensionEvent.model_validate(value)
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
            self._emit_failure(
                "event-parse-failed",
                {"line": line_number, "reason": "invalid-extension-event"},
            )
            raise ValueError("invalid extension event") from exc

    @staticmethod
    def _line_number(handle: BinaryIO, cursor: int) -> int:
        handle.seek(0)
        line_number = handle.read(cursor).count(b"\n") + 1
        handle.seek(cursor)
        return line_number

    def forward(self) -> ForwardResult:
        """Forward available events and retain every unaccepted envelope for retry."""

        with self._lock:
            cursor = self._load_cursor()
            forwarded = 0
            failed = 0
            pending = self._load_pending()
            if pending is not None:
                pending_cursor, envelope, body = pending
                accepted, delivery_failures = self._deliver(envelope, body)
                failed += delivery_failures
                if not accepted:
                    return ForwardResult(forwarded, failed, cursor, True)
                if pending_cursor > cursor:
                    self._save_cursor(pending_cursor)
                    cursor = pending_cursor
                self._clear_pending()
                forwarded += 1

            if not self.events_path.exists():
                return ForwardResult(forwarded, failed, cursor, False)

            file_size = self.events_path.stat().st_size
            if cursor > file_size:
                raise ValueError("event cursor is beyond the event log")
            with self.events_path.open("rb") as handle:
                if cursor and not self._cursor_is_line_boundary(handle, cursor):
                    raise ValueError("event cursor is not at a line boundary")
                line_number = self._line_number(handle, cursor)
                while True:
                    raw_line = handle.readline()
                    if not raw_line:
                        break
                    next_cursor = handle.tell()
                    try:
                        event = self._read_event(raw_line, line_number)
                    except ValueError:
                        failed += 1
                        break
                    envelope = self._sign(event)
                    body = envelope.model_dump_json(by_alias=True).encode("utf-8")
                    self._save_pending(next_cursor, envelope, body)
                    accepted, delivery_failures = self._deliver(envelope, body)
                    failed += delivery_failures
                    if not accepted:
                        return ForwardResult(forwarded, failed, cursor, True)
                    self._save_cursor(next_cursor)
                    cursor = next_cursor
                    self._clear_pending()
                    forwarded += 1
                    line_number += 1

            return ForwardResult(forwarded, failed, cursor, self.pending_path.exists())

    @staticmethod
    def _cursor_is_line_boundary(handle: BinaryIO, cursor: int) -> bool:
        handle.seek(cursor - 1)
        return handle.read(1) == b"\n"


def load_event_forwarder_config(
    path: Path,
    *,
    transport: PostTransport | None = None,
    now: Callable[[], datetime] | None = None,
) -> EventForwarder:
    """Load one production event forwarder from strict YAML configuration."""

    try:
        value: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValueError(f"could not load event forwarder config at {path}") from exc
    root = require_mapping(value, "event forwarder config")
    controllers = root.get("controllers")
    if not isinstance(controllers, list) or not controllers:
        raise ValueError("controllers must be a nonempty list")
    controller_values = [require_text(item, "controller") for item in controllers]
    timeout = positive_number(root.get("timeoutSeconds"), "timeoutSeconds", 10.0)
    ttl_seconds = positive_number(root.get("recordTtlSeconds"), "recordTtlSeconds", 300.0)
    ssl_context = load_mtls_context(path, root.get("tls"))
    events_path = resolve_path(path, root.get("eventsPath", str(DEFAULT_EVENT_PATH)), "eventsPath")
    state_directory = events_path.parent
    return EventForwarder(
        signer=load_ed25519_signer(path, require_mapping(root.get("signing"), "signing")),
        controllers=controller_values,
        sequence_store=ReportSequenceStore(
            resolve_path(
                path,
                root.get("sequencePath", str(state_directory / "sequence.json")),
                "sequencePath",
            )
        ),
        transport=transport or UrllibTransport(timeout=timeout, ssl_context=ssl_context),
        event_sink=EventStore(
            resolve_path(
                path,
                root.get(
                    "localEventsPath",
                    str(state_directory / "forwarder-errors.jsonl"),
                ),
                "localEventsPath",
            )
        ).append,
        events_path=events_path,
        cursor_path=resolve_path(
            path,
            root.get("cursorPath", str(state_directory / "cursor.json")),
            "cursorPath",
        ),
        pending_path=resolve_path(
            path,
            root.get("pendingPath", str(state_directory / "pending.json")),
            "pendingPath",
        ),
        now=now,
        ttl=timedelta(seconds=ttl_seconds),
    )


__all__ = [
    "DEFAULT_EVENT_PATH",
    "EventForwarder",
    "ExtensionEvent",
    "ForwardResult",
    "load_event_forwarder_config",
]
