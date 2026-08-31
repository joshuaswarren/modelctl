"""SQLite WAL persistence for controller state."""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

from modelctl.policy.signing import SignedEnvelope, bundle_id


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _load(value: str) -> Any:
    return json.loads(value)


def _utc_text(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a UTC offset")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def fingerprint(value: Any) -> str:
    return hashlib.sha256(_json(value).encode("utf-8")).hexdigest()


def envelope_fingerprint(envelope: SignedEnvelope) -> str:
    return fingerprint(envelope.model_dump(mode="json", by_alias=True))


def sanitize(value: Any, key: str | None = None) -> Any:
    """Remove secrets and private fields from data returned by the controller."""

    sensitive = {
        "authorization",
        "apikey",
        "password",
        "privatekey",
        "secret",
        "secretkey",
        "token",
        "bearertoken",
        "accesstoken",
        "refreshtoken",
        "signingkey",
    }
    if key is not None and key.lower().replace("-", "").replace("_", "") in sensitive:
        return "[redacted]"
    if isinstance(value, Mapping):
        return {str(name): sanitize(item, str(name)) for name, item in value.items()}
    if isinstance(value, list):
        return [sanitize(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize(item) for item in value]
    return value


class ControllerStore:
    """Single SQLite connection with explicit immediate write transactions."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path) if str(path) != ":memory:" else Path(":memory:")
        self._connection = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        self._initialize()

    def _initialize(self) -> None:
        statements = (
            "CREATE TABLE IF NOT EXISTS state (name TEXT PRIMARY KEY, value TEXT NOT NULL)",
            ("CREATE TABLE IF NOT EXISTS replay_nonces "
             "(nonce TEXT PRIMARY KEY, key_id TEXT NOT NULL, sequence INTEGER NOT NULL)"),
            "CREATE TABLE IF NOT EXISTS replay_sequences (key_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL)",
            ("CREATE TABLE IF NOT EXISTS outbound_sequences "
             "(key_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL)"),
            ("CREATE TABLE IF NOT EXISTS events "
             "(event_id TEXT PRIMARY KEY, time TEXT NOT NULL, subsystem TEXT NOT NULL, "
             "severity TEXT NOT NULL, subject TEXT NOT NULL, detail TEXT NOT NULL, operation_id TEXT)"),
            ("CREATE TABLE IF NOT EXISTS operations "
             "(operation_id TEXT PRIMARY KEY, source_controller TEXT NOT NULL, epoch INTEGER NOT NULL, "
             "generation INTEGER NOT NULL, fingerprint TEXT NOT NULL DEFAULT '', "
             "replication_state TEXT NOT NULL DEFAULT 'committed')"),
            ("CREATE TABLE IF NOT EXISTS prepared_operations "
             "(operation_id TEXT PRIMARY KEY, source_controller TEXT NOT NULL, epoch INTEGER NOT NULL, "
             "generation INTEGER NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL, envelope TEXT NOT NULL, "
             "original_envelope TEXT NOT NULL DEFAULT '', fingerprint TEXT NOT NULL)"),
            ("CREATE TABLE IF NOT EXISTS replication_outbox "
             "(operation_id TEXT PRIMARY KEY, message TEXT NOT NULL, envelope TEXT NOT NULL, "
             "fingerprint TEXT NOT NULL)"),
            ("CREATE TABLE IF NOT EXISTS host_reports "
             "(host_id TEXT PRIMARY KEY, payload TEXT NOT NULL, drained INTEGER NOT NULL, updated_at TEXT NOT NULL)"),
            "CREATE TABLE IF NOT EXISTS quotas (record_id TEXT PRIMARY KEY, payload TEXT NOT NULL, updated_at TEXT NOT NULL)",
            ("CREATE TABLE IF NOT EXISTS apply_receipts "
             "(record_id TEXT PRIMARY KEY, payload TEXT NOT NULL, updated_at TEXT NOT NULL)"),
            ("CREATE TABLE IF NOT EXISTS policy_bundles "
             "(generation INTEGER PRIMARY KEY, bundle_id TEXT NOT NULL, envelope TEXT NOT NULL, "
             "created_at TEXT NOT NULL)"),
        )
        with self.transaction() as cursor:
            for statement in statements:
                cursor.execute(statement)
            columns = {row["name"] for row in cursor.execute("PRAGMA table_info(operations)")}
            if "fingerprint" not in columns:
                cursor.execute("ALTER TABLE operations ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''")
            if "replication_state" not in columns:
                cursor.execute("ALTER TABLE operations ADD COLUMN replication_state TEXT NOT NULL DEFAULT 'committed'")
            prepared_columns = {row["name"] for row in cursor.execute("PRAGMA table_info(prepared_operations)")}
            if "original_envelope" not in prepared_columns:
                cursor.execute("ALTER TABLE prepared_operations ADD COLUMN original_envelope TEXT NOT NULL DEFAULT ''")

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Cursor]:
        with self._lock:
            cursor = self._connection.cursor()
            cursor.execute("BEGIN IMMEDIATE")
            try:
                yield cursor
            except BaseException:
                self._connection.rollback()
                raise
            else:
                self._connection.commit()

    @staticmethod
    def _state(cursor: sqlite3.Cursor) -> dict[str, Any]:
        rows = cursor.execute("SELECT name, value FROM state").fetchall()
        return {row["name"]: _load(row["value"]) for row in rows}

    def initialize_state(self, *, role: str, epoch: int) -> None:
        with self.transaction() as cursor:
            defaults = {
                "role": role,
                "epoch": epoch,
                "generation": 0,
                "last_replication_ack": None,
                "last_replication_at": None,
                "promotion_state": "unpromoted",
                "lag_degraded": False,
            }
            for name, value in defaults.items():
                cursor.execute("INSERT OR IGNORE INTO state(name, value) VALUES (?, ?)", (name, _json(value)))

    def state(self) -> dict[str, Any]:
        with self._lock:
            return self._state(self._connection.cursor())

    @staticmethod
    def set_state_value(cursor: sqlite3.Cursor, name: str, value: Any) -> None:
        cursor.execute("INSERT OR REPLACE INTO state(name, value) VALUES (?, ?)", (name, _json(value)))

    @staticmethod
    def replay_accept(cursor: sqlite3.Cursor, key_id: str, nonce: str, sequence: int) -> bool:
        if cursor.execute("SELECT 1 FROM replay_nonces WHERE nonce = ?", (nonce,)).fetchone() is not None:
            return False
        row = cursor.execute("SELECT sequence FROM replay_sequences WHERE key_id = ?", (key_id,)).fetchone()
        if row is not None and sequence <= int(row["sequence"]):
            return False
        cursor.execute("INSERT INTO replay_nonces(nonce, key_id, sequence) VALUES (?, ?, ?)", (nonce, key_id, sequence))
        cursor.execute("INSERT OR REPLACE INTO replay_sequences(key_id, sequence) VALUES (?, ?)", (key_id, sequence))
        return True

    @staticmethod
    def replay_remove(cursor: sqlite3.Cursor, key_id: str, nonce: str, sequence: int) -> None:
        cursor.execute(
            "DELETE FROM replay_nonces WHERE nonce = ? AND key_id = ? AND sequence = ?",
            (nonce, key_id, sequence),
        )
        row = cursor.execute(
            "SELECT MAX(sequence) AS sequence FROM replay_nonces WHERE key_id = ?", (key_id,)
        ).fetchone()
        if row["sequence"] is None:
            cursor.execute("DELETE FROM replay_sequences WHERE key_id = ?", (key_id,))
        else:
            cursor.execute("UPDATE replay_sequences SET sequence = ? WHERE key_id = ?", (row["sequence"], key_id))

    @staticmethod
    def next_outbound_sequence(cursor: sqlite3.Cursor, key_id: str) -> int:
        row = cursor.execute("SELECT sequence FROM outbound_sequences WHERE key_id = ?", (key_id,)).fetchone()
        sequence = 1 if row is None else int(row["sequence"]) + 1
        cursor.execute("INSERT OR REPLACE INTO outbound_sequences(key_id, sequence) VALUES (?, ?)", (key_id, sequence))
        return sequence


    def outbound_sequence(self, key_id: str) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT sequence FROM outbound_sequences WHERE key_id = ?",
                (key_id,),
            ).fetchone()
        return 0 if row is None else int(row["sequence"])

    @staticmethod
    def append_event_tx(
        cursor: sqlite3.Cursor,
        *,
        now: datetime,
        subsystem: str,
        severity: str,
        subject: str,
        detail: Mapping[str, Any] | None = None,
        operation_id: str | None = None,
    ) -> str:
        event_id = uuid4().hex
        cursor.execute(
            "INSERT INTO events(event_id, time, subsystem, severity, subject, detail, operation_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (event_id, _utc_text(now), subsystem, severity, subject, _json(sanitize(dict(detail or {}))), operation_id),
        )
        return event_id

    def append_event(
        self,
        *,
        now: datetime,
        subsystem: str,
        severity: str,
        subject: str,
        detail: Mapping[str, Any] | None = None,
        operation_id: str | None = None,
    ) -> str:
        with self.transaction() as cursor:
            return self.append_event_tx(
                cursor,
                now=now,
                subsystem=subsystem,
                severity=severity,
                subject=subject,
                detail=detail,
                operation_id=operation_id,
            )

    def rejected(self, *, now: datetime, reason: str, detail: Mapping[str, Any] | None = None) -> str:
        data = {"reason": reason, **dict(detail or {})}
        return self.append_event(
            now=now,
            subsystem="controller",
            severity="warning",
            subject="mutation-rejected",
            detail=data,
        )

    @staticmethod
    def operation(cursor: sqlite3.Cursor, operation_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            cursor.execute(
                "SELECT operation_id, source_controller, epoch, generation, fingerprint, replication_state "
                "FROM operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone(),
        )

    @staticmethod
    def prepared(cursor: sqlite3.Cursor, operation_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            cursor.execute(
                "SELECT operation_id, source_controller, epoch, generation, kind, payload, envelope, "
                "original_envelope, fingerprint FROM prepared_operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone(),
        )

    @staticmethod
    def outbox(cursor: sqlite3.Cursor, operation_id: str) -> sqlite3.Row | None:
        return cast(
            sqlite3.Row | None,
            cursor.execute(
                "SELECT operation_id, message, envelope, fingerprint FROM replication_outbox WHERE operation_id = ?",
                (operation_id,),
            ).fetchone(),
        )


    def pending_outbox(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT operation_id, message, envelope, fingerprint "
                "FROM replication_outbox ORDER BY rowid"
            ).fetchall()
        return [
            {
                "operationId": row["operation_id"],
                "message": _load(row["message"]),
                "envelope": _load(row["envelope"]),
                "fingerprint": row["fingerprint"],
            }
            for row in rows
        ]


    @staticmethod
    def record_prepared(
        cursor: sqlite3.Cursor,
        operation_id: str,
        source_controller: str,
        epoch: int,
        generation: int,
        kind: str,
        payload: Mapping[str, Any],
        replication_envelope: SignedEnvelope,
        original_envelope: SignedEnvelope,
        operation_fingerprint: str,
    ) -> None:
        cursor.execute(
            "INSERT OR REPLACE INTO prepared_operations("
            "operation_id, source_controller, epoch, generation, kind, payload, envelope, original_envelope, fingerprint) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                operation_id,
                source_controller,
                epoch,
                generation,
                kind,
                _json(dict(payload)),
                _json(replication_envelope.model_dump(mode="json", by_alias=True)),
                _json(original_envelope.model_dump(mode="json", by_alias=True)),
                operation_fingerprint,
            ),
        )

    @staticmethod
    def delete_prepared(cursor: sqlite3.Cursor, operation_id: str) -> None:
        cursor.execute("DELETE FROM prepared_operations WHERE operation_id = ?", (operation_id,))

    @staticmethod
    def record_operation(
        cursor: sqlite3.Cursor,
        operation_id: str,
        source_controller: str,
        epoch: int,
        generation: int,
        operation_fingerprint: str,
        replication_state: str = "committed",
    ) -> None:
        cursor.execute(
            "INSERT INTO operations(operation_id, source_controller, epoch, generation, fingerprint, replication_state) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (operation_id, source_controller, epoch, generation, operation_fingerprint, replication_state),
        )

    @staticmethod
    def record_outbox(
        cursor: sqlite3.Cursor,
        operation_id: str,
        message: Mapping[str, Any],
        envelope: SignedEnvelope,
        operation_fingerprint: str,
    ) -> None:
        cursor.execute(
            "INSERT OR REPLACE INTO replication_outbox(operation_id, message, envelope, fingerprint) VALUES (?, ?, ?, ?)",
            (
                operation_id,
                _json(dict(message)),
                _json(envelope.model_dump(mode="json", by_alias=True)),
                operation_fingerprint,
            ),
        )

    @staticmethod
    def mark_replicated(cursor: sqlite3.Cursor, operation_id: str) -> None:
        cursor.execute(
            "UPDATE operations SET replication_state = 'committed' WHERE operation_id = ?", (operation_id,)
        )
        cursor.execute("DELETE FROM replication_outbox WHERE operation_id = ?", (operation_id,))

    @staticmethod
    def put_host(cursor: sqlite3.Cursor, payload: Mapping[str, Any], now: datetime) -> None:
        host_id = str(payload.get("hostId", payload.get("host_id", "")))
        if not host_id:
            raise ValueError("hostId is required")
        drained = str(payload.get("health", "healthy")).lower() in {"failed", "unhealthy", "offline"}
        cursor.execute(
            "INSERT OR REPLACE INTO host_reports(host_id, payload, drained, updated_at) VALUES (?, ?, ?, ?)",
            (host_id, _json(sanitize(dict(payload))), int(drained), _utc_text(now)),
        )

    @staticmethod
    def put_record(cursor: sqlite3.Cursor, table: str, payload: Mapping[str, Any], now: datetime) -> None:
        record_id = str(payload.get("recordId", payload.get("id", uuid4().hex)))
        if table not in {"quotas", "apply_receipts"}:
            raise ValueError("invalid record table")
        cursor.execute(
            f"INSERT OR REPLACE INTO {table}(record_id, payload, updated_at) VALUES (?, ?, ?)",
            (record_id, _json(sanitize(dict(payload))), _utc_text(now)),
        )

    @staticmethod
    def put_policy(cursor: sqlite3.Cursor, envelope: SignedEnvelope, generation: int, now: datetime) -> None:
        wire = envelope.model_dump(mode="json", by_alias=True)
        cursor.execute(
            "INSERT INTO policy_bundles(generation, bundle_id, envelope, created_at) VALUES (?, ?, ?, ?)",
            (generation, bundle_id(envelope.payload), _json(wire), _utc_text(now)),
        )

    def policy(self) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT envelope FROM policy_bundles ORDER BY generation DESC LIMIT 1"
            ).fetchone()
        return None if row is None else _load(row["envelope"])

    def _rows(self, table: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(f"SELECT payload FROM {table} ORDER BY updated_at, record_id").fetchall()
        return [_load(row["payload"]) for row in rows]

    def hosts(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT host_id, payload, drained FROM host_reports ORDER BY host_id"
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            payload = _load(row["payload"])
            payload["drained"] = bool(row["drained"])
            result.append(payload)
        return result

    def quotas(self) -> list[dict[str, Any]]:
        return self._rows("quotas")

    def apply_receipts(self) -> list[dict[str, Any]]:
        return self._rows("apply_receipts")

    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT event_id, time, subsystem, severity, subject, detail, operation_id "
                "FROM events ORDER BY rowid"
            ).fetchall()
        return [
            {
                "id": row["event_id"],
                "time": row["time"],
                "subsystem": row["subsystem"],
                "severity": row["severity"],
                "subject": row["subject"],
                "detail": _load(row["detail"]),
                "operationId": row["operation_id"],
            }
            for row in rows
        ]

    def replay_state(self) -> dict[str, Any]:
        with self._lock:
            nonces = [
                row["nonce"]
                for row in self._connection.execute("SELECT nonce FROM replay_nonces ORDER BY rowid")
            ]
            sequences = {
                row["key_id"]: row["sequence"]
                for row in self._connection.execute(
                    "SELECT key_id, sequence FROM replay_sequences ORDER BY key_id"
                )
            }
        return {"nonces": nonces, "sequences": sequences}

    def operation_count(self, operation_id: str) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT COUNT(*) AS count FROM operations WHERE operation_id = ?",
                (operation_id,),
            ).fetchone()
        return int(row["count"])

    def set_replication_ack(self, operation_id: str, generation: int, at: datetime) -> None:
        with self.transaction() as cursor:
            self.set_state_value(cursor, "last_replication_ack", operation_id)
            self.set_state_value(cursor, "last_replication_generation", generation)
            self.set_state_value(cursor, "last_replication_at", _utc_text(at))

    def set_lag_degraded(self, degraded: bool) -> bool:
        with self.transaction() as cursor:
            state = self._state(cursor)
            previous = bool(state.get("lag_degraded", False))
            self.set_state_value(cursor, "lag_degraded", degraded)
            return previous != degraded

    def close(self) -> None:
        with self._lock:
            self._connection.close()
