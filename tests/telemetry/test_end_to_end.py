from __future__ import annotations

import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from modelctl.agents.host.transport import HttpResponse
from modelctl.controller.api import Controller, create_app
from modelctl.controller.auth import PrincipalRegistry
from modelctl.controller.loops.runway_loop import RunwayLoop
from modelctl.policy.signing import PolicySigner, SignedEnvelope
from modelctl.telemetry import QuotaRecord, QuotaSourceClass
from modelctl.telemetry.collector_client import load_collector_config

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
TOKEN = "fleet-test-token"


class RecordingTransport:
    def __init__(self) -> None:
        self.posts: list[tuple[str, bytes, Mapping[str, str]]] = []

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> HttpResponse:
        self.posts.append((url, body, headers))
        return HttpResponse(200, {"accepted": True})


def write_private_key(path: Path, key: ed25519.Ed25519PrivateKey) -> None:
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(path, 0o600)


class ControllerTransport:
    def __init__(self, clients: Mapping[str, TestClient]) -> None:
        self.clients = clients

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> HttpResponse:
        parsed = urlsplit(url)
        response = self.clients[parsed.netloc].post(
            parsed.path,
            json=json.loads(body),
            headers=dict(headers),
        )
        return HttpResponse(response.status_code, response.json())


def test_collector_config_reads_sources_and_posts_signed_records(tmp_path: Path) -> None:
    private_key = ed25519.Ed25519PrivateKey.generate()
    key_path = tmp_path / "collector.pem"
    write_private_key(key_path, private_key)
    (tmp_path / "provider.json").write_text(
        json.dumps(
            [
                {
                    "provider": "provider-a",
                    "accountLabel": "primary",
                    "quotaUsed": 10,
                    "resetTime": (NOW + timedelta(days=1)).isoformat(),
                    "capturedAt": NOW.isoformat(),
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "dashboard.json").write_text(
        json.dumps(
            [
                {
                    "provider": "provider-b",
                    "accountLabel": "secondary",
                    "quotaUsed": 20,
                    "resetTime": (NOW + timedelta(days=2)).isoformat(),
                    "capturedAt": (NOW - timedelta(hours=6)).isoformat(),
                }
            ]
        ),
        encoding="utf-8",
    )
    config_path = tmp_path / "collector.yaml"
    config_path.write_text(
        "\n".join(
            [
                "signing:",
                "  keyId: quota-writer",
                f"  privateKeyPath: {key_path.name}",
                "controllers:",
                "  - https://active.example",
                "  - https://standby.example/v1/quota",
                "sequencePath: quota-sequence.json",
                "sources:",
                "  - path: provider.json",
                "    sourceClass: provider-derived",
                "  - path: dashboard.json",
                "    sourceClass: delayed-dashboard",
                "timeoutSeconds: 2",
                "recordTtlSeconds: 300",
            ]
        ),
        encoding="utf-8",
    )
    transport = RecordingTransport()

    client, records = load_collector_config(config_path, transport=transport, now=lambda: NOW)
    results = client.publish(records)

    assert [record.source_class for record in records] == [
        QuotaSourceClass.PROVIDER_DERIVED,
        QuotaSourceClass.DELAYED_DASHBOARD,
    ]
    assert len(results) == 2
    assert len(transport.posts) == 4
    assert {post[0] for post in transport.posts} == {
        "https://active.example/v1/quota",
        "https://standby.example/v1/quota",
    }
    first = SignedEnvelope.model_validate_json(transport.posts[0][1])
    assert first.key_id == "quota-writer"
    assert first.payload["accountLabel"] == "primary"
    assert "email" not in json.dumps(first.payload).lower()

def test_collector_posts_through_signed_controller_boundary_into_runway(tmp_path: Path) -> None:
    collector_private = ed25519.Ed25519PrivateKey.generate()
    replication_private = ed25519.Ed25519PrivateKey.generate()
    registry = PrincipalRegistry()
    registry.register("quota-writer", collector_private.public_key(), ("quota:write",))
    registry.register("replicator", replication_private.public_key(), ("replication:write",))
    standby = Controller(
        tmp_path / "standby.db",
        controller_id="standby",
        role="standby",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        now=lambda: NOW,
    )
    active = Controller(
        tmp_path / "active.db",
        controller_id="active",
        role="active",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        peer=standby,
        replication_signer=PolicySigner(replication_private, "replicator"),
        now=lambda: NOW,
    )
    key_path = tmp_path / "collector.pem"
    write_private_key(key_path, collector_private)
    (tmp_path / "source.json").write_text(
        json.dumps(
            [
                {
                    "provider": "provider-a",
                    "accountLabel": "primary",
                    "quotaUsed": 10,
                    "resetTime": (NOW + timedelta(days=1)).isoformat(),
                    "capturedAt": NOW.isoformat(),
                }
            ]
        ),
        encoding="utf-8",
    )
    config_path = tmp_path / "collector.yaml"
    config_path.write_text(
        "\n".join(
            [
                "signing:",
                "  keyId: quota-writer",
                f"  privateKeyPath: {key_path.name}",
                "controllers:",
                "  - https://active.example",
                "  - https://standby.example",
                "sources:",
                "  - path: source.json",
                "    sourceClass: provider-derived",
            ]
        ),
        encoding="utf-8",
    )
    transport = ControllerTransport(
        {
            "active.example": TestClient(create_app(active)),
            "standby.example": TestClient(create_app(standby)),
        }
    )

    collector, records = load_collector_config(config_path, transport=transport, now=lambda: NOW)
    deliveries = collector.publish(records)
    runway = RunwayLoop(active).run_once()

    assert deliveries[0].deliveries == {
        "https://active.example/v1/quota": True,
        "https://standby.example/v1/quota": False,
    }
    assert len(active.store.quotas()) == 1
    assert active.store.quotas() == standby.store.quotas()
    assert isinstance(runway, list)
    assert runway[0]["quotaUsed"] == 10
    assert runway[0]["sourceClass"] == "provider-derived"



def test_runway_loop_joins_quota_omp_and_proxy_spend(tmp_path: Path) -> None:
    controller = Controller(
        tmp_path / "controller.db",
        controller_id="active",
        role="active",
        epoch=1,
        fleet_token=TOKEN,
        principals=PrincipalRegistry(),
        now=lambda: NOW,
    )
    quota = QuotaRecord(
        provider="provider-a",
        accountLabel="primary",
        quotaUsed=50,
        resetTime=NOW + timedelta(days=1),
        sourceClass="provider-derived",
        freshnessTime=NOW - timedelta(minutes=5),
    )
    with controller.store.transaction() as cursor:
        controller.store.put_record(cursor, "quotas", quota.model_dump(mode="json", by_alias=True), NOW)
        controller.store.append_event_tx(
            cursor,
            now=NOW,
            subsystem="omp",
            severity="info",
            subject="event",
            detail={
                "subject": "usage_observed",
                "time": (NOW - timedelta(minutes=2)).isoformat(),
                "detail": {
                    "provider": "provider-a",
                    "accountLabel": "primary",
                    "consumedTokens": 7,
                    "attribution": "manual",
                },
            },
        )
        controller.store.put_record(
            cursor,
            "apply_receipts",
            {
                "kind": "modelctl.proxy.spend",
                "provider": "provider-a",
                "accountLabel": "primary",
                "amount": 3,
                "occurredAt": (NOW - timedelta(minutes=1)).isoformat(),
                "source": "proxy",
                "attribution": "proxy",
            },
            NOW,
        )

    result = RunwayLoop(controller).run_once()

    assert result == [
        {
            "sourceClass": "provider-derived",
            "provider": "provider-a",
            "accountLabel": "primary",
            "quotaUsed": 50,
            "quotaUnit": "tokens",
            "projectedQuotaUsed": 60,
            "resetTime": (NOW + timedelta(days=1)).isoformat().replace("+00:00", "Z"),
            "freshnessTime": (NOW - timedelta(minutes=5)).isoformat().replace("+00:00", "Z"),
            "directSpend": 0,
            "manualSpend": 7,
            "proxySpend": 3,
            "totalSpend": 10,
        }
    ]
    response = TestClient(create_app(controller)).get(
        "/v1/runway",
        headers={"authorization": f"Bearer {TOKEN}"},
    )
    assert response.status_code == 200
    assert response.json() == result


def test_controller_rejects_invalid_signed_quota_before_replication(tmp_path: Path) -> None:
    writer_private = ed25519.Ed25519PrivateKey.generate()
    replication_private = ed25519.Ed25519PrivateKey.generate()
    writer = PolicySigner(writer_private, "quota-writer")
    replicator = PolicySigner(replication_private, "replicator")
    registry = PrincipalRegistry()
    registry.register("quota-writer", writer_private.public_key(), ("quota:write",))
    registry.register("replicator", replication_private.public_key(), ("replication:write",))
    standby = Controller(
        tmp_path / "standby.db",
        controller_id="standby",
        role="standby",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        now=lambda: NOW,
    )
    active = Controller(
        tmp_path / "active.db",
        controller_id="active",
        role="active",
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        peer=standby,
        replication_signer=replicator,
        now=lambda: NOW,
    )
    envelope = writer.sign(
        {
            "provider": "provider-a",
            "accountLabel": "owner@example.invalid",
            "quotaUsed": 10,
            "resetTime": (NOW + timedelta(days=1)).isoformat(),
            "sourceClass": "provider-derived",
            "freshnessTime": NOW.isoformat(),
            "sourceDomain": "broker-host",
        },
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        sequence=1,
    )

    response = TestClient(create_app(active)).post(
        "/v1/quota",
        json=envelope.model_dump(mode="json", by_alias=True),
    )

    assert response.status_code == 422
    assert active.store.quotas() == []
    assert standby.store.quotas() == []
    assert any(event["subject"] == "mutation-rejected" for event in active.events())
