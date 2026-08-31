from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient

from modelctl.controller.api import Controller, create_app
from modelctl.controller.auth import PrincipalRegistry
from modelctl.policy.signing import PolicySigner

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
TOKEN = "fleet-test-token"
SCOPES = (
    "host:report",
    "event:write",
    "quota:write",
    "adapter:write",
    "policy:write",
    "replication:write",
    "controller:promote",
)


def setup_controller(tmp_path: Path, *, observe_only: bool, role: str = "standby") -> tuple[Controller, PolicySigner]:
    private = ed25519.Ed25519PrivateKey.generate()
    signer = PolicySigner(private, "writer")
    registry = PrincipalRegistry()
    registry.register("writer", private.public_key(), SCOPES)
    controller = Controller(
        tmp_path / "controller.db",
        controller_id="observer",
        role=role,
        epoch=1,
        fleet_token=TOKEN,
        principals=registry,
        observe_only=observe_only,
        now=lambda: NOW,
    )
    return controller, signer


def signed(signer: PolicySigner, payload: dict[str, object], sequence: int, nonce: str) -> dict[str, object]:
    return signer.sign(
        payload,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        nonce=nonce,
        sequence=sequence,
    ).model_dump(mode="json", by_alias=True)


def test_cli_parses_only_exact_observe_only_booleans(monkeypatch: pytest.MonkeyPatch) -> None:
    from modelctl.controller.cli import build_parser

    monkeypatch.setenv("MODELCTL_OBSERVE_ONLY", "true")
    assert build_parser().parse_args([]).observe_only is True
    monkeypatch.setenv("MODELCTL_OBSERVE_ONLY", "false")
    assert build_parser().parse_args(["--observe-only", "true"]).observe_only is True
    assert build_parser().parse_args(["--observe-only", "false"]).observe_only is False
    monkeypatch.setenv("MODELCTL_OBSERVE_ONLY", "false")
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--observe-only", "yes"])
    monkeypatch.setenv("MODELCTL_OBSERVE_ONLY", "1")
    with pytest.raises(ValueError, match="MODELCTL_OBSERVE_ONLY must be exactly true or false"):
        build_parser()


def test_observe_only_mode_is_visible_in_status_and_health(tmp_path: Path) -> None:
    controller, _ = setup_controller(tmp_path, observe_only=True)
    client = TestClient(create_app(controller))
    headers = {"Authorization": f"Bearer {TOKEN}"}

    assert controller.status()["observe_only"] is True
    assert controller.health()["observe_only"] is True
    assert client.get("/health", headers=headers).json()["observe_only"] is True
    assert client.get("/v1/status", headers=headers).json()["observe_only"] is True


def test_observe_only_accepts_signed_ingestion_without_replication(tmp_path: Path) -> None:
    controller, signer = setup_controller(tmp_path, observe_only=True)
    client = TestClient(create_app(controller))

    host = signed(signer, {"hostId": "host-1", "health": "healthy"}, 1, "host-1")
    event = signed(signer, {"subject": "telemetry", "detail": {"value": 1}}, 2, "event-1")
    quota = signed(
        signer,
        {
            "provider": "provider",
            "accountLabel": "account",
            "quotaUsed": 10,
            "quotaUnit": "tokens",
            "resetTime": "2026-08-31T00:00:00Z",
            "sourceClass": "provider-derived",
            "freshnessTime": "2026-08-30T12:00:00Z",
        },
        3,
        "quota-1",
    )

    assert client.post("/v1/host-reports", json=host).status_code == 200
    assert client.post("/v1/events", json=event).status_code == 200
    assert client.post("/v1/quota", json=quota).status_code == 200
    assert controller.status()["hosts"] == [{"hostId": "host-1", "health": "healthy", "drained": False}]
    assert controller.status()["quotas"][0]["provider"] == "provider"
    assert controller.status()["observe_only"] is True


def test_observe_only_rejects_control_plane_changes_durably(tmp_path: Path) -> None:
    controller, signer = setup_controller(tmp_path, observe_only=True, role="active")
    client = TestClient(create_app(controller))

    policy = signed(signer, {"bundle": "policy"}, 1, "policy-1")
    receipt = signed(signer, {"recordId": "receipt-1", "result": "applied"}, 2, "receipt-1")

    assert client.post("/v1/policies", json=policy).status_code == 409
    assert client.post("/v1/apply-receipts", json=receipt).status_code == 409
    assert client.post("/v1/promote", json={}).status_code == 409
    assert client.post("/v1/replication/prepare", json={}).status_code == 409
    assert client.post("/v1/replication/commit", json={}).status_code == 409
    assert client.post("/v1/replication/abort", json={}).status_code == 409
    assert client.post("/v1/replication/fence", json={}).status_code == 409

    assert controller.policy() is None
    assert controller.status()["apply_receipts"] == []
    rejected = [event for event in controller.events() if event["subject"] == "mutation-rejected"]
    assert len(rejected) == 7
    assert all(event["detail"]["mode"] == "observe-only" for event in rejected)
    assert all("control-plane" in event["detail"]["reason"] for event in rejected)
