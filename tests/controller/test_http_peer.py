import json
from datetime import UTC, datetime, timedelta

import httpx
from cryptography.hazmat.primitives.asymmetric import ed25519

from modelctl.controller.replication import ReplicationMessage
from modelctl.policy.signing import PolicySigner, SignedEnvelope

NOW = datetime(2026, 8, 29, 12, 0, tzinfo=UTC)


def test_http_peer_sends_signed_phase_requests_to_exact_routes() -> None:
    from modelctl.controller.http_peer import HttpReplicationPeer
    signer = PolicySigner(ed25519.Ed25519PrivateKey.generate(), "replicator")
    sequence = 1
    requests: list[tuple[str, dict[str, object]]] = []

    def sign_control(payload: dict[str, object]) -> SignedEnvelope:
        nonlocal sequence
        envelope = signer.sign(
            payload,
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            nonce=f"control-{sequence}",
            sequence=sequence,
        )
        sequence += 1
        return envelope

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append((request.url.path, json.loads(request.content)))
        return httpx.Response(200, json={"accepted": True})

    client = httpx.Client(transport=httpx.MockTransport(respond))
    peer = HttpReplicationPeer("https://standby.example", sign_control=sign_control, client=client)
    message = ReplicationMessage(
        sourceController="active",
        epoch=1,
        generation=1,
        operationId="operation-1",
        payload={"kind": "event", "payload": {}},
    )
    prepare = sign_control(message.model_dump(mode="json", by_alias=True))

    assert peer.prepare_replication(message, prepare)
    assert peer.commit_replication("operation-1")
    peer.abort_replication("operation-1")
    assert peer.fence(2)

    assert [path for path, _ in requests] == [
        "/v1/replication/prepare",
        "/v1/replication/commit",
        "/v1/replication/abort",
        "/v1/replication/fence",
    ]
    assert requests[1][1]["payload"] == {"action": "commit", "operationId": "operation-1"}
    assert requests[2][1]["payload"] == {"action": "abort", "operationId": "operation-1"}
    assert requests[3][1]["payload"] == {"action": "fence", "epoch": 2}


def test_http_peer_uses_supplied_mutual_tls_context(monkeypatch: object) -> None:
    import ssl
    from typing import Any

    from modelctl.controller.http_peer import HttpReplicationPeer

    context = ssl.create_default_context()
    captured: dict[str, object] = {}

    class Client:
        def close(self) -> None:
            return None

    def client_factory(*, timeout: float, verify: ssl.SSLContext) -> Client:
        captured.update(timeout=timeout, verify=verify)
        return Client()

    cast_monkeypatch: Any = monkeypatch
    cast_monkeypatch.setattr(httpx, "Client", client_factory)
    peer = HttpReplicationPeer(
        "https://standby.example",
        sign_control=lambda payload: SignedEnvelope.model_validate(payload),
        timeout=2.5,
        ssl_context=context,
    )

    assert captured == {"timeout": 2.5, "verify": context}
    peer.close()
