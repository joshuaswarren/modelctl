"""Signed HTTP transport for controller replication."""
from __future__ import annotations

import ssl
from collections.abc import Callable
from urllib.parse import urlsplit

import httpx

from modelctl.controller.replication import ReplicationMessage
from modelctl.policy.signing import SignedEnvelope


class HttpReplicationPeer:
    """Send signed replication phases to one controller peer."""

    def __init__(
        self,
        base_url: str,
        *,
        sign_control: Callable[[dict[str, object]], SignedEnvelope],
        timeout: float = 5.0,
        client: httpx.Client | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("replication peer URL must be HTTP or HTTPS")
        if timeout <= 0:
            raise ValueError("replication timeout must be positive")
        self._base_url = base_url.rstrip("/")
        self._sign_control = sign_control
        if client is not None:
            self._client = client
        elif ssl_context is not None:
            self._client = httpx.Client(timeout=timeout, verify=ssl_context)
        else:
            self._client = httpx.Client(timeout=timeout)
        self._owns_client = client is None

    def _post(self, path: str, envelope: SignedEnvelope) -> bool:
        try:
            response = self._client.post(
                f"{self._base_url}{path}",
                json=envelope.model_dump(mode="json", by_alias=True),
            )
            response.raise_for_status()
            value = response.json()
        except (httpx.HTTPError, ValueError):
            return False
        return isinstance(value, dict) and value.get("accepted") is True

    def prepare_replication(self, message: ReplicationMessage, envelope: SignedEnvelope) -> bool:
        if envelope.payload != message.model_dump(mode="json", by_alias=True):
            return False
        return self._post("/v1/replication/prepare", envelope)

    def commit_replication(self, operation_id: str) -> bool:
        envelope = self._sign_control({"action": "commit", "operationId": operation_id})
        return self._post("/v1/replication/commit", envelope)

    def abort_replication(self, operation_id: str) -> None:
        envelope = self._sign_control({"action": "abort", "operationId": operation_id})
        self._post("/v1/replication/abort", envelope)

    def fence(self, epoch: int) -> bool:
        envelope = self._sign_control({"action": "fence", "epoch": epoch})
        return self._post("/v1/replication/fence", envelope)

    def close(self) -> None:
        if self._owns_client:
            self._client.close()
