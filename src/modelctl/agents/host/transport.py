"""Injectable HTTP boundaries for host collectors and report delivery."""
from __future__ import annotations

import json
import ssl
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.request import Request, urlopen


@dataclass(frozen=True)
class HttpResponse:
    """The small HTTP result needed by host agents."""

    status_code: int
    body: Any


class HttpTransport(Protocol):
    """HTTP operations used by collectors and controller delivery."""

    def get(self, url: str) -> HttpResponse:
        """Perform one read-only GET request."""
        ...

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> HttpResponse:
        """Post one signed envelope."""
        ...


def build_mtls_context(
    ca_path: Path,
    cert_path: Path,
    key_path: Path,
) -> ssl.SSLContext:
    """Load a CA and mode-0600 client key into one mutual TLS context."""

    if stat.S_IMODE(key_path.stat().st_mode) & 0o077:
        raise ValueError(f"TLS client key permissions must be 0600 at {key_path}")
    context = ssl.create_default_context(cafile=str(ca_path))
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return context

class UrllibTransport:
    """Production transport with no client dependency beyond the standard library."""

    def __init__(
        self,
        *,
        timeout: float = 10.0,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        if timeout <= 0:
            raise ValueError("timeout must be positive")
        self.timeout = timeout
        self.ssl_context = ssl_context

    def get(self, url: str) -> HttpResponse:
        request = Request(url, method="GET")
        response = (
            urlopen(request, timeout=self.timeout)
            if self.ssl_context is None
            else urlopen(request, timeout=self.timeout, context=self.ssl_context)
        )
        with response:
            return HttpResponse(response.status, json.loads(response.read().decode("utf-8")))

    def post(self, url: str, body: bytes, headers: Mapping[str, str]) -> HttpResponse:
        request = Request(url, data=body, headers=dict(headers), method="POST")
        response = (
            urlopen(request, timeout=self.timeout)
            if self.ssl_context is None
            else urlopen(request, timeout=self.timeout, context=self.ssl_context)
        )
        with response:
            raw_body = response.read()
            parsed: Any = json.loads(raw_body.decode("utf-8")) if raw_body else {}
            return HttpResponse(response.status, parsed)
