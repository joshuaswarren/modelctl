"""Authentication for controller reads and signed mutations."""
from __future__ import annotations

import hmac
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta

from modelctl.policy.signing import SignedEnvelope
from modelctl.policy.store import PublicKey
from modelctl.policy.verify import PolicyVerifier


class AuthenticationError(Exception):
    """A request failed authentication or authorization."""

    def __init__(self, reason: str, status_code: int = 401) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code


@dataclass(frozen=True)
class Principal:
    """One signing identity and its exact allowed scopes."""

    key_id: str
    public_key: PublicKey
    scopes: frozenset[str]

    def allows(self, scope: str) -> bool:
        return scope in self.scopes


class PrincipalRegistry:
    """In-memory registry of trusted keys and exact scopes."""

    def __init__(self, principals: Mapping[str, Principal] | None = None) -> None:
        self._principals: dict[str, Principal] = dict(principals or {})

    def register(self, key_id: str, public_key: PublicKey, scopes: Iterable[str]) -> None:
        scope_set = frozenset(scopes)
        if not key_id or not scope_set or any(not scope for scope in scope_set):
            raise ValueError("principal key_id and scopes must be non-empty")
        self._principals[key_id] = Principal(key_id, public_key, scope_set)

    def get(self, key_id: str) -> Principal | None:
        return self._principals.get(key_id)

    def public_keys(self) -> dict[str, PublicKey]:
        return {key_id: principal.public_key for key_id, principal in self._principals.items()}


class FleetBearerToken:
    """Constant-time comparison for the fleet read token."""

    def __init__(self, expected: str) -> None:
        if not expected:
            raise ValueError("fleet token must not be empty")
        self._expected = expected

    def check(self, authorization: str | None) -> bool:
        prefix = "Bearer "
        if authorization is None or not authorization.startswith(prefix):
            return False
        supplied = authorization[len(prefix) :]
        return hmac.compare_digest(supplied.encode("utf-8"), self._expected.encode("utf-8"))


class EnvelopeAuthenticator:
    """Verify an envelope before an exact scope check."""

    def __init__(
        self,
        principals: PrincipalRegistry,
        *,
        now: Callable[[], datetime] | None = None,
        max_future_skew: timedelta = timedelta(0),
    ) -> None:
        self.principals = principals
        self.verifier = PolicyVerifier(principals.public_keys(), now=now, max_future_skew=max_future_skew)

    def authenticate(self, envelope: SignedEnvelope, required_scope: str) -> Principal:
        if not self.verifier.verify(envelope, record_replay=False):
            raise AuthenticationError("invalid signed envelope", 401)
        principal = self.principals.get(envelope.key_id)
        if principal is None or not principal.allows(required_scope):
            raise AuthenticationError("scope is not authorized", 403)
        return principal
