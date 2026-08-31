"""Receive, verify, and safely apply signed controller policy."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import ssl
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

import yaml
from cryptography.hazmat.primitives.asymmetric import ed25519

from modelctl.adapters.litellm.apply import (
    ApplyError,
    ApplyReceipt,
    JsonlReceiptSink,
    SubprocessRuntimeController,
    SubprocessSmokeVerifier,
    apply,
)
from modelctl.agents.host.transport import build_mtls_context
from modelctl.domain.policy import PolicyBundle
from modelctl.policy.signing import SignedEnvelope
from modelctl.policy.store import PolicyKeyStore, PolicyStore
from modelctl.policy.verify import PolicyVerifier


class PolicyTransport(Protocol):
    """Read one policy response over the authenticated controller link."""

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        ssl_context: ssl.SSLContext | None,
        timeout: float,
    ) -> PolicyResponse: ...


@dataclass(frozen=True)
class PolicyResponse:
    """HTTP status and decoded JSON returned by one controller."""

    status_code: int
    body: object


class UrllibPolicyTransport:
    """Production HTTPS transport with bearer auth and mutual TLS."""

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        ssl_context: ssl.SSLContext | None,
        timeout: float,
    ) -> PolicyResponse:
        if ssl_context is None:
            raise ValueError("mutual TLS context is required")
        parsed = urlsplit(url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("controller policy URL must use HTTPS")
        request = Request(url, headers=dict(headers), method="GET")
        try:
            response = urlopen(request, timeout=timeout, context=ssl_context)
        except HTTPError as error:
            return PolicyResponse(error.code, None)
        with response:
            return PolicyResponse(response.status, json.loads(response.read().decode("utf-8")))


@dataclass(frozen=True)
class ReceiverConfig:
    """Strict receiver settings loaded from YAML."""

    active_controller_url: str
    standby_controller_url: str
    bearer_token_file: Path
    tls_ca_file: Path
    tls_cert_file: Path
    tls_key_file: Path
    trusted_controller_keys: Mapping[str, bytes]
    policy_state_path: Path
    litellm_config_path: Path
    restart_command: tuple[str, ...]
    smoke_command: tuple[str, ...]
    apply_receipt_path: Path
    apply_enabled: bool = False
    timeout_seconds: float = 10.0

    def __post_init__(self) -> None:
        _https_url(self.active_controller_url, "active controller")
        _https_url(self.standby_controller_url, "standby controller")
        if self.active_controller_url == self.standby_controller_url:
            raise ValueError("active and standby controller URLs must differ")
        if self.timeout_seconds <= 0:
            raise ValueError("timeoutSeconds must be positive")
        if not self.restart_command or not all(item.strip() for item in self.restart_command):
            raise ValueError("restartCommand must contain nonempty strings")
        if not self.smoke_command or not all(item.strip() for item in self.smoke_command):
            raise ValueError("smokeCommand must contain nonempty strings")


@dataclass(frozen=True)
class _Candidate:
    controller: str
    envelope: SignedEnvelope
    policy: PolicyBundle


class _NoReplayVerifier:
    """Repeat full verification without changing replay state during commit."""

    def __init__(self, verifier: PolicyVerifier) -> None:
        self._verifier = verifier

    def verify(self, envelope: SignedEnvelope, *, record_replay: bool = True) -> bool:
        _ = record_replay
        return self._verifier.verify(envelope, record_replay=False)


class Receiver:
    """Synchronize one receiver from active and standby controllers."""

    def __init__(
        self,
        config: ReceiverConfig,
        *,
        ssl_context: ssl.SSLContext | None,
        transport: PolicyTransport | None = None,
        store: PolicyStore | None = None,
        verifier: PolicyVerifier | None = None,
        apply_operation: Callable[..., ApplyReceipt] = apply,
    ) -> None:
        if ssl_context is None:
            raise ValueError("mutual TLS context is required")
        self.config = config
        self.ssl_context = ssl_context
        self.transport = transport or UrllibPolicyTransport()
        self.store = store or PolicyStore(PolicyKeyStore(config.trusted_controller_keys), path=config.policy_state_path)
        self.verifier = verifier or PolicyVerifier(self.store.keys)
        self.apply_operation = apply_operation

    def sync_once(self) -> dict[str, object]:
        token = _read_secret(self.config.bearer_token_file, "bearer token file")
        candidates: list[_Candidate] = []
        failures: list[dict[str, str]] = []
        for name, controller_url in self._controllers():
            candidate, failure_class = self._fetch_candidate(name, controller_url, token)
            if candidate is not None:
                candidates.append(candidate)
            elif failure_class is not None:
                failures.append({"controller": name, "class": failure_class})

        if _split_brain(candidates):
            return _result(
                status="split_brain",
                selected=None,
                last_known_good=self.store.current,
                failures=failures,
                exit_code=1,
            )
        selected = _select_highest(candidates)
        if selected is None or selected.envelope.sequence <= _sequence(self.store.current):
            return _result(
                status="no_update",
                selected=selected,
                last_known_good=self.store.current,
                failures=failures,
                exit_code=0,
            )
        if not self.config.apply_enabled:
            return _result(
                status="update_available",
                selected=selected,
                last_known_good=self.store.current,
                failures=failures,
                exit_code=0,
            )

        try:
            current_digest = _file_digest(self.config.litellm_config_path)
            receipt = self.apply_operation(
                self.config.litellm_config_path,
                selected.policy,
                expected_original_digest=current_digest,
                runtime=SubprocessRuntimeController(self.config.restart_command),
                smoke=SubprocessSmokeVerifier(self.config.smoke_command),
                receipts=JsonlReceiptSink(self.config.apply_receipt_path),
            )
        except (ApplyError, OSError, RuntimeError, TypeError, ValueError):
            return _result(
                status="apply_failed",
                selected=selected,
                last_known_good=self.store.current,
                failures=failures,
                exit_code=1,
            )

        try:
            committed = self.store.apply(selected.envelope, _NoReplayVerifier(self.verifier))
        except (OSError, RuntimeError, TypeError, ValueError):
            committed = False
        if not committed:
            return _result(
                status="state_commit_failed",
                selected=selected,
                last_known_good=self.store.current,
                failures=failures,
                receipt=receipt,
                exit_code=1,
            )
        return _result(
            status="applied",
            selected=selected,
            last_known_good=self.store.current,
            failures=failures,
            receipt=receipt,
            exit_code=0,
        )

    def _controllers(self) -> tuple[tuple[str, str], tuple[str, str]]:
        return (
            ("active", _policy_endpoint(self.config.active_controller_url)),
            ("standby", _policy_endpoint(self.config.standby_controller_url)),
        )

    def _fetch_candidate(
        self,
        name: str,
        url: str,
        token: str,
    ) -> tuple[_Candidate | None, str | None]:
        try:
            response = self.transport.get(
                url,
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                ssl_context=self.ssl_context,
                timeout=self.config.timeout_seconds,
            )
        except (TimeoutError, OSError, URLError):
            return None, "unavailable"
        except ValueError:
            return None, "invalid_response"
        except Exception:  # noqa: BLE001
            return None, "transport_error"
        if response.status_code != 200:
            return None, "http_error"
        if response.body is None:
            return None, "no_policy"
        if not isinstance(response.body, Mapping):
            return None, "invalid_response"
        try:
            envelope = SignedEnvelope.model_validate(response.body)
        except (TypeError, ValueError):
            return None, "invalid_envelope"
        try:
            if not self.verifier.verify(envelope, record_replay=False):
                return None, "verification_failed"
            policy = PolicyBundle.model_validate(envelope.payload)
        except (TypeError, ValueError):
            return None, "invalid_policy"
        return _Candidate(name, envelope, policy), None


def load_config(path: Path) -> ReceiverConfig:
    """Load and validate the strict receiver YAML configuration."""

    try:
        document: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        raise ValueError("could not load receiver config") from None
    root = _mapping(document, "config")
    _strict_keys(
        root,
        {
            "controllers",
            "bearerTokenFile",
            "bearer_token_file",
            "mtls",
            "trustedControllerKeysFile",
            "trusted_controller_keys_file",
            "policyStatePath",
            "policy_state_path",
            "litellmConfigPath",
            "litellm_config_path",
            "restartCommand",
            "restart_command",
            "smokeCommand",
            "smoke_command",
            "applyReceiptPath",
            "apply_receipt_path",
            "timeoutSeconds",
            "timeout_seconds",
            "applyEnabled",
            "apply_enabled",
        },
        "config",
    )
    controllers = _mapping(root.get("controllers"), "controllers")
    _strict_keys(controllers, {"active", "standby"}, "controllers")
    active = _https_url(_text(controllers.get("active"), "controllers.active"), "controllers.active")
    standby = _https_url(_text(controllers.get("standby"), "controllers.standby"), "controllers.standby")
    if active == standby:
        raise ValueError("active and standby controller URLs must differ")

    mtls = _mapping(root.get("mtls"), "mtls")
    _strict_keys(mtls, {"caPath", "clientCertPath", "clientKeyPath"}, "mtls")
    config = ReceiverConfig(
        active_controller_url=active,
        standby_controller_url=standby,
        bearer_token_file=_path(path, _value(root, "bearerTokenFile", "bearer_token_file"), "bearerTokenFile"),
        tls_ca_file=_path(path, mtls.get("caPath"), "mtls.caPath"),
        tls_cert_file=_path(path, mtls.get("clientCertPath"), "mtls.clientCertPath"),
        tls_key_file=_path(path, mtls.get("clientKeyPath"), "mtls.clientKeyPath"),
        trusted_controller_keys=_trusted_keys_file(
            _path(
                path,
                _value(root, "trustedControllerKeysFile", "trusted_controller_keys_file"),
                "trustedControllerKeysFile",
            )
        ),
        policy_state_path=_path(path, _value(root, "policyStatePath", "policy_state_path"), "policyStatePath"),
        litellm_config_path=_path(
            path,
            _value(root, "litellmConfigPath", "litellm_config_path"),
            "litellmConfigPath",
        ),
        restart_command=_command(_value(root, "restartCommand", "restart_command"), "restartCommand"),
        smoke_command=_command(_value(root, "smokeCommand", "smoke_command"), "smokeCommand"),
        apply_receipt_path=_path(
            path,
            _value(root, "applyReceiptPath", "apply_receipt_path"),
            "applyReceiptPath",
        ),
        apply_enabled=_boolean(
            _value(root, "applyEnabled", "apply_enabled", required=False, default=False),
            "applyEnabled",
        ),
        timeout_seconds=_positive_number(
            _value(root, "timeoutSeconds", "timeout_seconds", required=False, default=10.0),
            "timeoutSeconds",
        ),
    )
    _require_secret_file(config.bearer_token_file, "bearer token file")
    _require_secret_file(config.tls_key_file, "TLS client key file")
    return config


def build_receiver(config: ReceiverConfig) -> Receiver:
    """Build the production receiver and its complete mutual TLS context."""

    _read_secret(config.bearer_token_file, "bearer token file")
    context = build_mtls_context(config.tls_ca_file, config.tls_cert_file, config.tls_key_file)
    return Receiver(config, ssl_context=context)


def sync_once(
    config: ReceiverConfig,
    *,
    ssl_context: ssl.SSLContext | None,
    transport: PolicyTransport | None = None,
    store: PolicyStore | None = None,
    verifier: PolicyVerifier | None = None,
    apply_operation: Callable[..., ApplyReceipt] = apply,
) -> dict[str, object]:
    """Run one receiver synchronization with injectable local test boundaries."""

    return Receiver(
        config,
        ssl_context=ssl_context,
        transport=transport,
        store=store,
        verifier=verifier,
        apply_operation=apply_operation,
    ).sync_once()


def main(argv: Sequence[str] | None = None) -> int:
    """Run one production receiver synchronization."""

    parser = argparse.ArgumentParser(prog="modelctl-litellm-receiver")
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("command", choices=("sync-once",), nargs="?", default="sync-once")
    args = parser.parse_args(argv)
    try:
        result = build_receiver(load_config(args.config)).sync_once()
    except (OSError, RuntimeError, TypeError, ValueError):
        result = {
            "status": "unsafe",
            "selected": None,
            "lastKnownGood": None,
            "applyReceipt": None,
            "controllerFailures": [],
            "errorClass": "configuration_error",
            "exitCode": 1,
        }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return cast(int, result["exitCode"])


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be an object")
    return value


def _strict_keys(value: Mapping[str, Any], allowed: set[str], label: str) -> None:
    if set(value) - allowed:
        raise ValueError(f"{label} has unsupported fields")


def _text(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a nonempty string")
    return value


def _value(
    value: Mapping[str, Any],
    primary: str,
    alternate: str | None = None,
    *,
    required: bool = True,
    default: object = None,
) -> object:
    names = (primary,) if alternate is None else (primary, alternate)
    present = [name for name in names if name in value]
    if len(present) > 1:
        raise ValueError(f"set only one of {primary} and {alternate}")
    if not present:
        if required:
            raise ValueError(f"{primary} is required")
        return default
    return value[present[0]]


def _path(config_path: Path, value: object, label: str) -> Path:
    candidate = Path(_text(value, label)).expanduser()
    return candidate if candidate.is_absolute() else config_path.parent / candidate


def _https_url(value: str, label: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username or parsed.password:
        raise ValueError(f"{label} must be an HTTPS URL")
    if parsed.query or parsed.fragment:
        raise ValueError(f"{label} must not contain query or fragment")
    return value.rstrip("/")


def _command(value: object, label: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError(f"{label} must be a nonempty string list")
    return tuple(value)


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{label} must be a boolean")
    return value


def _positive_number(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        raise ValueError(f"{label} must be positive")
    return float(value)


def _trusted_keys(value: object) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    if isinstance(value, Mapping):
        entries = list(value.items())
    elif isinstance(value, list):
        entries = []
        for index, item in enumerate(value):
            entry = _mapping(item, f"trustedControllerKeys[{index}]")
            _strict_keys(entry, {"keyId", "publicKey"}, f"trustedControllerKeys[{index}]")
            entries.append((entry.get("keyId"), entry.get("publicKey")))
    else:
        raise TypeError("trustedControllerKeys must be an object or list")
    for key_id_value, public_key_value in entries:
        key_id = _text(key_id_value, "trusted controller key id")
        if key_id in result:
            raise ValueError("trusted controller key ids must be unique")
        public_key_text = _text(public_key_value, f"trustedControllerKeys.{key_id}")
        try:
            raw_key = base64.b64decode(public_key_text.encode("ascii"), validate=True)
            ed25519.Ed25519PublicKey.from_public_bytes(raw_key)
        except (UnicodeEncodeError, ValueError, TypeError):
            raise ValueError("trusted controller public key must be base64 Ed25519") from None
        result[key_id] = raw_key
    if not result:
        raise ValueError("trustedControllerKeys must not be empty")
    return result


def _trusted_keys_file(path: Path) -> dict[str, bytes]:
    try:
        value: Any = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        raise ValueError("could not load trusted controller keys") from None
    return _trusted_keys(value)


def _require_secret_file(path: Path, label: str) -> None:
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except OSError:
        raise ValueError(f"{label} is not readable") from None
    if mode != 0o600:
        raise ValueError(f"{label} permissions must be 0600")


def _read_secret(path: Path, label: str) -> str:
    _require_secret_file(path, label)
    try:
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        raise ValueError(f"{label} is not readable") from None
    if not value:
        raise ValueError(f"{label} must not be empty")
    return value


def _policy_endpoint(url: str) -> str:
    return url if urlsplit(url).path.rstrip("/") == "/v1/policy" else f"{url}/v1/policy"


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sequence(envelope: SignedEnvelope | None) -> int:
    return -1 if envelope is None else envelope.sequence


def _split_brain(candidates: Sequence[_Candidate]) -> bool:
    by_sequence: dict[int, set[str]] = {}
    for candidate in candidates:
        by_sequence.setdefault(candidate.envelope.sequence, set()).add(candidate.envelope.payload_digest)
    return any(len(digests) > 1 for digests in by_sequence.values())


def _select_highest(candidates: Sequence[_Candidate]) -> _Candidate | None:
    if not candidates:
        return None
    return max(candidates, key=lambda candidate: (candidate.envelope.sequence, candidate.controller == "active"))


def _selected(value: _Candidate | SignedEnvelope | None) -> dict[str, object] | None:
    if value is None:
        return None
    envelope = value.envelope if isinstance(value, _Candidate) else value
    return {"sequence": envelope.sequence, "digest": envelope.payload_digest}


def _receipt_summary(receipt: ApplyReceipt | None) -> dict[str, object] | None:
    if receipt is None:
        return None
    return {
        "bundleId": receipt.bundle_id,
        "originalDigest": receipt.original_digest,
        "renderedDigest": receipt.rendered_digest,
        "backupPath": str(receipt.backup_path) if receipt.backup_path is not None else None,
        "restartPerformed": receipt.restart_performed,
        "distributions": receipt.distributions,
    }


def _result(
    *,
    status: str,
    selected: _Candidate | None,
    last_known_good: SignedEnvelope | None,
    failures: Sequence[Mapping[str, str]],
    exit_code: int,
    receipt: ApplyReceipt | None = None,
) -> dict[str, object]:
    return {
        "status": status,
        "selected": _selected(selected),
        "lastKnownGood": _selected(last_known_good),
        "applyReceipt": _receipt_summary(receipt),
        "controllerFailures": list(failures),
        "exitCode": exit_code,
    }


if __name__ == "__main__":
    raise SystemExit(main())
