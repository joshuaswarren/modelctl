"""Reject private values before generic modelctl content becomes public."""
from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable
from pathlib import Path

_SELF = Path(__file__).resolve()
_IGNORED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".unlazy",
    ".claude",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    "venv",
}
_IGNORED_SUFFIXES = {".pyc", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".zip", ".lock"}
_SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".go",
    ".h",
    ".html",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".swift",
    ".ts",
    ".tsx",
}
_QUOTED_SECRET_RE = re.compile(
    r"(?i)(?:api[_-]?key|secret|password|token)\s*[:=]\s*[\"'](?P<value>[A-Za-z0-9_./+=-]{12,})[\"']"
)
_UNQUOTED_SECRET_RE = re.compile(
    r"(?im)^\s*(?:api[_-]?key|secret|password|token)\s*[:=]\s*(?P<value>[A-Za-z0-9_./+=-]{12,})\s*$"
)
_PREFIXED_SECRET_RE = re.compile(r"\b(?P<value>(?:sk|ghp|github_pat|AKIA)[A-Za-z0-9_-]{8,})")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]+ PRIVATE KEY-----")
_PLACEHOLDER_VALUES = {
    "fleet-test-token",
    "receiver-token-do-not-print",
    "sk-live-value-must-not-leak",
}
_PRIVATE_HOST_RE = re.compile(
    r"(?i)(?:[\w-]+\.(?:internal|local|lan|home)(?=$|[/\s\"'=:/])|"
    r"(?:^|[./\s\"'=])(?:jarvis|macstudio|jw14m2|16m1mbp|proxmox\d*)(?:$|[./\s\"'=:/]))"
)
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_USERNAME_RE = re.compile(r"(?i)(?:username|user_name)\s*[:=]\s*[\"']?[A-Za-z][\w.-]*")
_HOME_PATH_RE = re.compile(r"(?:/home/|/Users/)[A-Za-z0-9._-]+")
_CLIENT_RE = re.compile(r"(?i)(?:clientName|client_name|customerName|customer_name)\s*[:=]")
_PRIVATE_REPO_RE = re.compile(
    r"(?i)(?:git@[^\s:]+:|https?://[^\s/]+/[^\s/]+/(?:private|internal|confidential)[^\s]*)"
)
_PROMPT_RE = re.compile(r"(?i)(?:system prompt|private prompt|prompt\s*[:=]\s*(?:you are|system:))")
_PRIVATE_EVAL_RE = re.compile(r"(?i)(?:private[-_ ]?eval|privateEval|eval[-_ ]?data)\s*[:=]")


def _is_rfc1918(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    networks = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
    )
    return any(address in network for network in networks)


def _is_placeholder(value: str) -> bool:
    return value.lower() in _PLACEHOLDER_VALUES


def _contains_secret(path: Path, text: str) -> bool:
    if _PRIVATE_KEY_RE.search(text):
        return True
    for match in _QUOTED_SECRET_RE.finditer(text):
        if not _is_placeholder(match.group("value")):
            return True
    if path.suffix.lower() not in _SOURCE_SUFFIXES:
        for match in _UNQUOTED_SECRET_RE.finditer(text):
            if not _is_placeholder(match.group("value")):
                return True
    return any(
        not _is_placeholder(match.group("value"))
        for match in _PREFIXED_SECRET_RE.finditer(text)
    )


def _files(paths: Iterable[Path]) -> Iterable[Path]:
    for requested in paths:
        path = requested.resolve()
        if path.is_file():
            yield path
            continue
        if not path.is_dir():
            continue
        for candidate in sorted(path.rglob("*")):
            if not candidate.is_file() or any(part in _IGNORED_DIRECTORIES for part in candidate.parts):
                continue
            if candidate.suffix.lower() in _IGNORED_SUFFIXES:
                continue
            yield candidate


def _scan_file(path: Path) -> list[str]:
    if path == _SELF or path.name == "privacy_scan.py" and path.parent.name == "scripts":
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return []

    errors: list[str] = []
    label = str(path)
    if _contains_secret(path, text):
        errors.append(f"{label}: secret")
    if _PRIVATE_HOST_RE.search(text):
        errors.append(f"{label}: private hostname")
    if any(_is_rfc1918(match) for match in _IP_RE.findall(text)):
        errors.append(f"{label}: RFC1918 address")
    if _USERNAME_RE.search(text) or _HOME_PATH_RE.search(text):
        errors.append(f"{label}: username")
    if _CLIENT_RE.search(text):
        errors.append(f"{label}: client name")
    if _PRIVATE_REPO_RE.search(text):
        errors.append(f"{label}: private repository link")
    if _PROMPT_RE.search(text):
        errors.append(f"{label}: prompt")
    if _PRIVATE_EVAL_RE.search(text) or re.search(r"(?i)private[-_ ]?eval", path.name):
        errors.append(f"{label}: private eval data")
    return errors


def scan_paths(paths: Iterable[Path]) -> list[str]:
    """Return stable, categorized privacy findings for the given paths."""

    return [error for path in _files(paths) for error in _scan_file(path)]
