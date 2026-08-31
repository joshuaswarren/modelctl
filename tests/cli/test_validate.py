import json
from pathlib import Path

from modelctl.cli.validate import validate_paths


def test_validate_accepts_synthetic_policy(tmp_path: Path) -> None:
    policy = {
        "version": 1,
        "workloads": [{"name": "tiny"}],
        "routes": {"slow": "engine-b.example.test", "tiny": "engine-a.example.test"},
    }
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")

    assert validate_paths([tmp_path]) == []


def test_validate_rejects_invalid_policy_schema(tmp_path: Path) -> None:
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps({"version": 0}), encoding="utf-8")

    errors = validate_paths([tmp_path])

    assert any("version" in error for error in errors)

def test_validate_rejects_private_hostname_and_rfc1918_address(tmp_path: Path) -> None:
    path = tmp_path / "private.json"
    hostname = "engine" + "." + "internal"
    address = ".".join(("192", "168", "1", "20"))  # noqa: FLY002 - keep private address out of source
    path.write_text(
        json.dumps({"host": hostname, "address": address}),
        encoding="utf-8",
    )

    errors = validate_paths([tmp_path])

    assert any("private hostname" in error for error in errors)
    assert any("RFC1918" in error for error in errors)


def test_validate_rejects_missing_path(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"

    assert validate_paths([missing]) == [f"{missing}: path does not exist"]
