import json
from pathlib import Path

import pytest

from modelctl.cli.validate import main, validate_paths


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


@pytest.mark.parametrize("suffix", [".yaml", ".yml", ".YAML"])
def test_validate_loads_nested_yaml_policy(tmp_path: Path, suffix: str) -> None:
    directory = tmp_path / "nested"
    directory.mkdir()
    (directory / f"policy{suffix}").write_text(
        "version: 1\nworkloads:\n  - name: tiny\nroutes: {}\n", encoding="utf-8"
    )

    assert validate_paths([tmp_path]) == []


@pytest.mark.parametrize(
    ("filename", "content"),
    [("policy.json", b'{"version":'), ("policy.yaml", b"version: ["), ("policy.yml", b"\xff")],
)
def test_validate_reports_unreadable_documents(tmp_path: Path, filename: str, content: bytes) -> None:
    path = tmp_path / filename
    path.write_bytes(content)

    errors = validate_paths([path])

    assert len(errors) == 1
    assert errors[0].startswith(f"{path}: ")


def test_cli_defaults_to_current_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / "policy.json").write_text(
        json.dumps({"version": 1, "workloads": [{"name": "tiny"}], "routes": {}}), encoding="utf-8"
    )

    assert main([]) == 0
    assert capsys.readouterr().out == "valid\n"


def test_cli_reports_each_bad_file_without_stopping(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    malformed = tmp_path / "malformed.yaml"
    malformed.write_text("version: [", encoding="utf-8")
    missing = tmp_path / "missing.json"

    assert main([str(malformed), str(missing)]) == 1
    output = capsys.readouterr()
    assert f"{malformed}:" in output.out
    assert f"{missing}: path does not exist" in output.out
    assert "valid\n" not in output.out
    assert output.err == ""
