import json
from pathlib import Path

import pytest

from modelctl.telemetry.cli import main


@pytest.mark.parametrize("content", ["controllers: [", "[]", "null"])
def test_collector_cli_reports_unparseable_config(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], content: str
) -> None:
    path = tmp_path / "collector.yaml"
    path.write_text(content, encoding="utf-8")

    assert main(["collect", "--config", str(path)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err.startswith("quota collector failed: ")


def test_collector_cli_reports_missing_config(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = tmp_path / "missing.yaml"

    assert main(["collect", "--config", str(path)]) == 2
    assert str(path) in capsys.readouterr().err


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("controllers", [], "controllers must be a nonempty list"),
        ("controllers", [42], "controller must be a nonempty string"),
        ("sources", [], "sources must be a nonempty list"),
        ("sources", [42], "sources[0] must be an object"),
        ("sources", [{"path": "snapshot.json"}], "sources[0] must contain only path and sourceClass"),
        (
            "sources",
            [{"path": "snapshot.json", "sourceClass": "unsupported"}],
            "sources[0].sourceClass is invalid",
        ),
        ("timeoutSeconds", 0, "timeoutSeconds must be positive"),
        ("recordTtlSeconds", True, "recordTtlSeconds must be positive"),
        ("tls", {"caPath": "ca.pem"}, "tls must contain only caPath, clientCertPath, and clientKeyPath"),
    ],
)
def test_collector_cli_rejects_bad_config_before_publish(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], field: str, value: object, message: str
) -> None:
    path = tmp_path / "collector.yaml"
    (tmp_path / "snapshot.json").write_text("[]", encoding="utf-8")
    config: dict[str, object] = {
        "controllers": ["https://control.example"],
        "sources": [{"path": "snapshot.json", "sourceClass": "provider-derived"}],
        "sequencePath": str(tmp_path / "sequence.json"),
        "eventsPath": str(tmp_path / "events.jsonl"),
    }
    config[field] = value
    path.write_text(json.dumps(config), encoding="utf-8")

    assert main(["collect", "--config", str(path)]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == f"quota collector failed: {message}\n"
    assert not (tmp_path / "sequence.json").exists()
    assert not (tmp_path / "events.jsonl").exists()


@pytest.mark.parametrize("arguments", [[], ["collect"], ["unsupported"]])
def test_collector_cli_rejects_incomplete_or_unknown_command(
    capsys: pytest.CaptureFixture[str], arguments: list[str]
) -> None:
    with pytest.raises(SystemExit) as error:
        main(arguments)

    assert error.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert "usage: modelctl-quota-collector" in output.err
    assert "error:" in output.err
