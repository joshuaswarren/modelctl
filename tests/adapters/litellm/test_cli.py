from __future__ import annotations

import json

import pytest

from modelctl.adapters.litellm.cli import main


def test_check_cli_uses_generic_public_fixture(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--check"]) == 0

    output = json.loads(capsys.readouterr().out)
    assert output["originalDigest"]
    assert "manual_model: preserve" in output["diff"]
    assert "fixture-auto" in json.dumps(output, sort_keys=True)


def test_check_cli_requires_check_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as error:
        main([])

    assert error.value.code == 2
    assert "only --check" in capsys.readouterr().err
