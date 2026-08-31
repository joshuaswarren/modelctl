from pathlib import Path

from modelctl.controller.api import Controller
from modelctl.controller.auth import PrincipalRegistry
from modelctl.controller.loops.base import LoopRunner


def test_loop_failure_opens_only_that_circuit_and_records_event(tmp_path: Path) -> None:
    controller = Controller(
        tmp_path / "controller.db",
        controller_id="active",
        role="active",
        epoch=1,
        fleet_token="token",
        principals=PrincipalRegistry(),
    )
    canary = LoopRunner("canary", controller, lambda: (_ for _ in ()).throw(RuntimeError("canary failed")))
    budget = LoopRunner("budget", controller, lambda: {"status": "ok"})

    assert canary.run_once() is None
    assert canary.breaker.open is True
    assert budget.run_once() == {"status": "ok"}
    assert any(event["subject"] == "canary" for event in controller.events())
