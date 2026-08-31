import subprocess
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient

from modelctl.dashboard import (
    ALLOWED_ACTION_ENDPOINTS,
    action_endpoint_allowed,
    mount_dashboard,
)


def test_dashboard_serves_self_contained_token_safe_contract() -> None:
    app = FastAPI()
    mount_dashboard(app)

    response = TestClient(app).get("/dashboard")

    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    body = response.text
    assert "fetch(\"/v1/status\"" in body
    assert "fetch(\"/v1/runway\"" in body
    assert "fetch(\"/v1/policy\"" in body
    assert "fetch(\"/v1/actions\"" in body
    assert "Authorization" in body
    assert "localStorage" not in body
    assert "sessionStorage" not in body
    assert "?token" not in body
    assert "Promise.allSettled" in body
    assert "policy?.payload" in body
    assert 'id="action-form"' in body
    assert 'id="action-envelope"' in body
    assert 'id="action-confirm"' in body
    assert 'id="action-result"' in body
    for label in (
        "Runway by subscription",
        "Direct usage",
        "Manual usage",
        "Proxy usage",
        "Budgets by scope",
        "Physical reservations",
        "Queue age and depth",
        "Degraded workloads",
        "Active canaries",
        "Loading",
        "Unauthorized",
        "Network error",
        "Partial data loaded",
        "Signed policy action",
        "I confirm this exact signed envelope",
        "Submit signed policy",
    ):
        assert label in body


def test_dashboard_embedded_javascript_parses(tmp_path: Path) -> None:
    app = FastAPI()
    body = TestClient(mount_dashboard(app)).get("/dashboard").text
    script = body.split("<script>", maxsplit=1)[1].split("</script>", maxsplit=1)[0]
    script_path = tmp_path / "dashboard.js"
    script_path.write_text(script, encoding="utf-8")

    result = subprocess.run(
        ["node", "--check", str(script_path)],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_dashboard_action_allow_list_rejects_non_mutation_targets() -> None:
    assert ALLOWED_ACTION_ENDPOINTS
    for endpoint in ALLOWED_ACTION_ENDPOINTS:
        assert action_endpoint_allowed(endpoint)
    assert not action_endpoint_allowed("/v1/status")
    assert not action_endpoint_allowed("/v1/promote")
    assert not action_endpoint_allowed("https://other.example/v1/events")
    assert not action_endpoint_allowed("/v1/events?token=secret")
    assert ALLOWED_ACTION_ENDPOINTS == frozenset({"/v1/policies"})


def test_dashboard_has_trailing_slash_route() -> None:
    app = FastAPI()
    mount_dashboard(app)

    assert TestClient(app).get("/dashboard/").status_code == 200
