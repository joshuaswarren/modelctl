"""Server-rendered modelctl operator dashboard."""
from __future__ import annotations

import json

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from modelctl.operator.actions import ALLOWED_ACTION_ENDPOINTS, action_endpoint_allowed

_DASHBOARD_ACTIONS = json.dumps(sorted(ALLOWED_ACTION_ENDPOINTS))

_DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>modelctl operator dashboard</title>
<style>
:root { color-scheme: light dark; --bg: #101418; --panel: #192027; --text: #edf2f7; --muted: #a9b6c2; --line: #34424d; --accent: #77c7b5; --warn: #f0c674; --bad: #ef8d8d; }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 16px/1.45 system-ui, sans-serif; }
main { width: min(1440px, 100%); margin: 0 auto; padding: 1rem; }
header { display: flex; flex-wrap: wrap; gap: 1rem; align-items: end; justify-content: space-between; margin-bottom: 1rem; }
h1 { margin: 0; font-size: clamp(1.4rem, 3vw, 2rem); }
.connection { display: flex; flex-wrap: wrap; gap: .5rem; width: min(100%, 34rem); }
input, select, textarea, button { border: 1px solid var(--line); border-radius: .4rem; padding: .65rem .8rem; font: inherit; }
input, select, textarea { color: var(--text); background: var(--panel); }
.connection input { flex: 1 1 16rem; }
button { color: #08110f; background: var(--accent); cursor: pointer; font-weight: 700; }
button:disabled { cursor: wait; opacity: .65; }
#status { min-height: 2.3rem; padding: .6rem .8rem; border: 1px solid var(--line); border-radius: .4rem; color: var(--muted); }
#status.bad { color: var(--bad); border-color: var(--bad); }
#status.good { color: var(--accent); border-color: var(--accent); }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 26rem), 1fr)); gap: 1rem; margin-top: 1rem; }
section { min-width: 0; padding: 1rem; border: 1px solid var(--line); border-radius: .5rem; background: var(--panel); }
section.wide { grid-column: 1 / -1; }
h2 { margin: 0 0 .8rem; font-size: 1.1rem; }
.table-wrap { overflow-x: auto; }
table { width: 100%; border-collapse: collapse; min-width: 24rem; }
th, td { padding: .5rem; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
th { color: var(--muted); font-size: .85rem; font-weight: 600; }
.empty { color: var(--muted); margin: 0; }
.badge { display: inline-block; padding: .1rem .4rem; border: 1px solid var(--line); border-radius: 99rem; color: var(--muted); font-size: .85rem; }
code { overflow-wrap: anywhere; }
.action-form { display: grid; gap: .75rem; }
.action-form label { display: grid; gap: .35rem; color: var(--muted); }
.action-form textarea { min-height: 11rem; resize: vertical; font-family: ui-monospace, monospace; }
.action-form .confirm { display: flex; align-items: center; color: var(--text); }
.action-form .confirm input { width: 1rem; height: 1rem; }
#action-result { min-height: 1.5rem; margin: 0; overflow-wrap: anywhere; }
@media (max-width: 40rem) { main { padding: .7rem; } section { padding: .8rem; } table { min-width: 22rem; } }
</style>
</head>
<body>
<main>
<header>
  <div><h1>modelctl operator dashboard</h1><p class="empty">Read-only control-plane view. Signed actions require an exact envelope.</p></div>
  <form class="connection" id="connection-form">
    <label for="fleet-token" class="empty">Fleet bearer token</label>
    <input id="fleet-token" type="password" autocomplete="off" spellcheck="false">
    <button id="connect" type="submit">Connect</button>
  </form>
</header>
<div id="status" role="status" aria-live="polite">Enter a token to load controller data.</div>
<div class="grid">
<section class="wide"><h2>Runway by subscription</h2><div id="runway"><p class="empty">Loading runway data will show source, direct, manual, and proxy usage.</p></div></section>
<section><h2>Budgets by scope</h2><div id="budgets"><p class="empty">Loading budget data.</p></div></section>
<section><h2>Physical reservations</h2><div id="reservations"><p class="empty">Loading reservation data.</p></div></section>
<section><h2>Queue age and depth</h2><div id="queues"><p class="empty">Loading queue data.</p></div></section>
<section><h2>Degraded workloads</h2><div id="degraded"><p class="empty">Loading workload data.</p></div></section>
<section><h2>Active canaries</h2><div id="canaries"><p class="empty">Loading canary data.</p></div></section>
<section class="wide"><h2>Signed action targets</h2><div id="actions"><p class="empty">Loading action targets.</p></div></section>
<section class="wide">
  <h2>Signed policy action</h2>
  <form id="action-form" class="action-form">
    <label for="action-endpoint">Action endpoint<select id="action-endpoint"><option value="/v1/policies">/v1/policies</option></select></label>
    <label for="action-envelope">Exact signed envelope<textarea id="action-envelope" required spellcheck="false" placeholder='{"keyId":"…","sequence":1,"signature":"…","payload":{}}'></textarea></label>
    <label class="confirm" for="action-confirm"><input id="action-confirm" type="checkbox" required>I confirm this exact signed envelope</label>
    <button id="action-submit" type="submit">Submit signed policy</button>
    <p id="action-result" role="status" aria-live="polite"></p>
  </form>
</section>
</div>
</main>
<script>
(() => {
  "use strict";
  const ALLOWED_ACTION_ENDPOINTS = new Set(__ACTION_ENDPOINTS__);
  const state = { token: "", connected: false };
  const statusElement = document.getElementById("status");
  const connectButton = document.getElementById("connect");

  function escapeHtml(value) {
    return String(value ?? "").replace(/[&<>"']/g, character => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[character]));
  }

  function setStatus(message, kind) {
    statusElement.textContent = message;
    statusElement.className = kind || "";
  }

  function requestOptions() {
    return { headers: { "Authorization": `Bearer ${state.token}`, "Accept": "application/json" } };
  }

  async function readResponse(response) {
    if (response.status === 401 || response.status === 403) {
      const error = new Error("Unauthorized");
      error.kind = "unauthorized";
      throw error;
    }
    if (!response.ok) throw new Error(`Controller request failed (${response.status})`);
    return response.json();
  }

  async function loadData() {
    if (!state.token) { setStatus("Enter a token to load controller data.", ""); return; }
    connectButton.disabled = true;
    setStatus("Loading controller data…", "");
    try {
      const responses = await Promise.allSettled([
        fetch("/v1/status", requestOptions()).then(readResponse),
        fetch("/v1/runway", requestOptions()).then(readResponse),
        fetch("/v1/policy", requestOptions()).then(readResponse),
        fetch("/v1/actions", requestOptions()).then(readResponse)
      ]);
      const fulfilled = responses.filter(response => response.status === "fulfilled");
      if (!fulfilled.length) throw responses[0].reason;
      const values = responses.map(response => response.status === "fulfilled" ? response.value : undefined);
      renderAll(values[0], values[1], values[2], values[3]);
      state.connected = true;
      if (fulfilled.length === responses.length) setStatus("Controller data loaded.", "good");
      else setStatus("Partial data loaded. One or more controller requests failed.", "bad");
    } catch (error) {
      renderAll();
      state.connected = false;
      if (error?.kind === "unauthorized") setStatus("Unauthorized. Check the fleet bearer token.", "bad");
      else setStatus("Network error. The controller data could not be loaded.", "bad");
    } finally {
      connectButton.disabled = false;
    }
  }

  function table(headers, rows) {
    if (!rows.length) return '<p class="empty">No data reported.</p>';
    return `<div class="table-wrap"><table><thead><tr>${headers.map(header => `<th>${escapeHtml(header)}</th>`).join("")}</tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
  }

  function renderRunway(value) {
    const records = Array.isArray(value) ? value : (value?.runway || []);
    const rows = records.map(record => `<tr><td>${escapeHtml(record.accountLabel || record.account_label || "Unknown")}</td><td>${escapeHtml(record.provider || "Unknown")}</td><td><span class="badge">${escapeHtml(record.sourceClass || record.source_class || record.source || "unknown")}</span></td><td>${escapeHtml(record.directSpend ?? record.direct_spend ?? 0)}</td><td>${escapeHtml(record.manualSpend ?? record.manual_spend ?? 0)}</td><td>${escapeHtml(record.proxySpend ?? record.proxy_spend ?? 0)}</td></tr>`);
    document.getElementById("runway").innerHTML = table(["Subscription", "Provider", "Source", "Direct usage", "Manual usage", "Proxy usage"], rows);
  }

  function budgetRecords(policy, status) {
    const source = policy?.budgets ?? policy?.omp?.budgets ?? status?.budgets ?? {};
    if (Array.isArray(source)) return source.flatMap(record => ["agent", "project", "provider"].flatMap(scope => Object.entries(record?.[scope] || {}).map(([name, limit]) => ({ scope, name, limit }))));
    return ["agent", "project", "provider"].flatMap(scope => Object.entries(source?.[scope] || {}).map(([name, limit]) => ({ scope, name, limit })));
  }

  function renderBudgets(policy, status) {
    const rows = budgetRecords(policy, status).map(record => `<tr><td>${escapeHtml(record.scope)}</td><td>${escapeHtml(record.name)}</td><td>${escapeHtml(record.limit)}</td></tr>`);
    document.getElementById("budgets").innerHTML = table(["Scope", "Name", "Limit"], rows);
  }

  function renderReservations(policy, status) {
    const records = policy?.reservations || status?.reservations || [];
    const rows = records.map(record => `<tr><td>${escapeHtml(record.workload || "Unknown")}</td><td>${escapeHtml((record.prewarmHosts || record.prewarm_hosts || []).join(", ") || "None")}</td><td>${record.n1Impossible || record.n1_impossible ? "Exception" : "Ready"}</td></tr>`);
    document.getElementById("reservations").innerHTML = table(["Workload", "Pre-warm hosts", "N+1 state"], rows);
  }

  function renderQueues(status, policy) {
    const queue = status?.queue || status?.queues || status?.queueMetrics || policy?.queue || policy?.queues || {};
    const records = Array.isArray(queue) ? queue : Object.entries(queue).map(([name, value]) => ({ name, ...(value && typeof value === "object" ? value : { depth: value }) }));
    const rows = records.map(record => `<tr><td>${escapeHtml(record.name || record.queue || "Queue")}</td><td>${escapeHtml(record.ageSeconds ?? record.age_seconds ?? record.age ?? record.queueAgeSeconds ?? record.queue_age_seconds ?? "Unknown")}</td><td>${escapeHtml(record.depth ?? record.queueDepth ?? record.queue_depth ?? "Unknown")}</td></tr>`);
    document.getElementById("queues").innerHTML = table(["Queue", "Oldest age", "Depth"], rows);
  }

  function renderList(id, value, emptyText) {
    const records = Array.isArray(value) ? value : [];
    document.getElementById(id).innerHTML = records.length ? `<ul>${records.map(record => `<li>${escapeHtml(typeof record === "object" ? (record.name || record.workload || JSON.stringify(record)) : record)}</li>`).join("")}</ul>` : `<p class="empty">${emptyText}</p>`;
  }

  function renderAll(status, runway, policy, actions) {
    const policyPayload = policy?.payload || policy || {};
    renderRunway(runway);
    renderBudgets(policyPayload, status);
    renderReservations(policyPayload, status);
    renderQueues(status, policyPayload);
    renderList("degraded", status?.degradedWorkloads || status?.degraded_workloads || status?.degraded || policyPayload?.degradedWorkloads || policyPayload?.degraded_workloads, "No degraded workloads reported.");
    renderList("canaries", status?.activeCanaries || status?.active_canaries || policyPayload?.canaries || policyPayload?.activeCanaries || policyPayload?.active_canaries, "No active canaries reported.");
    const targets = actions && typeof actions === "object" ? Object.entries(actions).map(([name, value]) => `${name}: ${Array.isArray(value) ? value.length : value}`) : [];
    renderList("actions", targets, "No action targets reported.");
  }

  function actionEndpointAllowed(endpoint) {
    try {
      const parsed = new URL(endpoint, window.location.origin);
      return parsed.origin === window.location.origin && !parsed.search && !parsed.hash && ALLOWED_ACTION_ENDPOINTS.has(parsed.pathname);
    } catch (_) { return false; }
  }

  async function submitSignedEnvelope(endpoint, envelope) {
    if (!actionEndpointAllowed(endpoint)) throw new Error("Action endpoint is not allow-listed");
    if (!envelope || typeof envelope !== "object" || Array.isArray(envelope)) throw new Error("Signed envelope is required");
    const response = await fetch(endpoint, { method: "POST", headers: { "Accept": "application/json", "Content-Type": "application/json" }, body: JSON.stringify(envelope) });
    return readResponse(response);
  }

  document.getElementById("action-form").addEventListener("submit", async event => {
    event.preventDefault();
    const resultElement = document.getElementById("action-result");
    const submitButton = document.getElementById("action-submit");
    try {
      if (!document.getElementById("action-confirm").checked) throw new Error("Confirm the exact signed envelope.");
      const envelope = JSON.parse(document.getElementById("action-envelope").value);
      submitButton.disabled = true;
      resultElement.textContent = "Submitting signed policy…";
      const result = await submitSignedEnvelope(document.getElementById("action-endpoint").value, envelope);
      resultElement.textContent = `Policy accepted at sequence ${String(result.sequence ?? envelope.sequence ?? "unknown")}.`;
    } catch (error) {
      resultElement.textContent = error instanceof SyntaxError ? "The signed envelope is not valid JSON." : String(error.message || error);
    } finally {
      submitButton.disabled = false;
    }
  });

  document.getElementById("connection-form").addEventListener("submit", event => {
    event.preventDefault();
    state.token = document.getElementById("fleet-token").value;
    loadData();
  });
  window.modelctlDashboard = { actionEndpointAllowed, submitSignedEnvelope };
})();
</script>
</body>
</html>
""".replace("__ACTION_ENDPOINTS__", _DASHBOARD_ACTIONS)


def dashboard_html() -> str:
    """Return the immutable dashboard document."""

    return _DASHBOARD_HTML


def mount_dashboard(app: FastAPI, path: str = "/dashboard") -> FastAPI:
    """Mount the dashboard at a path and its trailing-slash form."""

    normalized_path = "/" + path.strip("/") if path.strip("/") else "/"

    async def dashboard() -> HTMLResponse:
        return HTMLResponse(_DASHBOARD_HTML)

    app.add_api_route(normalized_path, dashboard, methods=["GET"], include_in_schema=False)
    if normalized_path != "/":
        app.add_api_route(f"{normalized_path}/", dashboard, methods=["GET"], include_in_schema=False)
    return app


__all__ = ["ALLOWED_ACTION_ENDPOINTS", "action_endpoint_allowed", "dashboard_html", "mount_dashboard"]
