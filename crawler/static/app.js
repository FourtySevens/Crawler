"use strict";

const $ = (id) => document.getElementById(id);
const esc = (value) => String(value ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));
const number = (value) => Number(value || 0).toLocaleString();
const state = {token: "", job: null, report: null, jobs: [], view: "overview", urlPage: 0, loading: false};
const colors = {high: "#f08090", medium: "#e9bc75", low: "#72b9ed", info: "#a8a1d8"};
const titles = {
  overview: ["Overview", "See your application clearly.", "Map your website’s surface and uncover security signals in one place."],
  urls: ["URL inventory", "Explore the application surface.", "Inspect discovered pages, resources, and endpoints — with coverage at every step."],
  findings: ["Security findings", "Turn signals into next steps.", "Review passive observations, supporting evidence, and practical remediation."],
  forms: ["Forms & inputs", "Understand the input surface.", "Inspect form actions, methods, and field names across your application."]
};

async function api(path, options = {}) {
  const response = await fetch(path, {...options, headers: {"Content-Type": "application/json", "X-Crawler-Token": state.token, ...(options.headers || {})}});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

function error(message) {
  $("error").textContent = message;
  $("error").hidden = !message;
}

function empty(title, description, symbol = "⌘") {
  return `<div class="empty-state"><div class="empty-symbol">${esc(symbol)}</div><h3>${esc(title)}</h3><p>${esc(description)}</p></div>`;
}

function changeView(view) {
  if (!titles[view]) return;
  state.view = view;
  for (const [name, labels] of Object.entries(titles)) {
    $(`${name}-view`).hidden = name !== view;
    if (name === view) {
      $("breadcrumb").textContent = labels[0];
      $("view-title").textContent = labels[1];
      $("view-description").textContent = labels[2];
    }
  }
  document.querySelectorAll(".nav-item").forEach(el => el.classList.toggle("active", el.dataset.view === view));
  renderView();
}

function statusCode(code) {
  const style = !code ? "unknown" : code >= 400 ? "bad" : code >= 300 ? "redirect" : "";
  return `<span class="status-code ${style}">${esc(code || "—")}</span>`;
}

function pagesTable(pages) {
  if (!pages.length) return empty("Your map starts with a single URL", "Start a crawl to see pages, response codes, and the paths connecting your application.", "↳");
  return `<div class="table-scroll"><table><thead><tr><th>Status</th><th>URL / title</th><th>Content type</th><th>Depth</th><th>Time</th></tr></thead><tbody>${pages.map(p => `<tr><td>${statusCode(p.status)}</td><td class="url-cell code">${esc(p.url)}<small>${esc(p.title || p.error || (p.redirect_to ? "→ " + p.redirect_to : ""))}</small></td><td class="code">${esc((p.content_type || "—").split(";")[0])}</td><td>${esc(p.depth)}</td><td class="code">${number(p.elapsed_ms)} ms</td></tr>`).join("")}</tbody></table></div>`;
}

function data() {
  return state.report || state.job || {pages: [], findings: [], summary: {}};
}

function renderSummary() {
  const d = data(), s = d.summary || {}, job = state.job;
  for (const key of ["pages", "findings", "forms", "requests"]) $(`stat-${key}`).textContent = number(s[key]);
  $("stat-discovered").textContent = `${number(s.discovered)} URLs discovered`;
  $("stat-high").textContent = `${number(s.severity?.high)} high priority`;
  $("stat-errors").textContent = `${number(s.errors)} network / body errors`;
  $("nav-urls").textContent = number(s.discovered);
  $("nav-findings").textContent = number(s.findings);
  $("nav-forms").textContent = number(s.forms);
  const running = state.jobs.some(j => ["running", "stopping"].includes(j.status));
  $("start-button").hidden = Boolean(job && ["running", "stopping"].includes(job.status));
  $("start-button").disabled = !state.token || running;
  $("stop-button").hidden = !job || !["running", "stopping"].includes(job.status);
  $("stop-button").disabled = job?.status === "stopping";
  $("stop-button").textContent = job?.status === "stopping" ? "Stopping…" : "Stop crawl";
  $("scan-status").textContent = !job ? "Ready to explore" : {running: "Crawl in progress", stopping: "Finishing current requests", complete: "Crawl complete", cancelled: "Crawl stopped", failed: "Crawl failed"}[job.status];
  $("status-dot").className = "status-dot " + (job?.status || "");
  $("scan-target").textContent = job?.target || "Configure a target to begin your assessment.";
  if (job) {
    const seconds = Math.max(0, Math.floor(((job.finished_at ? new Date(job.finished_at) : new Date()) - new Date(job.started_at)) / 1000));
    $("scan-time").textContent = `${Math.floor(seconds / 60)}m ${seconds % 60}s · ${(job.stop_reason || "running").replaceAll("_", " ")}`;
  } else $("scan-time").textContent = "No scan running";
  $("export-actions").hidden = !state.report;
  if (state.report) {
    $("html-export").href = `/reports/${job.id}/report.html`;
    $("json-export").href = `/reports/${job.id}/report.json`;
  }
  const warnings = [...(d.warnings || []), ...(job?.error ? [job.error] : [])];
  $("warnings").innerHTML = warnings.map(w => `<p>${esc(w)}</p>`).join("");
  $("warnings").hidden = !warnings.length;
}

function renderOverview() {
  const d = data(), s = d.summary || {}, severity = s.severity || {}, total = s.findings || 0;
  let angle = 0;
  const segments = [];
  $("severity-total").textContent = number(total);
  $("severity-legend").innerHTML = Object.entries(colors).map(([level, color]) => {
    const count = severity[level] || 0, percentage = total ? Math.round(count / total * 100) : 0;
    const start = angle; angle += total ? count / total * 360 : 0;
    if (count) segments.push(`${color} ${start}deg ${angle}deg`);
    return `<div class="legend-row"><span class="severity-dot" data-color="${level}"></span>${level === "info" ? "Informational" : level[0].toUpperCase() + level.slice(1)}<b>${number(count)}</b><small>${percentage}%</small></div>`;
  }).join("");
  $("severity-legend").querySelectorAll("[data-color]").forEach(el => { el.style.background = colors[el.dataset.color]; });
  $("severity-donut").style.background = segments.length ? `conic-gradient(${segments.join(",")})` : "#26394a";
  const states = s.states || {}, discovered = s.discovered || 0;
  const coverage = [["Collected responses", s.pages || 0], ["Out of scope / excluded", (states.out_of_scope || 0) + (states.excluded || 0) + (states.robots_blocked || 0)], ["Inventory only / limited / pending", ["inventory_only", "pending", "queued", "fetching", "depth_limit", "variant_limit"].reduce((sum, key) => sum + (states[key] || 0), 0)]];
  $("coverage-bars").innerHTML = coverage.map(([label, count]) => `<div class="coverage-row"><div class="coverage-label"><span>${esc(label)}</span><b>${number(count)}</b></div><div class="bar-track"><div class="bar-fill" data-count="${count}"></div></div></div>`).join("");
  $("coverage-bars").querySelectorAll(".bar-fill").forEach(el => { el.style.width = `${discovered ? Math.min(100, Number(el.dataset.count) / discovered * 100) : 0}%`; });
  $("coverage-badge").textContent = state.job ? state.job.stop_reason.replaceAll("_", " ") : "AWAITING TARGET";
  $("coverage-note").textContent = !state.job ? "Discovery follows links, redirects, scripts, robots.txt, and nested sitemaps." : `Coverage reflects this crawl’s configured scope and limits. ${number((states.pending || 0) + (states.depth_limit || 0) + (states.variant_limit || 0))} discovered URLs remain limited or pending.`;
  $("recent-pages").innerHTML = pagesTable((d.pages || []).slice(-6).reverse());
}

function renderURLs() {
  const d = data(), query = $("url-search").value.toLowerCase(), filter = $("url-state").value;
  const pageMap = new Map((d.pages || []).map(p => [p.url, p]));
  const inventory = state.report ? state.report.discovered : (d.pages || []).map(p => ({url: p.url, state: p.error ? "error" : "fetched", kind: "response", depth: p.depth}));
  const rows = inventory.filter(item => (!filter || item.state === filter) && (item.url + " " + (pageMap.get(item.url)?.title || "")).toLowerCase().includes(query));
  const pageSize = 100, last = Math.max(0, Math.ceil(rows.length / pageSize) - 1);
  state.urlPage = Math.min(state.urlPage, last);
  const shown = rows.slice(state.urlPage * pageSize, (state.urlPage + 1) * pageSize);
  $("url-count").textContent = `${number(rows.length)} matching URLs`;
  $("inventory-note").textContent = state.report ? "Complete discovered inventory, including unfetched URLs" : state.job ? "Latest 50 responses during crawl · Full inventory available when finished" : "Pages, assets, endpoints, and external references";
  if (!rows.length) { $("url-table").innerHTML = empty("No URLs to display", state.job ? "Try changing your filters or wait for the next response." : "Start a crawl to build your application inventory."); return; }
  $("url-table").innerHTML = `<div class="table-scroll"><table><thead><tr><th>Status</th><th>URL / title</th><th>State</th><th>Discovery</th><th>Parameters</th></tr></thead><tbody>${shown.map(item => {
    const p = pageMap.get(item.url);
    const parameters = p?.parameters || [...new Set(new URL(item.url).searchParams.keys())];
    return `<tr><td>${statusCode(p?.status)}</td><td class="url-cell code">${esc(item.url)}<small>${esc(p?.title || p?.error || "")}</small></td><td><span class="badge neutral">${esc(item.state.replaceAll("_", " "))}</span></td><td>${esc(item.kind.replaceAll("_", " "))}</td><td class="code">${esc(parameters.join(", ") || "—")}</td></tr>`;
  }).join("")}</tbody></table></div><div class="table-foot"><span>Page ${state.urlPage + 1} of ${last + 1}</span><div><button id="prev-urls" ${state.urlPage === 0 ? "disabled" : ""}>Previous</button><button id="next-urls" ${state.urlPage === last ? "disabled" : ""}>Next</button></div></div>`;
  $("prev-urls").onclick = () => { state.urlPage--; renderURLs(); };
  $("next-urls").onclick = () => { state.urlPage++; renderURLs(); };
}

function renderFindings() {
  const filter = $("severity-filter").value;
  const findings = (data().findings || []).filter(f => !filter || f.severity === filter);
  if (!findings.length) { $("finding-list").innerHTML = empty("No findings to display", state.job ? "No observations match the current severity filter." : "Passive checks run automatically as responses arrive.", "◇"); return; }
  const order = Object.keys(colors), groups = new Map();
  for (const finding of [...findings].sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity))) {
    const key = finding.rule + finding.severity;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(finding);
  }
  const opened = new Set([...$("finding-list").querySelectorAll("details[open]")].map(el => el.dataset.rule));
  $("finding-list").innerHTML = [...groups].map(([key, items]) => {
    const f = items[0];
    return `<details class="finding" data-rule="${esc(key)}" ${opened.has(key) ? "open" : ""}><summary><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span><span>${esc(f.title)}</span><span class="instance-count">${number(items.length)} instances</span></summary><div class="finding-body"><p>${esc(f.recommendation)}</p><a href="${esc(f.reference)}" target="_blank" rel="noreferrer">Remediation reference ↗</a>${items.slice(0, 100).map(item => `<div class="finding-instance"><b class="code">${esc(item.url)}</b><p>${esc(item.evidence)}</p><span class="confidence">Confidence: ${esc(item.confidence)}</span></div>`).join("")}${items.length > 100 ? `<p>Showing 100 instances. The exported report contains all ${number(items.length)}.</p>` : ""}</div></details>`;
  }).join("") + (!state.report ? '<p class="muted small">Showing the latest 100 finding instances while this scan runs.</p>' : "");
}

function renderForms() {
  const forms = (data().pages || []).flatMap(p => (p.forms || []).map(f => ({...f, source: p.url})));
  if (!forms.length) { $("form-list").innerHTML = empty("No forms discovered yet", "Form actions and input names appear here as the crawler explores pages.", "▤"); return; }
  $("form-list").innerHTML = forms.slice(0, 500).map(f => `<div class="form-card"><div class="form-title"><span class="badge neutral">${esc(f.method)}</span><span class="code">${esc(f.action)}</span></div><div class="form-source">Found on ${esc(f.source)}</div><div class="field-tags">${f.fields.map(field => `<span class="field-tag code">${esc(field.name || "(unnamed)")}<small>${esc(field.type)}</small></span>`).join("") || '<span class="muted small">No input fields</span>'}</div></div>`).join("") + (forms.length > 500 ? '<p class="table-foot">Showing the first 500 forms. Export the report for the full inventory.</p>' : "");
}

function renderView() {
  renderSummary();
  ({overview: renderOverview, urls: renderURLs, findings: renderFindings, forms: renderForms})[state.view]();
}

function renderHistory() {
  $("history").innerHTML = state.jobs.length ? state.jobs.map(job => `<button class="history-item ${job.id === state.job?.id ? "selected" : ""}" data-id="${esc(job.id)}">${esc(new URL(job.target).host)}<small>${esc(job.status)} · ${number(job.summary.pages)} responses</small></button>`).join("") : '<p class="sidebar-muted">Your scans will appear here.</p>';
  $("history").querySelectorAll("button").forEach(button => button.onclick = () => selectScan(button.dataset.id));
}

async function selectScan(id) {
  const job = state.jobs.find(j => j.id === id);
  if (!job) return;
  state.job = job;
  state.report = null;
  state.urlPage = 0;
  renderHistory(); renderView();
  if (["complete", "cancelled"].includes(job.status)) {
    try {
      const report = await api(`/reports/${id}/report.json`);
      if (state.job?.id === id) { state.report = report; renderView(); }
    } catch (err) { error(err.message); }
  }
}

async function refresh() {
  if (state.loading) return;
  state.loading = true;
  try {
    state.jobs = await api("/api/scans");
    $("connection").textContent = "Local server connected";
    if (state.job) {
      state.job = state.jobs.find(j => j.id === state.job.id) || state.job;
      if (!state.report && ["complete", "cancelled"].includes(state.job.status)) {
        const id = state.job.id, report = await api(`/reports/${id}/report.json`);
        if (state.job?.id === id) state.report = report;
      }
    } else if (state.jobs.length) await selectScan(state.jobs[0].id);
    renderHistory(); renderView();
  } catch (err) { $("connection").textContent = "Server disconnected"; }
  finally { state.loading = false; }
}

$("scan-form").addEventListener("submit", async event => {
  event.preventDefault();
  error("");
  try {
    const lines = id => $(id).value.split("\n").map(x => x.trim()).filter(Boolean);
    const payload = {
      url: $("target").value.trim(), max_pages: Number($("max-pages").value), max_depth: Number($("max-depth").value),
      rate: Number($("rate").value), concurrency: Number($("concurrency").value), timeout: Number($("timeout").value), max_duration: Number($("max-duration").value),
      allowed_origins: lines("allowed-origins"), excludes: lines("excludes"), include_subdomains: $("subdomains").checked,
      respect_robots: $("robots").checked, discover_sitemaps: $("sitemaps").checked, verify_tls: $("verify-tls").checked,
      headers: JSON.parse($("headers").value || "{}"), cookies: JSON.parse($("cookies").value || "{}"), proxy: $("proxy").value.trim() || null
    };
    $("start-button").disabled = true;
    const response = await api("/api/scans", {method: "POST", body: JSON.stringify(payload)});
    $("headers").value = ""; $("cookies").value = "";
    state.jobs = await api("/api/scans");
    await selectScan(response.id);
    changeView("overview");
  } catch (err) { error(err.message); }
  finally { renderSummary(); }
});
$("stop-button").onclick = async () => {
  if (!state.job) return;
  try { await api(`/api/scans/${state.job.id}/stop`, {method: "POST", body: "{}"}); await refresh(); }
  catch (err) { error(err.message); }
};
$("settings-toggle").onclick = () => {
  const hidden = !$("settings").hidden;
  $("settings").hidden = hidden;
  $("settings-toggle").setAttribute("aria-expanded", String(!hidden));
};
document.querySelectorAll("[data-view]").forEach(button => button.onclick = () => changeView(button.dataset.view));
$("url-search").oninput = () => { state.urlPage = 0; renderURLs(); };
$("url-state").onchange = () => { state.urlPage = 0; renderURLs(); };
$("severity-filter").onchange = renderFindings;
$("max-pages").oninput = () => { $("pages-hint").textContent = number($("max-pages").value); };
$("rate").oninput = () => { $("rate-hint").textContent = $("rate").value; };
renderView();
(async () => {
  try {
    state.token = (await api("/api/session")).token;
    await refresh();
    setInterval(refresh, 1500);
  } catch (err) { error("Unable to connect to the local server. " + err.message); }
})();
