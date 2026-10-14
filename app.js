/* LogLens front-end: plain JavaScript + Plotly.js for charts. */
const $ = (s, r = document) => r.querySelector(s);
const SEV_COL = { critical: "#D9412B", high: "#E0762E", medium: "#C98512", low: "#3B6EA8" };
const SEV_R = { 1: 4, 2: 6, 3: 8, 4: 10 };
const SEV_NAME = { 1: "low", 2: "medium", 3: "high", 4: "critical" };
const STAGES = ["Reconnaissance", "Access attempts", "Exploitation", "Compromise", "Data theft", "Disruption"];
const state = { overview: null, incidents: [], ips: [], selected: null };

const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const nf = n => Number(n).toLocaleString("en-US");
const hhmm = iso => iso.slice(11, 16);
const when = iso => { const d = new Date(iso); return d.toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", timeZone: "UTC" }) + " UTC"; };
const riskCol = r => r >= 70 ? "#D9412B" : r >= 40 ? "#E0762E" : r >= 25 ? "#C98512" : "#3B6EA8";

async function api(url, opt) {
  const r = await fetch(url, opt);
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || r.statusText);
  return j;
}
function toast(msg) { const t = $("#toast"); t.textContent = msg; t.classList.add("show"); setTimeout(() => t.classList.remove("show"), 2600); }

/* ---------------------------------------------------------------- load */
async function loadAll() {
  const [ov, inc, ips] = await Promise.all([api("/api/overview"), api("/api/incidents"), api("/api/ips")]);
  state.overview = ov; state.incidents = inc; state.ips = ips;
  if (!state.selected || !inc.find(i => i.ip === state.selected)) state.selected = inc[0]?.ip || null;
  renderKpis(); renderTimeline(); renderBars(); renderStories(); renderAlerts(); renderIps(); renderRaw();
}

/* ---------------------------------------------------------------- KPIs */
function renderKpis() {
  const s = state.overview.summary, ev = state.overview.evaluation, sev = s.severity || {};
  $("#source").textContent = `${s.source || ""}  |  ${s.from ? when(s.from) : ""} to ${s.to ? when(s.to) : ""}`;
  const total = Math.max(1, s.alerts);
  const bar = ["critical", "high", "medium", "low"].map(k => `<i style="width:${(sev[k] || 0) / total * 100}%;background:${SEV_COL[k]}" title="${k}: ${sev[k] || 0}"></i>`).join("");
  const evalHtml = ev
    ? `<div class="kpi"><div class="v">${ev.found}/${ev.known_attackers}</div><div class="l">Known attackers found</div><div class="s">${ev.false_alarms.length} false alarms, F1 score ${ev.f1}</div></div>`
    : `<div class="kpi"><div class="v">${nf(s.unique_ips)}</div><div class="l">Unique IP addresses</div><div class="s">${s.skipped} unreadable lines skipped</div></div>`;
  $("#kpis").innerHTML = `
    <div class="kpi"><div class="v">${nf(s.events)}</div><div class="l">Log events analysed</div><div class="s">${nf(s.web)} web, ${nf(s.ssh)} SSH</div></div>
    <div class="kpi"><div class="v">${s.alerts}</div><div class="l">Alerts raised</div><div class="sevbar">${bar}</div></div>
    <div class="kpi"><div class="v">${s.incidents}</div><div class="l">Attackers reconstructed</div><div class="s">${esc(s.model)} + rules + time-series</div></div>
    <div class="kpi ${s.compromised ? "bad" : ""}"><div class="v">${s.compromised}</div><div class="l">Likely breaches</div><div class="s">${s.compromised ? "Needs action now" : "None seen"}</div></div>
    ${evalHtml}`;
}

/* ---------------------------------------------------------------- charts (Plotly.js) */
const PCFG = { displayModeBar: false, responsive: true };
const PFONT = { family: "IBM Plex Sans, Segoe UI, sans-serif", size: 12, color: "#5B6B7B" };
const havePlotly = () => typeof Plotly !== "undefined";

function renderTimeline() {
  const rows = state.overview.timeline, el = $("#timeline");
  if (!rows.length) { el.innerHTML = `<div class="empty">No data</div>`; return; }
  if (!havePlotly()) { el.innerHTML = `<div class="empty">plotly.min.js not found in static/ folder</div>`; return; }
  const x = rows.map(r => new Date(r.t * 1000).toISOString());
  const mx = Math.max(...rows.map(r => Math.max(r.web, r.ssh_fail)), 1);
  const sq = v => Math.sqrt(v);   // square-root scale so small attacks stay visible
  const ticks = [0, 10, 100, 1000, 10000].filter(v => v <= mx);
  const al = rows.filter(r => r.alerts);

  const traces = [
    { type: "bar", name: "Web requests", x, y: rows.map(r => sq(r.web)), customdata: rows.map(r => r.web),
      marker: { color: "#9CC9C9" }, hovertemplate: "%{x|%H:%M} UTC<br>%{customdata} web requests<extra></extra>" },
    { type: "scatter", mode: "lines", name: "Failed SSH logins", x, y: rows.map(r => sq(r.ssh_fail)), customdata: rows.map(r => r.ssh_fail),
      line: { color: "#3B6EA8", width: 2 }, hovertemplate: "%{x|%H:%M} UTC<br>%{customdata} failed SSH logins<extra></extra>" },
    { type: "scatter", mode: "markers", name: "Alert (size = severity)", yaxis: "y2",
      x: al.map(r => new Date(r.t * 1000).toISOString()), y: al.map(() => 1),
      customdata: al.map(r => r.ips[0] || ""),
      text: al.map(r => `${r.alerts} alert(s), worst: ${SEV_NAME[r.sev]}${r.ips.length ? "<br>" + r.ips.join(", ") : ""}`),
      marker: { size: al.map(r => SEV_R[r.sev] * 2), color: al.map(r => SEV_COL[SEV_NAME[r.sev]]), line: { color: "#fff", width: 1 } },
      hovertemplate: "%{text}<extra></extra>" }
  ];
  const layout = {
    height: 300, margin: { l: 44, r: 10, t: 6, b: 32 }, font: PFONT, bargap: 0.05,
    paper_bgcolor: "rgba(0,0,0,0)", plot_bgcolor: "rgba(0,0,0,0)", hovermode: "closest",
    legend: { orientation: "h", y: -0.12, x: 0 },
    xaxis: { gridcolor: "#E3E9EF", tickformat: "%H:%M", hoverformat: "%H:%M" },
    yaxis: { domain: [0, 0.84], tickvals: ticks.map(sq), ticktext: ticks.map(String), gridcolor: "#E3E9EF", zeroline: false,
             title: { text: "events / 10 min (sqrt scale)", font: { size: 11 } } },
    yaxis2: { domain: [0.9, 1], range: [0.4, 1.6], visible: false, fixedrange: true }
  };
  Plotly.react(el, traces, layout, PCFG);
  if (el.removeAllListeners) el.removeAllListeners("plotly_click");
  el.on("plotly_click", d => {
    const p = d.points[0];
    if (p.curveNumber === 2 && p.customdata) { selectIncident(p.customdata); $("#tabs").scrollIntoView(); }
  });
}

function plotBars(sel, items, color) {
  const el = $(sel);
  if (!items.length) { el.innerHTML = `<div class="empty">Nothing yet</div>`; return; }
  if (!havePlotly()) { el.innerHTML = `<div class="empty">plotly.min.js not found in static/ folder</div>`; return; }
  const it = items.slice().reverse();   // so biggest bar is on top
  Plotly.react(el, [{
    type: "bar", orientation: "h", x: it.map(i => i.count), y: it.map(i => i.name),
    text: it.map(i => nf(i.count)), textposition: "outside", cliponaxis: false,
    marker: { color }, hovertemplate: "%{y}: %{x}<extra></extra>"
  }], {
    height: 36 + it.length * 30, margin: { l: 120, r: 36, t: 4, b: 4 }, font: PFONT,
    paper_bgcolor: "rgba(0,0,0,0)", plot_bgcolor: "rgba(0,0,0,0)",
    xaxis: { visible: false }, yaxis: { automargin: true }
  }, PCFG);
}
function renderBars() {
  const o = state.overview;
  plotBars("#stagebars", o.stage_counts, "#D9412B");
  plotBars("#userbars", o.top_users, "#3B6EA8");
}

function drawIpChart() {
  const el = $("#ipchart");
  if (!el || !havePlotly() || !state.ips.length) return;
  const it = state.ips.slice(0, 15).reverse();
  Plotly.react(el, [{
    type: "bar", orientation: "h", x: it.map(r => r.score), y: it.map(r => r.ip),
    marker: { color: it.map(r => r.flagged ? "#D9412B" : "#9CB4CC") },
    text: it.map(r => r.score), textposition: "outside", cliponaxis: false,
    hovertemplate: "%{y}<br>anomaly score %{x}<extra></extra>"
  }], {
    height: 60 + it.length * 24, margin: { l: 130, r: 36, t: 4, b: 30 }, font: PFONT,
    paper_bgcolor: "rgba(0,0,0,0)", plot_bgcolor: "rgba(0,0,0,0)",
    xaxis: { range: [0, 110], gridcolor: "#E3E9EF", title: { text: "anomaly score (red = flagged)", font: { size: 11 } } },
    yaxis: { automargin: true }
  }, PCFG);
}

/* ---------------------------------------------------------------- attack stories (unique feature) */
function selectIncident(ip) { state.selected = ip; switchTab("stories"); renderStories(); }

function renderStories() {
  const box = $("#tab-stories"), inc = state.incidents;
  if (!inc.length) { box.innerHTML = `<div class="empty">No attackers found in these logs. Try "New sample data".</div>`; return; }
  const list = inc.map(i => `<button class="icard ${i.ip === state.selected ? "on" : ""}" data-ip="${esc(i.ip)}">
      <span class="risk" style="background:${riskCol(i.risk)}" title="Risk score">${i.risk}</span>
      <span><span class="ip">${esc(i.ip)}</span><br><span class="vd">${esc(i.verdict)}</span></span></button>`).join("");
  box.innerHTML = `<div class="stories"><div class="ilist" role="list">${list}</div><div class="story" id="story"></div></div>`;
  box.querySelectorAll(".icard").forEach(b => b.addEventListener("click", () => { state.selected = b.dataset.ip; renderStories(); }));
  renderStory(inc.find(i => i.ip === state.selected) || inc[0]);
}

function renderStory(i) {
  const f = i.furthest;
  const chain = STAGES.map((n, k) => `<div class="stg ${i.stages.includes(k) ? "hit" : ""} ${k === f ? "last" : ""} ${f !== null && k === f + 1 ? "next" : ""}">${n}</div>`).join("");
  const steps = i.steps.map(s => `<li class="step ${s.severity}">
      <div class="when">${hhmm(s.ts)} UTC${s.gap ? `<em>${esc(s.gap)} later</em>` : ""}</div>
      <h4>${esc(s.stage_name)}: ${esc(s.title)}</h4><p>${esc(s.story)}</p>
      ${s.technique !== "-" ? `<span class="tag">MITRE ATT&amp;CK ${esc(s.technique)} ${esc(s.technique_name)}</span>` : ""}
      ${s.evidence.length ? `<details class="ev"><summary>Show log evidence</summary><pre>${s.evidence.map(esc).join("\n")}</pre></details>` : ""}</li>`).join("");
  const ml = i.ml && i.ml.flagged ? `<div class="box" style="margin-bottom:14px"><h5>Behaviour model: anomaly score ${i.ml.score}/100</h5>
      <ul>${i.ml.reasons.map(r => `<li>${esc(r.text)}</li>`).join("") || "<li>Overall pattern is unusual compared with other visitors.</li>"}</ul></div>` : "";
  const nextBox = f !== null && f < 5 || f === 5 ? `<div class="box warn"><h5>Predicted next move</h5><p>${esc(i.next_move)}</p></div>` : "";
  const acts = i.actions.length ? i.actions : ["Watch this IP and compare with the raw log lines."];
  $("#story").innerHTML = `
    <div class="shead"><div><h3>${esc(i.ip)}</h3><span class="badge ${i.verdict_class}">${esc(i.verdict)}</span></div>
      <span class="risk" style="background:${riskCol(i.risk)};width:60px;height:60px;font-size:20px" title="Risk score 0-100">${i.risk}</span></div>
    <p class="lead">${esc(i.headline)}</p>
    <div class="meta"><span>First alert <b>${when(i.first)}</b></span><span>Duration <b>${esc(i.duration)}</b></span>
      <span>Log events <b>${nf(i.stats.events)}</b></span>${i.users.length ? `<span>Accounts touched <b>${i.users.map(esc).join(", ")}</b></span>` : ""}</div>
    <div class="chain" aria-label="Kill chain">${chain}</div>
    <div class="chainkey"><span><i style="background:var(--ink)"></i>stage reached</span><span><i style="background:var(--red)"></i>furthest stage</span><span><i style="background:#F0D6AA"></i>likely next</span></div>
    <ol class="steps">${steps}</ol>${ml}
    <div class="cols">${nextBox}<div class="box"><h5>What to do</h5><ul>${acts.map(a => `<li>${esc(a)}</li>`).join("")}</ul></div></div>
    <div class="box" style="margin-top:16px"><h5>Block commands <button class="mini" id="copyBlock">Copy</button> <button class="mini" id="seeRaw">View raw log lines</button></h5>
      <pre>${i.block.map(esc).join("\n")}</pre></div>`;
  $("#copyBlock").onclick = () => navigator.clipboard.writeText(i.block.join("\n")).then(() => toast("Commands copied"));
  $("#seeRaw").onclick = () => { $("#rawip").value = i.ip; switchTab("raw"); loadRaw(); };
}

/* ---------------------------------------------------------------- alerts table */
function renderAlerts() {
  $("#tab-alerts").innerHTML = `<div class="tools"><select id="fsev"><option value="">All severities</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select>
    <input id="fq" placeholder="Search IP, rule, text" aria-label="Search alerts"></div><div id="alertTable"></div>`;
  $("#fsev").onchange = loadAlerts; $("#fq").oninput = loadAlerts; loadAlerts();
}
async function loadAlerts() {
  const p = new URLSearchParams({ severity: $("#fsev").value, q: $("#fq").value });
  const rows = await api("/api/alerts?" + p);
  $("#alertTable").innerHTML = rows.length ? `<div class="tablewrap"><table><thead><tr><th>Time (UTC)</th><th>Severity</th><th>Alert</th><th>Source IP</th><th>MITRE</th><th>Rule</th></tr></thead><tbody>${rows.map(a => `<tr>
    <td class="mono">${hhmm(a.ts)}</td><td><span class="sev ${a.severity}">${a.severity}</span></td><td><b>${esc(a.title)}</b><br><span style="color:var(--muted)">${esc(a.story)}</span></td>
    <td class="mono">${a.ip ? `<a href="#" data-ip="${esc(a.ip)}" class="ipl">${esc(a.ip)}</a>` : "many"}</td><td class="mono">${esc(a.technique)}<br>${esc(a.tactic)}</td><td class="mono">${esc(a.rule)}</td></tr>`).join("")}</tbody></table></div>` : `<div class="empty">No alerts match.</div>`;
  document.querySelectorAll(".ipl").forEach(l => l.onclick = e => { e.preventDefault(); if (state.incidents.find(i => i.ip === l.dataset.ip)) selectIncident(l.dataset.ip); });
}

/* ---------------------------------------------------------------- IP behaviour scores */
function renderIps() {
  const rows = state.ips.slice(0, 40);
  $("#tab-ips").innerHTML = `<p class="hint" style="margin-bottom:10px">Every IP gets a 0-100 anomaly score from an Isolation Forest trained on 8 behaviour features. Score alone is not an alarm; flagged IPs also need a strongly unusual feature.</p>
  <div id="ipchart" class="chart" style="margin-bottom:14px"></div>
  <div class="tablewrap"><table><thead><tr><th>IP</th><th>Anomaly score</th><th>Why (top unusual features)</th><th>Web req</th><th>Peak/min</th><th>Failed logins</th></tr></thead><tbody>${rows.map(r => `<tr>
    <td class="mono">${esc(r.ip)}${r.flagged ? " (flagged)" : ""}</td><td><span class="scorebar ${r.flagged ? "hot" : ""}" style="width:${r.score * 1.2}px"></span> <span class="mono">${r.score}</span></td>
    <td>${r.reasons.map(x => esc(x.text)).join("<br>") || '<span style="color:var(--muted)">looks normal</span>'}</td>
    <td class="mono">${nf(r.requests)}</td><td class="mono">${nf(r.peak_rpm)}</td><td class="mono">${nf(r.auth_fails)}</td></tr>`).join("")}</tbody></table></div>`;
}

/* ---------------------------------------------------------------- raw lines */
function renderRaw() {
  $("#tab-raw").innerHTML = `<div class="tools"><input id="rawip" placeholder="IP address, e.g. ${esc(state.selected || "185.220.101.45")}" value="${esc(state.selected || "")}" aria-label="IP address"><button class="mini" id="rawgo">Show lines</button></div><div id="rawOut"></div>`;
  $("#rawgo").onclick = loadRaw; $("#rawip").onkeydown = e => { if (e.key === "Enter") loadRaw(); };
}
async function loadRaw() {
  const ip = $("#rawip").value.trim();
  const rows = await api("/api/events?limit=400" + (ip ? "&ip=" + encodeURIComponent(ip) : ""));
  $("#rawOut").innerHTML = rows.length ? `<p class="hint">Showing ${rows.length} line(s) (max 400).</p><pre style="max-height:460px">${rows.map(r => esc(r.raw)).join("\n")}</pre>` : `<div class="empty">No lines for that IP.</div>`;
}

/* ---------------------------------------------------------------- tabs + actions */
function switchTab(name) {
  document.querySelectorAll("#tabs button").forEach(b => b.classList.toggle("on", b.dataset.tab === name));
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("on", t.id === "tab-" + name));
  if (name === "ips") drawIpChart();
}
$("#tabs").addEventListener("click", e => { if (e.target.dataset.tab) switchTab(e.target.dataset.tab); });
$("#btnSample").onclick = async () => { toast("Generating new sample logs..."); await api("/api/sample", { method: "POST" }); await loadAll(); toast("Sample data reloaded"); };
$("#fileIn").onchange = async e => {
  const fd = new FormData(); [...e.target.files].forEach(f => fd.append("files", f));
  try { toast("Analysing..."); await api("/api/upload", { method: "POST", body: fd }); await loadAll(); toast("Analysis done"); }
  catch (err) { toast(err.message); }
  e.target.value = "";
};
loadAll().catch(err => { document.body.insertAdjacentHTML("beforeend", `<p class="empty">Could not load data: ${esc(err.message)}</p>`); });
