/* ESET SOC Lite — Control Dashboard
 *
 * Every value rendered here originates from an ingested alert payload, which is
 * attacker-controllable. It MUST pass through esc() before reaching innerHTML.
 */
"use strict";

const API = "/dashboard/api";

const state = {
  jobs: new Map(),      // correlation_id -> job row
  emails: [],
  ai: [],
  runs: new Map(),      // correlation_id -> { stages: Map, started, source }
  stats: null,
  view: "overview",
};

const STAGES = ["INGEST", "NORMALIZE", "RISK", "INTEL", "AI", "LINT", "OUTPUT", "EMAIL", "SEND"];
const STAGE_LABEL = {
  INGEST: "Ingest", NORMALIZE: "Normalize", RISK: "Risk Engine", INTEL: "Threat Intel",
  AI: "AI Generate", LINT: "Safety Lint", OUTPUT: "Write Output", EMAIL: "Queue Email",
  SEND: "Send Mail",
};

/* ══════════════ helpers ══════════════ */

const ESC_MAP = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
function esc(v) {
  if (v === null || v === undefined) return "";
  return String(v).replace(/[&<>"']/g, (c) => ESC_MAP[c]);
}

const BADGES = new Set([
  "PENDING","PROCESSING","SUCCESS","PARTIAL","FAILED",
  "LOW","MEDIUM","HIGH","CRITICAL","UNKNOWN",
  "CLEAN","SUSPICIOUS","MALICIOUS",
  "CLIENT_JA","CTHREE_JA","INTERNAL_JA","ENGINEER_EN",
  "WEBHOOK","SYSLOG",
  "ACCEPTED",
]);
function badge(value) {
  const v = value && BADGES.has(value) ? value : "UNKNOWN";
  return `<span class="badge b-${v}"><span class="g"></span>${esc(value || "UNKNOWN")}</span>`;
}
const DASH = '<span class="dim">—</span>';

function timeAgo(ts) {
  if (!ts) return "—";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (s < 60) return Math.floor(s) + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
}
const shortId = (id) => (id ? esc(String(id).slice(0, 8)) : "—");

function toast(msg, isError) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.className = "toast show" + (isError ? " err" : "");
  clearTimeout(el._t);
  el._t = setTimeout(() => (el.className = "toast"), 2600);
}

/* ══════════════ auth + fetch ══════════════ */

const dashKey = () => sessionStorage.getItem("dash_key") || "";

async function api(path, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (dashKey()) headers["X-Dashboard-Key"] = dashKey();
  if (opts.body) headers["Content-Type"] = "application/json";

  const res = await fetch(API + path, { ...opts, headers });
  if (res.status === 401) { lock(); throw new Error("unauthorized"); }
  if (!res.ok) {
    let detail = await res.text();
    try { detail = JSON.parse(detail).detail || detail; } catch (e) { /* plain text */ }
    throw new Error(detail);
  }
  return res.status === 204 ? null : res.json();
}

function lock() {
  sessionStorage.removeItem("dash_key");
  document.getElementById("app").classList.remove("ready");
  document.getElementById("login").classList.remove("hidden");
  if (window._ws) { try { window._ws.close(); } catch (e) { /* already closed */ } }
}

async function attemptLogin(key) {
  sessionStorage.setItem("dash_key", key);
  try {
    await api("/jobs?limit=1");     // cheapest authenticated probe
    return true;
  } catch (e) {
    sessionStorage.removeItem("dash_key");
    return false;
  }
}

document.getElementById("loginBtn").onclick = async () => {
  const btn = document.getElementById("loginBtn");
  const err = document.getElementById("loginErr");
  const key = document.getElementById("loginKey").value.trim();
  btn.disabled = true; err.classList.remove("show");
  if (await attemptLogin(key)) {
    document.getElementById("login").classList.add("hidden");
    document.getElementById("app").classList.add("ready");
    boot();
  } else {
    err.classList.add("show");
    document.getElementById("loginKey").select();
  }
  btn.disabled = false;
};
document.getElementById("loginKey").addEventListener("keydown", (e) => {
  if (e.key === "Enter") document.getElementById("loginBtn").click();
});
document.getElementById("lockBtn").onclick = lock;

/* ══════════════ navigation ══════════════ */

const VIEW_META = {
  overview: ["Overview", "Live pipeline status and trends"],
  flow:     ["Pipeline Flow", "Every alert advancing through the pipeline, live"],
  alerts:   ["Alerts", "All ingested alerts and their outcomes"],
  ai:       ["AI Content", "Generated bilingual notifications"],
  emails:   ["Emails", "Pending outbox awaiting delivery"],
  logs:     ["Logs", "Structured application log"],
  settings: ["Settings", "Notification recipients and runtime configuration"],
  api:      ["API Docs", "How to send alerts into the platform"],
};

function showView(name) {
  state.view = name;
  document.querySelectorAll("nav a.tab").forEach((a) =>
    a.classList.toggle("active", a.dataset.view === name));
  document.querySelectorAll("section.view").forEach((s) =>
    s.classList.toggle("active", s.id === "view-" + name));
  const [title, sub] = VIEW_META[name] || ["", ""];
  document.getElementById("viewTitle").textContent = title;
  document.getElementById("viewSub").textContent = sub;

  if (name === "flow") renderFlow();
  if (name === "overview") loadStats();
  if (name === "logs") loadLogs();
  if (name === "ai") loadAiContent();
  if (name === "settings") loadSettings();
  if (name === "emails") loadDelivery();
}
document.querySelectorAll("nav a.tab").forEach((a) => (a.onclick = () => showView(a.dataset.view)));

/* ══════════════ overview ══════════════ */

function renderCards() {
  const jobs = [...state.jobs.values()];
  const byStatus = {};
  for (const j of jobs) byStatus[j.status] = (byStatus[j.status] || 0) + 1;
  const active = (byStatus.PENDING || 0) + (byStatus.PROCESSING || 0);

  const cards = [
    ["Total Alerts", jobs.length],
    ["In Flight", active],
    ["Success", byStatus.SUCCESS || 0],
    ["Partial", byStatus.PARTIAL || 0],
    ["Failed", byStatus.FAILED || 0],
    ["Emails Pending", state.emails.length],
  ];
  document.getElementById("statCards").innerHTML = cards
    .map(([l, n]) => `<div class="card"><div class="n">${n}</div><div class="l">${esc(l)}</div></div>`)
    .join("");

  document.getElementById("cAlerts").textContent = jobs.length;
  document.getElementById("cEmails").textContent = state.emails.length;
}

async function loadStats() {
  const hours = Number(document.getElementById("seriesWindow").value) || 24;
  try {
    state.stats = await api(`/stats?hours=${hours}`);
    drawSeries(state.stats.series);
    drawRisk(state.stats.by_risk);
    drawStatus(state.stats.by_status);
    drawSource(state.stats.by_source);
  } catch (e) { /* auth handled upstream */ }
}
document.getElementById("seriesWindow").onchange = loadStats;

/* ══════════════ alerts ══════════════ */

function upsertJob(patch) {
  const id = patch.correlation_id;
  state.jobs.set(id, { ...(state.jobs.get(id) || { correlation_id: id }), ...patch });
}

function jobFromRow(row) {
  const rp = row.raw_payload || {};
  return {
    correlation_id: row.correlation_id,
    source: row.source,
    status: row.status,
    error: row.error,
    created_at: row.created_at,
    updated_at: row.updated_at,
    detection_name: rp.detection_name,
    endpoint_name: rp.endpoint_name,
    risk_level: null,
  };
}

function renderAlerts() {
  const fStatus = document.getElementById("fStatus").value;
  const q = document.getElementById("fSearch").value.trim().toLowerCase();

  let rows = [...state.jobs.values()].sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));
  if (fStatus) rows = rows.filter((j) => j.status === fStatus);
  if (q) {
    rows = rows.filter((j) =>
      [j.detection_name, j.endpoint_name, j.correlation_id, j.source]
        .some((v) => v && String(v).toLowerCase().includes(q)));
  }

  document.getElementById("alertsEmpty").style.display = rows.length ? "none" : "block";
  document.getElementById("alertRows").innerHTML = rows.map((j) => `
    <tr class="clickable" data-id="${esc(j.correlation_id)}">
      <td>${badge(j.status)}</td>
      <td>${j.risk_level ? badge(j.risk_level) : DASH}</td>
      <td>${j.detection_name ? esc(j.detection_name) : DASH}</td>
      <td>${j.endpoint_name ? esc(j.endpoint_name) : DASH}</td>
      <td>${j.source ? badge(j.source) : DASH}</td>
      <td class="muted">${timeAgo(j.updated_at)}</td>
      <td class="mono muted">${shortId(j.correlation_id)}</td>
      <td>${["FAILED","PARTIAL"].includes(j.status)
            ? `<button class="small" data-retry="${esc(j.correlation_id)}">Retry</button>` : ""}</td>
    </tr>`).join("");

  renderCards();
}
document.getElementById("fStatus").onchange = renderAlerts;
document.getElementById("fSearch").oninput = renderAlerts;

document.getElementById("alertRows").addEventListener("click", async (e) => {
  const retry = e.target.getAttribute && e.target.getAttribute("data-retry");
  if (retry) {
    e.stopPropagation();
    e.target.disabled = true;
    try { await api(`/jobs/${encodeURIComponent(retry)}/retry`, { method: "POST" }); toast("Retry queued"); }
    catch (err) { toast("Retry failed: " + err.message, true); e.target.disabled = false; }
    return;
  }
  const tr = e.target.closest("tr[data-id]");
  if (tr) openAlert(tr.getAttribute("data-id"));
});

/* ══════════════ emails ══════════════ */

function renderEmails() {
  const es = state.emails;
  document.getElementById("emailCount").textContent = es.length ? `${es.length} pending` : "";
  document.getElementById("emailsEmpty").style.display = es.length ? "none" : "block";
  document.getElementById("emailRows").innerHTML = es.map((m) => `
    <tr class="clickable" data-email="${esc(m.email_id)}">
      <td>${badge(m.notification_type)}</td>
      <td>${(m.to || []).length ? esc((m.to || []).join(", ")) : DASH}</td>
      <td>${esc(m.subject)}</td>
      <td>${badge(m.risk_level)}</td>
      <td class="muted">${m.created_at ? esc(new Date(m.created_at).toLocaleString()) : "—"}</td>
      <td><button class="small danger" data-del="${esc(m.email_id)}">Discard</button></td>
    </tr>`).join("");
  renderCards();
}

document.getElementById("emailRows").addEventListener("click", async (e) => {
  const del = e.target.getAttribute && e.target.getAttribute("data-del");
  if (del) {
    e.stopPropagation();
    e.target.disabled = true;
    try {
      await api(`/emails/${encodeURIComponent(del)}`, { method: "DELETE" });
      state.emails = state.emails.filter((m) => m.email_id !== del);
      renderEmails(); toast("Email discarded");
    } catch (err) { toast("Discard failed: " + err.message, true); e.target.disabled = false; }
    return;
  }
  const tr = e.target.closest("tr[data-email]");
  if (tr) openEmail(tr.getAttribute("data-email"));
});

function openEmail(id) {
  const m = state.emails.find((x) => x.email_id === id);
  if (!m) return;
  showModal("Queued Email", `
    <div class="kv">
      <div>Type</div><div>${badge(m.notification_type)}</div>
      <div>To</div><div>${esc((m.to || []).join(", "))}</div>
      <div>Subject</div><div>${esc(m.subject)}</div>
      <div>Risk</div><div>${badge(m.risk_level)}</div>
      <div>Endpoint</div><div>${esc(m.endpoint_name)}</div>
      <div>Detection</div><div>${esc(m.detection_name)}</div>
      <div>Correlation ID</div><div class="mono">${esc(m.correlation_id)}</div>
      <div>Status</div><div>${badge(m.status)}</div>
    </div>
    <div class="notif">${esc(m.body)}</div>`);
}

/* ══════════════ mail delivery ══════════════ */

async function loadDelivery() {
  const filter = document.getElementById("deliveryFilter").value;
  try {
    const d = await api("/delivery" + (filter ? `?status=${encodeURIComponent(filter)}` : ""));
    renderDelivery(d);
  } catch (e) { return; }

  try {
    const svc = await api("/delivery/service-status");
    const foot = document.getElementById("serviceStatus");
    if (svc.available && svc.queue) {
      const q = svc.queue;
      foot.innerHTML = `Mail service queue — queued <strong>${esc(q.queued ?? 0)}</strong> · ` +
        `sending <strong>${esc(q.sending ?? 0)}</strong> · sent <strong>${esc(q.sent ?? 0)}</strong> · ` +
        `failed <strong>${esc(q.failed ?? 0)}</strong> <span class="dim">(delivery and retries are handled there)</span>`;
    } else {
      foot.innerHTML = `<span class="muted">Mail service status unavailable: ${esc(svc.error || "unknown")}</span>`;
    }
  } catch (e) { /* non-fatal */ }
}

function renderDelivery(d) {
  const cfg = d.config || {};
  const cfgEl = document.getElementById("deliveryConfig");
  if (!cfg.enabled) {
    cfgEl.innerHTML = '<span style="color:var(--warning)">Delivery disabled</span> — set EMAIL_DELIVERY_ENABLED=true';
  } else if (!cfg.configured) {
    cfgEl.innerHTML = `<span style="color:#f08a8a">Not configured</span> — ${esc(cfg.reason)}`;
  } else {
    cfgEl.innerHTML = `<span style="color:#3ec73e">●</span> ${esc(cfg.provider)} · ${esc(cfg.security_mode)} mode`;
  }

  const c = d.counts || {};
  const cards = [
    ["Awaiting Handoff", d.pending_in_outbox || 0],
    ["Accepted", c.ACCEPTED || 0],
    ["Failed", c.FAILED || 0],
  ];
  document.getElementById("deliveryCards").innerHTML = cards
    .map(([l, n]) => `<div class="card"><div class="n">${n}</div><div class="l">${esc(l)}</div></div>`)
    .join("");

  const rows = d.deliveries || [];
  document.getElementById("deliveryEmpty").style.display = rows.length ? "none" : "block";
  document.getElementById("deliveryRows").innerHTML = rows.map((r) => `
    <tr>
      <td>${badge(r.status)}</td>
      <td>${badge(r.notification_type)}</td>
      <td>${esc((r.recipients || []).join(", "))}</td>
      <td>${esc(r.subject)}</td>
      <td class="muted">${esc(r.attempts)}</td>
      <td class="mono muted">${r.remote_id ? "#" + esc(r.remote_id) : DASH}</td>
      <td class="muted">${r.updated_at ? timeAgo(r.updated_at) : "—"}</td>
    </tr>`).join("");
}

document.getElementById("deliveryFilter").onchange = loadDelivery;

document.getElementById("dispatchNow").onclick = async (e) => {
  e.target.disabled = true;
  try {
    const r = await api("/delivery/dispatch", { method: "POST" });
    if (r.skipped) toast(`Nothing sent: ${r.skipped}`, true);
    else toast(`Accepted ${r.accepted} · failed ${r.failed} · still queued ${r.pending}`);
    await boot();
    loadDelivery();
  } catch (err) { toast("Dispatch failed: " + err.message, true); }
  e.target.disabled = false;
};

/* ══════════════ AI content ══════════════ */

async function loadAiContent() {
  try {
    const res = await api("/ai-content?limit=50");
    state.ai = res.items;
    renderAiContent();
  } catch (e) { /* handled */ }
}

function renderAiContent() {
  const items = state.ai;
  document.getElementById("aiCount").textContent = items.length ? `${items.length} alerts` : "";
  document.getElementById("aiEmpty").style.display = items.length ? "none" : "block";
  document.getElementById("aiList").innerHTML = items.map((it, i) => `
    <div class="aiitem" data-ai="${i}">
      <div class="t">
        ${badge(it.risk_level)}
        <strong>${esc(it.detection_name)}</strong>
        <span class="muted">on ${esc(it.endpoint_name)}</span>
        <span class="muted mono" style="margin-left:auto">${esc(new Date(it.processed_at).toLocaleString())}</span>
      </div>
      <div class="snip">${esc(it.ai_output.client_notification_ja.summary)}</div>
    </div>`).join("");
}

document.getElementById("aiList").addEventListener("click", (e) => {
  const el = e.target.closest("[data-ai]");
  if (!el) return;
  const it = state.ai[Number(el.dataset.ai)];
  if (it) showModal("AI Notifications", notificationTabs(it.ai_output), true);
});

function notificationTabs(ai) {
  const bullets = (a) => (a || []).map((x) => `- ${x}`).join("\n");
  const tabs = [
    ["client", "Client (JA)",
      `${ai.client_notification_ja.summary}\n\n【現在の状況】\n${ai.client_notification_ja.current_status}\n\n【確認事項】\n${ai.client_notification_ja.required_confirmation}`],
    ["cthree", "C-Three (JA)",
      `${ai.cthree_notification_ja.summary}\n\n【評価】\n${ai.cthree_notification_ja.assessment}\n\n【フロントオフィス】\n${ai.cthree_notification_ja.front_office_notes}\n\n【クライアント返信案】\n${ai.cthree_notification_ja.draft_client_response}`],
    ["internal", "Internal (JA)",
      `${ai.internal_notification_ja.summary}\n\n【評価】\n${ai.internal_notification_ja.assessment}\n\n【推奨アクション】\n${bullets(ai.internal_notification_ja.recommended_actions)}\n\n【返信案】\n${ai.internal_notification_ja.draft_client_response}`],
    ["engineer", "Engineer (EN)",
      `${ai.engineer_notification_en.alert_summary}\n\nASSESSMENT\n${ai.engineer_notification_en.assessment}\n\nCONFIRMED\n${bullets(ai.engineer_notification_en.confirmed_information)}\n\nUNKNOWN\n${bullets(ai.engineer_notification_en.unknown_information)}\n\nINVESTIGATE\n${bullets(ai.engineer_notification_en.investigation_items)}\n\nRECOMMENDED ACTIONS\n${bullets(ai.engineer_notification_en.recommended_actions)}\n\nDRAFT CLIENT RESPONSE\n${ai.engineer_notification_en.draft_client_response}`],
  ];
  return `
    <div class="tabs">${tabs.map((t, i) =>
      `<div class="tabbtn ${i === 0 ? "active" : ""}" data-tab="${esc(t[0])}">${esc(t[1])}</div>`).join("")}</div>
    ${tabs.map((t, i) =>
      `<div class="notif" data-panel="${esc(t[0])}" style="${i === 0 ? "" : "display:none"}">${esc(t[2])}</div>`).join("")}`;
}

/* ══════════════ alert detail modal ══════════════ */

function showModal(title, bodyHtml) {
  const box = document.getElementById("modalBox");
  box.innerHTML = `
    <div class="head"><h3>${esc(title)}</h3><button class="small" id="closeModal">Close</button></div>
    <div class="body">${bodyHtml}</div>`;
  document.getElementById("overlay").classList.add("show");
  document.getElementById("closeModal").onclick = () =>
    document.getElementById("overlay").classList.remove("show");
  wireTabs(box);
}

function wireTabs(box) {
  box.querySelectorAll(".tabbtn").forEach((tab) => (tab.onclick = () => {
    box.querySelectorAll(".tabbtn").forEach((t) => t.classList.remove("active"));
    box.querySelectorAll("[data-panel]").forEach((p) => (p.style.display = "none"));
    tab.classList.add("active");
    const panel = box.querySelector(`[data-panel="${CSS.escape(tab.dataset.tab)}"]`);
    if (panel) panel.style.display = "block";
  }));
}

document.getElementById("overlay").addEventListener("click", (e) => {
  if (e.target.id === "overlay") e.currentTarget.classList.remove("show");
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") document.getElementById("overlay").classList.remove("show");
});

const kvRow = (k, v) => `<div>${esc(k)}</div><div>${esc(v)}</div>`;

async function openAlert(id) {
  showModal("Loading…", '<p class="muted">Fetching alert detail…</p>');
  let data;
  try { data = await api(`/jobs/${encodeURIComponent(id)}`); }
  catch (e) { showModal("Error", `<p class="muted">${esc(e.message)}</p>`); return; }

  const job = data.job, r = data.result;
  const a = r && r.normalized_alert;

  let html = `<div class="kv">
      <div>Correlation ID</div><div class="mono">${esc(job.correlation_id)}</div>
      <div>Status</div><div>${badge(job.status)}</div>
      <div>Source</div><div>${badge(job.source)}</div>
      ${kvRow("Created", new Date(job.created_at * 1000).toLocaleString())}
      ${kvRow("Updated", new Date(job.updated_at * 1000).toLocaleString())}
      ${job.error ? `<div>Error</div><div style="color:#f08a8a">${esc(job.error)}</div>` : ""}
    </div>`;

  if (a) {
    html += `<div class="kv">
      ${kvRow("Detection", a.detection_name)}
      ${kvRow("Endpoint", `${a.endpoint_name} (${a.endpoint_type})`)}
      ${kvRow("Severity (reported)", a.severity)}
      <div>Risk (computed)</div><div>${badge(r.risk_level)}</div>
      ${kvRow("Rationale", r.risk_rationale)}
      ${kvRow("User", a.user_name)}
      ${kvRow("OS", a.os_name)}
      ${kvRow("Action Taken", a.action_taken)}
      ${kvRow("Handled / Isolated", `${a.threat_handled} / ${a.isolation_status}`)}
      <div>Object URI</div><div class="mono">${esc(a.object_uri)}</div>
      <div>File Hash</div><div class="mono">${esc(a.file_hash)}</div>
      <div>IP / Domain</div><div class="mono">${esc(a.ip_address)} / ${esc(a.domain)}</div>
    </div>`;
  }

  if (r && r.threat_intel) {
    const ti = r.threat_intel;
    html += `<div class="intel-row">
      <div class="intel-box"><h4>VirusTotal</h4>${badge(ti.virustotal.status)}
        <div class="muted" style="margin-top:7px">${esc(ti.virustotal.positives)}/${esc(ti.virustotal.total)} engines flagged</div></div>
      <div class="intel-box"><h4>AbuseIPDB</h4>${badge(ti.abuseipdb.status)}
        <div class="muted" style="margin-top:7px">${esc(ti.abuseipdb.abuse_confidence_score)}% confidence · ${esc(ti.abuseipdb.total_reports)} reports</div></div>
    </div>`;
  }

  html += r && r.ai_output
    ? notificationTabs(r.ai_output)
    : '<p class="muted">No AI output for this alert.</p>';

  showModal("Alert Detail", html);
}

/* ══════════════ logs ══════════════ */

let logTimer = null;

async function loadLogs() {
  const level = document.getElementById("logLevel").value;
  const q = document.getElementById("logSearch").value.trim();
  const params = new URLSearchParams({ limit: "300" });
  if (level) params.set("level", level);
  if (q) params.set("q", q);

  try {
    const res = await api("/logs?" + params.toString());
    renderLogs(res.lines);
  } catch (e) { /* handled */ }

  clearTimeout(logTimer);
  if (document.getElementById("logAuto").checked && state.view === "logs") {
    logTimer = setTimeout(loadLogs, 3000);
  }
}

function renderLogs(lines) {
  document.getElementById("logsEmpty").style.display = lines.length ? "none" : "block";
  const skip = new Set(["event", "level", "timestamp", "logger", "filename", "lineno", "func_name"]);
  document.getElementById("logList").innerHTML = lines.slice().reverse().map((e) => {
    const ts = e.timestamp ? String(e.timestamp).slice(11, 19) : "";
    const lvl = (e.level || "info").toLowerCase();
    const extras = Object.keys(e)
      .filter((k) => !skip.has(k))
      .map((k) => `<span class="kvp">${esc(k)}=</span>${esc(String(e[k]).slice(0, 220))}`)
      .join("  ");
    return `<div class="logline">
      <span class="dim">${esc(ts)}</span>
      <span class="lvl ${esc(lvl)}">${esc(lvl)}</span>
      <span class="logmsg"><strong>${esc(e.event || "")}</strong> ${extras}</span>
    </div>`;
  }).join("");
}
document.getElementById("logLevel").onchange = loadLogs;
document.getElementById("logSearch").oninput = () => { clearTimeout(logTimer); logTimer = setTimeout(loadLogs, 300); };
document.getElementById("logAuto").onchange = loadLogs;

/* ══════════════ settings ══════════════ */

const RECIPIENT_FIELDS = [
  ["client", "client_notification_emails"],
  ["cthree", "cthree_notification_emails"],
  ["internal", "internal_notification_emails"],
  ["engineer", "engineer_notification_emails"],
];

async function loadSettings() {
  try {
    const s = await api("/settings");
    for (const [ui, key] of RECIPIENT_FIELDS) {
      document.getElementById("in-" + ui).value = s.recipients[key].value || "";
      const src = document.getElementById("src-" + ui);
      src.textContent = s.recipients[key].source === "dashboard" ? "saved here" : "from .env";
    }
    document.getElementById("runtimeKv").innerHTML =
      Object.entries(s.runtime).map(([k, v]) =>
        `<div>${esc(k.replace(/_/g, " "))}</div><div class="mono">${esc(v)}</div>`).join("");
  } catch (e) { /* handled */ }
}

document.getElementById("saveRecipients").onclick = async () => {
  const btn = document.getElementById("saveRecipients");
  btn.disabled = true;
  const body = {};
  for (const [ui, key] of RECIPIENT_FIELDS) body[key] = document.getElementById("in-" + ui).value.trim();
  try {
    await api("/settings/recipients", { method: "PUT", body: JSON.stringify(body) });
    toast("Recipients saved — applies to the next alert");
    loadSettings();
  } catch (e) { toast("Save failed: " + e.message, true); }
  btn.disabled = false;
};
document.getElementById("reloadRecipients").onclick = loadSettings;

/* ══════════════ API docs ══════════════ */

function renderApiDocs() {
  const o = location.origin;
  document.getElementById("ep-eset").textContent = `POST ${o}/webhook/eset`;
  document.getElementById("ep-syslog").textContent = `POST ${o}/webhook/syslog`;
  document.getElementById("ep-status").textContent = `GET  ${o}/status/{correlation_id}`;
  document.getElementById("ep-health").textContent = `GET  ${o}/health`;

  const body = {
    source: "ESET_PROTECT_CLOUD",
    event_type: "Threat Detection",
    alert_id: "alert-0001",
    occurred_at: "2026-08-17T10:00:00Z",
    severity: "HIGH",
    detection_name: "Win32/TrojanDownloader.Agent.YHV",
    endpoint_name: "FINANCE-PC-09",
    endpoint_type: "Server",
    user_name: "charlie.brown",
    os_name: "Windows Server 2022",
    action_taken: "Connection terminated",
    threat_handled: false,
    isolation_status: false,
    file_hash: "a4f5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5",
    ip_address: "185.220.101.5",
    raw_subject: "High Risk Trojan Activity on FINANCE-PC-09",
    raw_content: "A connection to a known C2 server was detected and blocked.",
  };
  const curl =
    `curl -X POST ${o}/webhook/eset \\\n` +
    `  -H "Authorization: Bearer $ESET_WEBHOOK_AUTH_TOKEN" \\\n` +
    `  -H "Content-Type: application/json" \\\n` +
    `  -d '${JSON.stringify(body, null, 2)}'`;
  document.getElementById("curlExample").textContent = curl;
  document.getElementById("copyCurl").onclick = () => {
    navigator.clipboard.writeText(curl).then(
      () => toast("curl copied"),
      () => toast("Copy blocked by browser", true));
  };

  const routes = [
    ["GET", "/dashboard/api/jobs", "List alerts (limit, offset, status)"],
    ["GET", "/dashboard/api/jobs/{id}", "Alert detail with full pipeline result"],
    ["POST", "/dashboard/api/jobs/{id}/retry", "Re-run a FAILED or PARTIAL alert"],
    ["GET", "/dashboard/api/alerts", "Alert index summary"],
    ["GET", "/dashboard/api/ai-content", "Generated notifications"],
    ["GET", "/dashboard/api/emails", "Pending email outbox"],
    ["DELETE", "/dashboard/api/emails/{id}", "Discard a pending email"],
    ["GET", "/dashboard/api/stats", "Aggregates and time series"],
    ["GET", "/dashboard/api/logs", "Tail structured logs"],
    ["GET", "/dashboard/api/settings", "Recipients and runtime config"],
    ["PUT", "/dashboard/api/settings/recipients", "Update notification recipients"],
    ["WS", "/dashboard/api/ws", "Live pipeline event stream"],
  ];
  document.getElementById("apiRows").innerHTML = routes.map(([m, p, d]) =>
    `<tr><td class="mono"><strong>${esc(m)}</strong></td><td class="mono">${esc(p)}</td><td class="muted">${esc(d)}</td></tr>`).join("");
}

/* ══════════════ health ══════════════ */

const setDot = (id, ok) => (document.getElementById(id).className = "dot " + (ok ? "ok" : "bad"));

async function loadHealth() {
  try {
    const h = await (await fetch("/health")).json();
    setDot("dbDot", h.database?.status === "ok");
    setDot("geminiDot", h.gemini_api?.status === "configured");
    setDot("dirDot", h.output_directory?.status === "ok");
    setDot("udpDot", h.syslog_listener?.udp === "ok");
    setDot("tcpDot", h.syslog_listener?.tcp === "ok");
  } catch (e) { /* transient */ }
}

/* ══════════════ websocket ══════════════ */

function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const key = dashKey();
  const ws = new WebSocket(`${proto}://${location.host}${API}/ws${key ? "?key=" + encodeURIComponent(key) : ""}`);
  window._ws = ws;

  ws.onopen = () => {
    document.getElementById("wsDot").className = "dot ok live";
    document.getElementById("wsLabel").textContent = "live";
  };
  ws.onclose = () => {
    document.getElementById("wsDot").className = "dot bad";
    document.getElementById("wsLabel").textContent = "reconnecting…";
    if (sessionStorage.getItem("dash_key") !== null) setTimeout(connectWs, 2000);
  };
  ws.onerror = () => ws.close();
  ws.onmessage = (evt) => handleEvent(JSON.parse(evt.data));
}

function handleEvent(msg) {
  const d = msg.data;
  if (msg.type === "job_status_changed") {
    const prev = state.jobs.get(d.correlation_id) || {};
    upsertJob({ ...prev, correlation_id: d.correlation_id, status: d.status,
                error: d.error, updated_at: d.updated_at, source: prev.source || d.source });
    renderAlerts();
    if (d.status === "PENDING") ensureRun(d.correlation_id, d.source);

  } else if (msg.type === "pipeline_stage") {
    applyStage(d);

  } else if (msg.type === "alert_completed") {
    upsertJob({
      correlation_id: d.correlation_id, source: d.source, status: d.pipeline_status,
      risk_level: d.risk_level, error: d.error, updated_at: Date.now() / 1000,
      detection_name: d.normalized_alert?.detection_name,
      endpoint_name: d.normalized_alert?.endpoint_name,
    });
    renderAlerts();
    if (state.view === "overview") loadStats();
    if (state.view === "ai" && d.ai_output) loadAiContent();

  } else if (msg.type === "email_queued") {
    state.emails.unshift(d);
    renderEmails();

  } else if (msg.type === "email_accepted") {
    // Handed to the mail service — it leaves our pending outbox
    state.emails = state.emails.filter((m) => m.email_id !== d.email_id);
    renderEmails();
    if (state.view === "emails") loadDelivery();
    toast(`Email accepted by mail service (#${d.remote_id ?? "?"})`);

  } else if (msg.type === "email_failed") {
    state.emails = state.emails.filter((m) => m.email_id !== d.email_id);
    renderEmails();
    if (state.view === "emails") loadDelivery();
    toast(`Email handoff failed: ${d.error || "unknown error"}`, true);
  }
}

/* ══════════════ boot ══════════════ */

async function boot() {
  renderApiDocs();
  try {
    const [jobs, emails] = await Promise.all([api("/jobs?limit=300"), api("/emails")]);
    state.jobs.clear();
    for (const row of jobs.jobs) upsertJob(jobFromRow(row));
    state.emails = emails.emails;
    renderAlerts();
    renderEmails();
  } catch (e) { return; }

  await loadStats();
  loadHealth();
  connectWs();
  setInterval(loadHealth, 20000);
  setInterval(renderAlerts, 15000);   // keep relative timestamps fresh
}

document.getElementById("refreshBtn").onclick = () => {
  boot();
  if (state.view === "logs") loadLogs();
  if (state.view === "ai") loadAiContent();
  if (state.view === "settings") loadSettings();
};

// Resume an existing session, otherwise show the login gate.
(async () => {
  if (dashKey() && (await attemptLogin(dashKey()))) {
    document.getElementById("login").classList.add("hidden");
    document.getElementById("app").classList.add("ready");
    boot();
  } else {
    // No key configured server-side? Then the probe succeeds with an empty key.
    if (await attemptLogin("")) {
      document.getElementById("login").classList.add("hidden");
      document.getElementById("app").classList.add("ready");
      boot();
    } else {
      document.getElementById("loginKey").focus();
    }
  }
})();
