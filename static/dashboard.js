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
  aiTraces: new Map(),  // trace_id -> trace summary row
  aiLive: [],           // bounded live AI activity feed
  aiOverview: null,
  // "connecting" | "live" | "reconnecting". Held in state rather than read back
  // off the DOM, so a language switch re-renders the CURRENT status instead of
  // resetting the label to "connecting…" while the dot stays green.
  wsState: "connecting",
  // The element focus should return to when the modal closes.
  modalReturnFocus: null,
  // The AI Content item currently open in the modal, if any. Kept so switching
  // the language re-renders the open analysis instead of leaving a Japanese
  // reader looking at the English text until they close and reopen it.
  openAiItem: null,
};

const STAGES = ["INGEST", "NORMALIZE", "INTEL", "RISK", "AI", "LINT", "OUTPUT", "EMAIL", "SEND"];
// Looked up live (not a static object) so it always reflects the current language —
// see i18n.js. Keys match src/utils/events.py: STAGES exactly.
const STAGE_KEY = {
  INGEST: "stage_ingest", NORMALIZE: "stage_normalize", RISK: "stage_risk", INTEL: "stage_intel",
  AI: "stage_ai", LINT: "stage_lint", OUTPUT: "stage_output", EMAIL: "stage_email", SEND: "stage_send",
};
const STAGE_LABEL = new Proxy({}, { get: (_t, stage) => t(STAGE_KEY[stage] || stage) });

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
  "OK","STARTED","BLOCKED","ERROR",
  "SAFE","REVIEW","SENSITIVE_DATA_DETECTED","SECRET_DETECTED","FAILED_SECURITY_CHECK",
]);
/** noTranslate=true is used by the Emails section's own rendering, which must keep
 * its current wording regardless of the dashboard language toggle. */
function badge(value, noTranslate) {
  const v = value && BADGES.has(value) ? value : "UNKNOWN";
  return `<span class="badge b-${v}"><span class="g"></span>${esc(tBadgeLabel(value || "UNKNOWN", noTranslate))}</span>`;
}
const DASH = '<span class="dim">—</span>';

/** BCP-47 tag for the active dashboard language.
 *
 * Every toLocaleString() here used to be called with no locale, so it followed
 * the BROWSER's locale: a Japanese dashboard on an en-GB browser printed
 * "22/09/2026, 12:26" instead of 2026/09/22. The date format has to follow the
 * language the operator picked, like every other string on the page. */
function uiLocale() {
  return state_lang.current === "ja" ? "ja-JP" : "en-GB";
}

/** Date+time in the active language. */
function fmtDateTime(value) {
  const d = value instanceof Date ? value : new Date(value);
  return isNaN(d) ? "—" : d.toLocaleString(uiLocale());
}

/** Time of day with seconds, in the active language (event feeds, timelines). */
function fmtClock(value) {
  const d = value instanceof Date ? value : new Date(value);
  return isNaN(d) ? "—" : d.toLocaleTimeString(uiLocale());
}

/** Time-of-day only, in the active language (chart axes, tooltips). */
function fmtTime(value) {
  const d = value instanceof Date ? value : new Date(value);
  return isNaN(d) ? "—" : d.toLocaleTimeString(uiLocale(), { hour: "2-digit", minute: "2-digit" });
}

/** Stat-tile / hero numbers: compact past 10k so the value keeps its display
 * size instead of overflowing the tile (1,284 → "1,284"; 12,900 → "12.9K"). */
function fmtCount(n) {
  if (typeof n !== "number" || !isFinite(n)) return "0";
  if (Math.abs(n) < 10000) return n.toLocaleString(uiLocale());
  if (Math.abs(n) < 1000000) return (n / 1000).toFixed(1).replace(/\.0$/, "") + "K";
  return (n / 1000000).toFixed(1).replace(/\.0$/, "") + "M";
}

/** noTranslate=true is used by the Emails section's own rendering (Handoff
 * History), which must keep its current English wording regardless of language. */
function timeAgo(ts, noTranslate) {
  if (!ts) return "—";
  const s = Math.max(0, Date.now() / 1000 - ts);
  if (noTranslate) {
    if (s < 60) return Math.floor(s) + "s ago";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    return Math.floor(s / 86400) + "d ago";
  }
  if (s < 60) return t("timeago_seconds", Math.floor(s));
  if (s < 3600) return t("timeago_minutes", Math.floor(s / 60));
  if (s < 86400) return t("timeago_hours", Math.floor(s / 3600));
  return t("timeago_days", Math.floor(s / 86400));
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
    const err = new Error(detail);
    err.status = res.status;
    err.retryAfter = Number(res.headers.get("Retry-After")) || 0;
    throw err;
  }
  return res.status === 204 ? null : res.json();
}

function lock() {
  sessionStorage.removeItem("dash_key");
  document.getElementById("app").classList.remove("ready");
  document.getElementById("login").classList.remove("hidden");
  if (window._ws) { try { window._ws.close(); } catch (e) { /* already closed */ } }
}

/** Resolves to null on success, or the message to show under the key field. */
async function attemptLogin(key) {
  sessionStorage.setItem("dash_key", key);
  try {
    await api("/jobs?limit=1");     // cheapest authenticated probe
    return null;
  } catch (e) {
    sessionStorage.removeItem("dash_key");
    if (e.status === 429) return t("login_err_throttled", Math.ceil((e.retryAfter || 60) / 60));
    return t("login_err");
  }
}

document.getElementById("loginBtn").onclick = async () => {
  const btn = document.getElementById("loginBtn");
  const err = document.getElementById("loginErr");
  const key = document.getElementById("loginKey").value.trim();
  btn.disabled = true; err.classList.remove("show");
  const problem = await attemptLogin(key);
  if (!problem) {
    document.getElementById("login").classList.add("hidden");
    document.getElementById("app").classList.add("ready");
    boot();
  } else {
    err.textContent = problem;
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

// Translation-key pairs, looked up live at render time — Emails is deliberately
// literal English (not keys), since that section's wording must never change.
const VIEW_META = {
  overview: ["view_overview_title", "view_overview_sub"],
  flow:     ["view_flow_title", "view_flow_sub"],
  alerts:   ["view_alerts_title", "view_alerts_sub"],
  ai:       ["view_ai_title", "view_ai_sub"],
  "ai-visibility": ["view_aivis_title", "view_aivis_sub"],
  emails:   null,   // rendered literally below — see updateViewHeader()
  logs:     ["view_logs_title", "view_logs_sub"],
  settings: ["view_settings_title", "view_settings_sub"],
  api:      ["view_api_title", "view_api_sub"],
};
const EMAILS_VIEW_HEADER = ["Emails", "Pending outbox awaiting delivery"];

function updateViewHeader(name) {
  const meta = VIEW_META[name];
  const [title, sub] = meta ? [t(meta[0]), t(meta[1])] : EMAILS_VIEW_HEADER;
  document.getElementById("viewTitle").textContent = title;
  document.getElementById("viewSub").textContent = sub;
}

function showView(name) {
  state.view = name;
  document.querySelectorAll("nav a.tab").forEach((a) => {
    const selected = a.dataset.view === name;
    a.classList.toggle("active", selected);
    if (selected) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  });
  document.querySelectorAll("section.view").forEach((s) =>
    s.classList.toggle("active", s.id === "view-" + name));
  updateViewHeader(name);

  if (name === "flow") renderFlow();
  if (name === "overview") loadStats();
  if (name === "logs") loadLogs();
  if (name === "ai") loadAiContent();
  if (name === "ai-visibility") loadAiVisibility();
  if (name === "settings") loadSettings();
  if (name === "emails") loadDelivery();
}

/** Called by i18n.js's setLang() after the language changes. Re-renders whatever
 * the current tab already has cached, WITHOUT re-fetching from the network, except
 * where a fetch is cheap and already the normal render path (settings, api docs).
 * The Emails tab is deliberately excluded — its content never changes with language. */
function refreshCurrentViewTranslations() {
  updateViewHeader(state.view);
  renderCards();
  renderAlerts();
  if (state.view === "flow") renderFlow();
  if (state.view === "overview" && state.stats) {
    drawSeries(state.stats.series);
    drawRisk(state.stats.by_risk);
    drawStatus(state.stats.by_status);
    drawSource(state.stats.by_source);
  }
  if (state.view === "ai") renderAiContent();
  // The AI analysis inside an open modal is language-dependent too (the engineer
  // report is generated in both languages), so re-render it in place.
  if (state.openAiItem && document.getElementById("overlay").classList.contains("show")) {
    openAiModal(state.openAiItem);
  }
  if (state.view === "ai-visibility") {
    if (state.aiOverview) renderAiOverview(state.aiOverview);
    renderAiTraces();
    renderAiLiveFeed();
  }
  if (state.view === "logs" && logState.res) renderLogs();
  if (state.view === "settings") loadSettings();
  if (state.view === "api") renderApiDocs();
  // state.view === "emails": intentionally does nothing.
}
document.querySelectorAll("nav a.tab").forEach((a) => {
  // These are page navigation links, not a tablist. A real href gives them
  // native keyboard activation and the expected screen-reader semantics.
  a.href = "#view-" + a.dataset.view;
  a.removeAttribute("role");
  a.removeAttribute("aria-selected");
  if (a.classList.contains("active")) a.setAttribute("aria-current", "page");
  a.onclick = (e) => { e.preventDefault(); showView(a.dataset.view); };
});

/* ══════════════ overview ══════════════ */

function renderCards() {
  const jobs = [...state.jobs.values()];
  const byStatus = {};
  for (const j of jobs) byStatus[j.status] = (byStatus[j.status] || 0) + 1;
  const active = (byStatus.PENDING || 0) + (byStatus.PROCESSING || 0);

  // [label, value, tone]. The tone is the CSS token for the tile's edge rule —
  // status tokens where the tile counts a state (succeeded / degraded / failed),
  // neutral ones where it is just a total. It is redundant with the label by
  // design; nothing here is encoded in colour alone.
  const cards = [
    [t("card_total_alerts"), jobs.length, "var(--accent)"],
    [t("card_in_flight"), active, "var(--cat-1)"],
    [t("card_success"), byStatus.SUCCESS || 0, "var(--good)"],
    [t("card_partial"), byStatus.PARTIAL || 0, "var(--warning)"],
    [t("card_failed"), byStatus.FAILED || 0, "var(--critical)"],
    [t("card_emails_pending"), state.emails.length, "var(--dim)"],
  ];
  document.getElementById("statCards").innerHTML = cards
    .map(([l, n, tone]) =>
      `<div class="card${n === 0 ? " zero" : ""}" style="--tone:${tone}">` +
      `<div class="n">${fmtCount(n)}</div><div class="l">${esc(l)}</div></div>`)
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

/** The normalizer writes "UNKNOWN" for fields it could not find; show those as blank. */
function knownValue(v) {
  return v && v !== "UNKNOWN" ? v : undefined;
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
    indicators: [rp.ip_address, rp.file_hash, rp.domain, rp.url, rp.object_uri],
    // The severity ESET itself reported, as distinct from the risk level this
    // platform computed — the two disagreeing (HIGH reported, LOW computed
    // because the threat was already handled) is exactly what the risk engine
    // exists to express, and the table can only show that if it keeps both.
    reported_severity: rp.severity || null,
    // Not in the jobs table: the computed risk lives in the result files, and is
    // merged in from /alerts by loadRiskLevels(). Left null here so a job that
    // has not finished shows "—" rather than a stale level.
    risk_level: null,
  };
}

/** Merges the computed risk level into every job already in state.
 *
 * The jobs table does not store risk — it is written to the result file at the
 * end of the pipeline — so before this ran, the Alerts table's Risk column was
 * "—" for every row that had not arrived live over the WebSocket during this
 * page's own session. After any reload, the column an analyst triages by was
 * blank for the entire history. /dashboard/api/alerts is the index of finished
 * results and already carries risk_level per correlation_id. */
async function loadRiskLevels() {
  try {
    const { alerts } = await api("/alerts");
    for (const a of alerts || []) {
      const job = state.jobs.get(a.correlation_id);
      // Only annotate jobs we already know about; /alerts can outlive the
      // 300-row jobs window, and a risk level with no job row has nothing to
      // attach to.
      if (job && a.risk_level) job.risk_level = a.risk_level;
      // Payloads not in ESET's shape have no detection_name/endpoint_name in
      // the raw body; the normalized (alias-resolved) names come from here.
      if (job && !job.detection_name && a.detection_name) job.detection_name = a.detection_name;
      if (job && !job.endpoint_name && a.endpoint_name) job.endpoint_name = a.endpoint_name;
    }
  } catch (e) { /* non-fatal: the column falls back to "—" */ }
}

function renderAlerts() {
  const fStatus = document.getElementById("fStatus").value;
  const fRisk = document.getElementById("fRisk").value;
  const q = document.getElementById("fSearch").value.trim().toLowerCase();

  let rows = [...state.jobs.values()].sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));
  if (fStatus) rows = rows.filter((j) => j.status === fStatus);
  if (fRisk) rows = rows.filter((j) => (j.risk_level || "UNKNOWN") === fRisk);
  if (q) {
    rows = rows.filter((j) =>
      [j.detection_name, j.endpoint_name, j.correlation_id, j.source, ...(j.indicators || [])]
        .some((v) => v && String(v).toLowerCase().includes(q)));
  }

  document.getElementById("alertsEmpty").style.display = rows.length ? "none" : "block";
  if (!rows.length && state.jobs.size) document.getElementById("alertsEmpty").textContent = t("alerts_no_matches");

  // Client-side paging over the loaded window (newest 500 jobs).
  const pages = Math.max(1, Math.ceil(rows.length / alertsPaging.size));
  alertsPaging.page = Math.min(alertsPaging.page, pages);
  const start = (alertsPaging.page - 1) * alertsPaging.size;
  const total = rows.length;
  rows = rows.slice(start, start + alertsPaging.size);
  document.getElementById("alertsPager").style.display = total > 25 ? "" : "none";
  document.getElementById("alertsRangeText").textContent =
    t("logs_showing", fmtCount(total ? start + 1 : 0), fmtCount(start + rows.length), fmtCount(total));
  document.getElementById("alertsPageText").textContent = `${t("page_word")} ${alertsPaging.page} ${t("page_of", pages)}`;
  document.getElementById("alertsPrev").disabled = alertsPaging.page <= 1;
  document.getElementById("alertsNext").disabled = alertsPaging.page >= pages;
  setSegActive(document.getElementById("alertsPageSize"), "data-size", alertsPaging.size);

  document.getElementById("alertRows").innerHTML = rows.map((j) => `
    <tr class="clickable" data-id="${esc(j.correlation_id)}">
      <td>${badge(j.status)}</td>
      <td>${j.risk_level ? badge(j.risk_level) : DASH}</td>
      <td>${j.detection_name ? esc(j.detection_name) : DASH}</td>
      <td>${j.endpoint_name ? esc(j.endpoint_name) : DASH}</td>
      <td>${j.source ? badge(j.source) : DASH}</td>
      <td class="muted">${timeAgo(j.updated_at)}</td>
      <td class="mono muted">${shortId(j.correlation_id)}</td>
      <td class="row" style="gap:6px;flex-wrap:nowrap">
        <button class="small" data-timeline="${esc(j.correlation_id)}" title="${esc(t("modal_alert_timeline"))}">${esc(t("btn_timeline"))}</button>
        <button class="small" data-raw="${esc(j.correlation_id)}" title="${esc(t("stage_view_raw"))}">${esc(t("btn_raw"))}</button>
        ${["FAILED","PARTIAL"].includes(j.status)
            ? `<button class="small" data-retry="${esc(j.correlation_id)}">${esc(t("btn_retry"))}</button>` : ""}
      </td>
    </tr>`).join("");
  makeRowsFocusable(document.getElementById("alertRows"), "tr.clickable");

  renderCards();
}
const alertsPaging = { page: 1, size: 25 };
function refilterAlerts() { alertsPaging.page = 1; renderAlerts(); }
document.getElementById("fStatus").onchange = refilterAlerts;
document.getElementById("fRisk").onchange = refilterAlerts;
document.getElementById("fSearch").oninput = refilterAlerts;
document.getElementById("alertsPrev").onclick = () => { alertsPaging.page--; renderAlerts(); };
document.getElementById("alertsNext").onclick = () => { alertsPaging.page++; renderAlerts(); };
document.getElementById("alertsPageSize").addEventListener("click", (e) => {
  const b = e.target.closest("[data-size]");
  if (b) { alertsPaging.size = Number(b.dataset.size); alertsPaging.page = 1; renderAlerts(); }
});

document.getElementById("alertRows").addEventListener("click", async (e) => {
  const timeline = e.target.getAttribute && e.target.getAttribute("data-timeline");
  if (timeline) {
    e.stopPropagation();
    openAlertTimeline(timeline);
    return;
  }
  const raw = e.target.getAttribute && e.target.getAttribute("data-raw");
  if (raw) {
    e.stopPropagation();
    openRawPayload(raw);
    return;
  }
  const retry = e.target.getAttribute && e.target.getAttribute("data-retry");
  if (retry) {
    e.stopPropagation();
    e.target.disabled = true;
    try { await api(`/jobs/${encodeURIComponent(retry)}/retry`, { method: "POST" }); toast(t("toast_retry_queued")); }
    catch (err) { toast(t("toast_retry_failed") + tBackendText(err.message), true); e.target.disabled = false; }
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
      <td>${badge(m.notification_type, true)}</td>
      <td>${(m.to || []).length ? esc((m.to || []).join(", ")) : DASH}</td>
      <td>${esc(m.subject)}</td>
      <td>${badge(m.risk_level, true)}</td>
      <td class="muted">${m.created_at ? esc(fmtDateTime(m.created_at)) : "—"}</td>
      <td><button class="small danger" data-del="${esc(m.email_id)}">Discard</button></td>
    </tr>`).join("");
  makeRowsFocusable(document.getElementById("emailRows"), "tr.clickable");
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
      <div>Type</div><div>${badge(m.notification_type, true)}</div>
      <div>To</div><div>${esc((m.to || []).join(", "))}</div>
      <div>Subject</div><div>${esc(m.subject)}</div>
      <div>Risk</div><div>${badge(m.risk_level, true)}</div>
      <div>Endpoint</div><div>${esc(m.endpoint_name)}</div>
      <div>Detection</div><div>${esc(m.detection_name)}</div>
      <div>Correlation ID</div><div class="mono">${esc(m.correlation_id)}</div>
      <div>Status</div><div>${badge(m.status, true)}</div>
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
    } else if (svc.reachable) {
      // The service answered its health probe, so this is a configuration
      // problem on our side, not an outage on theirs — say which, because the
      // two have opposite fixes.
      foot.innerHTML = `<span style="color:var(--text-warn)">●</span> ` +
        `Mail service is up, but this platform could not read its queue: ${esc(svc.error || "unknown")}`;
    } else {
      foot.innerHTML = `<span style="color:var(--text-danger)">●</span> ` +
        `Mail service unreachable: ${esc(svc.error || "unknown")}`;
    }
  } catch (e) { /* non-fatal */ }
}

function renderDelivery(d) {
  const cfg = d.config || {};
  const cfgEl = document.getElementById("deliveryConfig");
  if (!cfg.enabled) {
    cfgEl.innerHTML = '<span style="color:var(--warning)">Delivery disabled</span> — set EMAIL_DELIVERY_ENABLED=true';
  } else if (!cfg.configured) {
    cfgEl.innerHTML = `<span style="color:var(--text-danger)">Not configured</span> — ${esc(cfg.reason)}`;
  } else {
    cfgEl.innerHTML = `<span style="color:var(--text-good)">●</span> ${esc(cfg.provider)} · ${esc(cfg.security_mode)} mode`;
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
      <td>${badge(r.status, true)}</td>
      <td>${badge(r.notification_type, true)}</td>
      <td>${esc((r.recipients || []).join(", "))}</td>
      <td>${esc(r.subject)}</td>
      <td class="muted">${esc(r.attempts)}</td>
      <td class="mono muted">${r.remote_id ? "#" + esc(r.remote_id) : DASH}</td>
      <td class="muted">${r.updated_at ? timeAgo(r.updated_at, true) : "—"}</td>
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
  document.getElementById("aiCount").textContent = items.length ? t("ai_count", items.length) : "";
  document.getElementById("aiEmpty").style.display = items.length ? "none" : "block";
  document.getElementById("aiList").innerHTML = items.map((it, i) => `
    <div class="aiitem" data-ai="${i}" data-ai-id="${esc(it.correlation_id)}">
      <div class="t">
        ${badge(it.risk_level)}
        <strong>${esc(it.detection_name)}</strong>
        <span class="muted">${esc(t("ai_on_endpoint", it.endpoint_name))}</span>
        <span class="muted mono" style="margin-left:auto">${esc(fmtDateTime(it.processed_at))}</span>
      </div>
      <div class="snip">${esc(aiSnippet(it.ai_output))}</div>
    </div>`).join("");
  makeRowsFocusable(document.getElementById("aiList"), "[data-ai]");
}

function openAiModal(it) {
  const box = document.getElementById("modalBox");
  const activeTab = state.openAiItem === it ? box.querySelector(".tabbtn.active")?.dataset.tab : null;
  const scrollTop = state.openAiItem === it ? box.scrollTop : 0;
  showModal(t("modal_ai_analysis"), alertContext(it) + notificationTabs(it.ai_output));
  if (activeTab) box.querySelector(`[data-tab="${CSS.escape(activeTab)}"]`)?.click();
  box.scrollTop = scrollTop;
  // Set after showModal, which clears it — every other modal must leave it null so
  // a language switch re-renders only an actually-open AI analysis.
  state.openAiItem = it;
}

document.getElementById("aiList").addEventListener("click", (e) => {
  const el = e.target.closest("[data-ai]");
  if (!el) return;
  const it = state.ai[Number(el.dataset.ai)];
  if (it) openAiModal(it);
});

// Tab labels ("Client (JA)" etc.) are dashboard chrome and follow the language
// toggle. The notification BODIES (including their embedded 【...】/ALL-CAPS
// section headers) are real AI-generated content — always shown exactly as
// generated, in whichever language that particular notification is written in,
// regardless of the dashboard's own language setting.
/* The AI's assessment of the alert, as distinct from the notifications it drafts
 * from that assessment. Both come out of the same AI call
 * (src/models/ai_output.py), but the four notification tabs are audience-specific
 * emails — reading only those, you see what will be *sent* and never the
 * reasoning behind it: what the AI treated as confirmed, what it flagged as
 * still unknown, and what it wants investigated.
 *
 * The engineer notification is the one audience whose email carries the full
 * analytical breakdown, so its fields are the source here. It is rendered as
 * analysis rather than as correspondence — no greeting, no draft reply.
 */
/* Legacy results: the engineer report was written in BOTH languages (see
 * src/models/ai_output.py: engineer_notification_en / engineer_notification_ja),
 * and it is the source for the Analysis panel and the AI Content snippet. Picks
 * whichever language the dashboard toggle is currently set to.
 *
 * Falls back to the other language rather than rendering an empty panel: results
 * stored before the Japanese report existed only carry the English one, and those
 * files are never re-generated. `fallback` tells the caller to say so out loud, so
 * a Japanese reader is never left silently staring at English with no explanation.
 */
/* Results written since the OpenAI integration carry the client's flat output
 * schema (src/models/ai_output.py: alert_summary_ja, risk_reason_ja, ...).
 * Older result files carry the previous nested schema; both still render. */
function isFlatOutput(ai) {
  return !!(ai && typeof ai.alert_summary_ja === "string");
}

function aiSnippet(ai) {
  if (isFlatOutput(ai)) {
    return state_lang.current === "ja" ? ai.alert_summary_ja : (ai.engineer_summary_en || ai.alert_summary_ja);
  }
  const legacy = engineerReport(ai).report.alert_summary;
  return legacy || (ai && ai.client_notification_ja && ai.client_notification_ja.summary) || "";
}

function engineerReport(ai) {
  const en = (ai && ai.engineer_notification_en) || null;
  const ja = (ai && ai.engineer_notification_ja) || null;
  const wantJa = state_lang.current === "ja";
  const preferred = wantJa ? ja : en;
  const other = wantJa ? en : ja;
  if (preferred) return { report: preferred, fallback: false };
  if (other) return { report: other, fallback: true };
  return { report: {}, fallback: false };
}

function aiList(arr) {
  return (arr || []).length
    ? `<ul class="ai-list">${(arr || []).map((x) => `<li>${esc(x)}</li>`).join("")}</ul>`
    : `<p class="muted">${esc(t("ai_none_stated"))}</p>`;
}

/* Flat schema: the summary follows the language toggle (JA summary, or the EN
 * engineer summary); the risk reason and action lists exist in Japanese only,
 * by the client's field specification. */
function flatAnalysisPanel(ai) {
  const summary = state_lang.current === "ja" ? ai.alert_summary_ja : ai.engineer_summary_en;
  return `
    <div class="ai-analysis">
      <h4>${esc(t("ai_alert_summary"))}</h4>
      <p class="ai-prose">${esc(summary)}</p>

      <h4>${esc(t("ai_risk_reason"))}</h4>
      <p class="ai-prose">${esc(ai.risk_reason_ja)}</p>

      <div class="ai-cols">
        <div>
          <h4>${esc(t("ai_initial_actions"))}</h4>
          ${aiList(ai.recommended_initial_actions_ja)}
        </div>
        <div>
          <h4>${esc(t("ai_confirm_items"))}</h4>
          ${aiList(ai.additional_confirmation_items_ja)}
        </div>
      </div>

      <h4>${esc(t("ai_unknown_items"))}</h4>
      ${aiList(ai.unknown_items)}
    </div>`;
}

function analysisPanel(ai) {
  if (isFlatOutput(ai)) return flatAnalysisPanel(ai);
  const picked = engineerReport(ai);
  const e = picked.report;
  const notice = picked.fallback
    ? `<p class="ai-fallback">${esc(t(state_lang.current === "ja" ? "ai_lang_fallback_ja" : "ai_lang_fallback_en"))}</p>`
    : "";
  const list = (arr) => (arr || []).length
    ? `<ul class="ai-list">${(arr || []).map((x) => `<li>${esc(x)}</li>`).join("")}</ul>`
    : `<p class="muted">${esc(t("ai_none_stated"))}</p>`;

  return `
    <div class="ai-analysis">
      ${notice}
      <h4>${esc(t("ai_alert_summary"))}</h4>
      <p class="ai-prose">${esc(e.alert_summary)}</p>

      <h4>${esc(t("ai_assessment"))}</h4>
      <p class="ai-prose">${esc(e.assessment)}</p>

      <div class="ai-cols">
        <div>
          <h4>${esc(t("ai_confirmed"))}</h4>
          ${list(e.confirmed_information)}
        </div>
        <div>
          <h4>${esc(t("ai_unknown"))}</h4>
          ${list(e.unknown_information)}
        </div>
      </div>

      <h4>${esc(t("ai_investigate"))}</h4>
      ${list(e.investigation_items)}

      <h4>${esc(t("ai_recommended"))}</h4>
      ${list(e.recommended_actions)}
    </div>`;
}

/* Threat-intel result boxes (VirusTotal / AbuseIPDB), as their own function so
 * the Pipeline Flow INTEL stage detail can render exactly what alertContext()
 * shows in the AI Content modal, without duplicating it inline a third time. */
function threatIntelBlock(ti) {
  if (!ti || !ti.virustotal || !ti.abuseipdb) return "";
  return `<div class="intel-row">
      <div class="intel-box"><h4>VirusTotal</h4>${badge(ti.virustotal.status)}
        <div class="muted" style="margin-top:7px">${esc(ti.virustotal.positives)}/${esc(ti.virustotal.total)} ${esc(t("engines_flagged"))}</div></div>
      <div class="intel-box"><h4>AbuseIPDB</h4>${badge(ti.abuseipdb.status)}
        <div class="muted" style="margin-top:7px">${esc(ti.abuseipdb.abuse_confidence_score)}${esc(t("intel_confidence"))} · ${esc(ti.abuseipdb.total_reports)} ${esc(t("intel_reports"))}</div></div>
    </div>`;
}

/* The alert the assessment was made from: the deterministic risk call and its
 * rationale (produced by src/services/risk_engine.py, NOT by the AI), the intel
 * verdicts, and the normalized facts. Shown above the AI's own words so the two
 * can be read against each other.
 */
function alertContext(it) {
  const a = it.alert || {};
  let html = `<div class="kv">
      ${kvRow(t("kv_detection"), a.detection_name)}
      ${kvRow(t("kv_endpoint"), a.endpoint_name ? `${a.endpoint_name} (${a.endpoint_type})` : "")}
      ${kvRow(t("kv_severity_reported"), tBadgeLabel(a.severity))}
      <div>${esc(t("kv_risk_computed"))}</div><div>${badge(it.risk_level)}</div>
      ${riskFactorsRow(it.risk_factors, it.risk_rationale)}
      ${kvRow(t("kv_handled_isolated"), `${tBadgeLabel(a.threat_handled)} / ${tBadgeLabel(a.isolation_status)}`)}
      ${a.object_uri ? `<div>${esc(t("kv_object_uri"))}</div><div class="mono">${esc(a.object_uri)}</div>` : ""}
      ${a.file_hash ? `<div>${esc(t("kv_file_hash"))}</div><div class="mono">${esc(a.file_hash)}</div>` : ""}
    </div>`;

  if (it.ai_run) html += aiRunKv(it.ai_run);

  const ti = it.threat_intel;
  if (ti && ti.virustotal && ti.abuseipdb) {
    html += `<div class="intel-row">
      <div class="intel-box"><h4>VirusTotal</h4>${badge(ti.virustotal.status)}
        <div class="muted" style="margin-top:7px">${esc(ti.virustotal.positives)}/${esc(ti.virustotal.total)} ${esc(t("engines_flagged"))}</div></div>
      <div class="intel-box"><h4>AbuseIPDB</h4>${badge(ti.abuseipdb.status)}
        <div class="muted" style="margin-top:7px">${esc(ti.abuseipdb.abuse_confidence_score)}${esc(t("intel_confidence"))} · ${esc(ti.abuseipdb.total_reports)} ${esc(t("intel_reports"))}</div></div>
    </div>`;
  }
  return html;
}

function flatNotificationTabs(ai) {
  const bullets = (a) => (a || []).map((x) => `- ${x}`).join("\n");
  return [
    ["client-email", t("tab_client_email"), `件名: ${ai.email_subject_ja}\n\n${ai.email_body_ja}`],
    ["client", t("tab_client"), ai.client_notification_ja],
    ["internal", t("tab_internal"),
      `${ai.internal_summary_ja}\n\n【推奨初動対応】\n${bullets(ai.recommended_initial_actions_ja)}\n\n【追加確認事項】\n${bullets(ai.additional_confirmation_items_ja)}\n\n【不明・要確認事項】\n${bullets(ai.unknown_items)}`],
    ["engineer", t("tab_engineer"), `${ai.engineer_summary_en}\n\nUNKNOWN / NEEDS CONFIRMATION\n${bullets(ai.unknown_items)}`],
    ["backlog", t("tab_backlog"), ai.backlog_comment_ja],
  ];
}

/* The rules that decided the risk level (src/services/risk_engine.py), one per
 * line, or the single rationale string for results that predate risk_factors. */
function riskFactorsRow(factors, rationale) {
  const applied = (factors || []).filter((f) => f.effect === "base" || f.effect === "raised");
  if (!applied.length) return kvRow(t("kv_rationale"), tBackendText(rationale));
  return `<div>${esc(t("kv_rationale"))}</div><div><ul class="ai-list">${applied
    .map((f) => `<li>${esc(tBackendText(f.detail))}</li>`).join("")}</ul></div>`;
}

/* Audit record of the AI call: which provider/model explained the alert, and the
 * provider's request ID for support/audit. */
function aiRunKv(run) {
  const usage = run.usage && run.usage.total_tokens ? ` · ${run.usage.total_tokens} tokens` : "";
  return `<div class="kv" style="margin-top:8px">
      ${kvRow(t("kv_ai_model"), `${run.provider} / ${run.served_model || run.model}`)}
      ${kvRow(t("kv_ai_request_id"), run.request_id || "—")}
      ${kvRow(t("kv_ai_run"), `${run.status} · ${run.attempts} ${t("kv_ai_attempts")} · ${fmtMs(run.duration_ms)}${usage} · prompt ${run.prompt_version}`)}
    </div>`;
}

function notificationTabs(ai) {
  const bullets = (a) => (a || []).map((x) => `- ${x}`).join("\n");
  const tabs = isFlatOutput(ai) ? flatNotificationTabs(ai) : [
    ["client", t("tab_client"),
      `${ai.client_notification_ja.summary}\n\n【現在の状況】\n${ai.client_notification_ja.current_status}\n\n【確認事項】\n${ai.client_notification_ja.required_confirmation}`],
    ["cthree", t("tab_cthree"),
      `${ai.cthree_notification_ja.summary}\n\n【評価】\n${ai.cthree_notification_ja.assessment}\n\n【フロントオフィス】\n${ai.cthree_notification_ja.front_office_notes}\n\n【クライアント返信案】\n${ai.cthree_notification_ja.draft_client_response}`],
    ["internal", t("tab_internal"),
      `${ai.internal_notification_ja.summary}\n\n【評価】\n${ai.internal_notification_ja.assessment}\n\n【推奨アクション】\n${bullets(ai.internal_notification_ja.recommended_actions)}\n\n【返信案】\n${ai.internal_notification_ja.draft_client_response}`],
  ];

  // The engineer report exists in both languages and both are offered as their own
  // tab, regardless of the dashboard's language setting: the engineer email that
  // actually goes out is the English one, and a reviewer comparing the two needs
  // them side by side rather than behind a global toggle. Each keeps its own
  // language's section headers. Older stored results carry only the English one,
  // so each tab is added only when its content is actually present.
  const engineerEn = !isFlatOutput(ai) && ai.engineer_notification_en;
  if (engineerEn) {
    tabs.push(["engineer", t("tab_engineer"),
      `${engineerEn.alert_summary}\n\nASSESSMENT\n${engineerEn.assessment}\n\nCONFIRMED\n${bullets(engineerEn.confirmed_information)}\n\nUNKNOWN\n${bullets(engineerEn.unknown_information)}\n\nINVESTIGATE\n${bullets(engineerEn.investigation_items)}\n\nRECOMMENDED ACTIONS\n${bullets(engineerEn.recommended_actions)}\n\nDRAFT CLIENT RESPONSE\n${engineerEn.draft_client_response}`]);
  }
  const engineerJa = !isFlatOutput(ai) && ai.engineer_notification_ja;
  if (engineerJa) {
    tabs.push(["engineer-ja", t("tab_engineer_ja"),
      `${engineerJa.alert_summary}\n\n【評価】\n${engineerJa.assessment}\n\n【確認済みの情報】\n${bullets(engineerJa.confirmed_information)}\n\n【不明な情報】\n${bullets(engineerJa.unknown_information)}\n\n【調査項目】\n${bullets(engineerJa.investigation_items)}\n\n【推奨アクション】\n${bullets(engineerJa.recommended_actions)}\n\n【クライアント返信案】\n${engineerJa.draft_client_response}`]);
  }

  // The analysis panel leads: it is what the AI concluded, and the four
  // notification tabs are the audience-specific drafts derived from it.
  // Its content is markup (headings, lists), so it is emitted as HTML built
  // from esc()'d values, while notification bodies stay escaped plain text.
  const panels = [
    { id: "analysis", label: t("tab_analysis"), html: analysisPanel(ai), cls: "notif-html" },
    ...tabs.map((tb) => ({ id: tb[0], label: tb[1], html: esc(tb[2]), cls: "notif" })),
  ];

  return `
    <div class="tabs" role="tablist">${panels.map((p, i) =>
      `<button type="button" role="tab" class="tabbtn ${i === 0 ? "active" : ""}" ` +
      `id="notification-tab-${esc(p.id)}" aria-controls="notification-panel-${esc(p.id)}" ` +
      `tabindex="${i === 0 ? "0" : "-1"}" aria-selected="${i === 0}" data-tab="${esc(p.id)}">${esc(p.label)}</button>`).join("")}</div>
    <div class="notification-actions"><button type="button" class="small" data-copy-notification>${esc(t("btn_copy_panel"))}</button></div>
    ${panels.map((p, i) =>
      `<div class="${p.cls}" role="tabpanel" tabindex="0" id="notification-panel-${esc(p.id)}" ` +
      `aria-labelledby="notification-tab-${esc(p.id)}" data-panel="${esc(p.id)}" style="${i === 0 ? "" : "display:none"}">${p.html}</div>`).join("")}`;
}

/* ══════════════ AI visibility ══════════════
 * What did the AI receive, what did it contact, what came back, was anything
 * sensitive involved, and what did the application do with the result? Every AI
 * call in this app (src/services/ai/gemini_service.py) produces one trace via
 * src/services/ai/trace_recorder.py; this section is a live view over those traces.
 */

function fmtMs(ms) {
  if (ms === null || ms === undefined) return "—";
  return ms < 1000 ? `${Math.round(ms)}ms` : `${(ms / 1000).toFixed(1)}s`;
}

async function loadAiVisibility() {
  const riskFilter = document.getElementById("aiTraceRisk").value;
  try {
    const [overview, traces] = await Promise.all([
      api("/ai/overview"),
      api("/ai/traces?limit=50" + (riskFilter ? `&risk=${encodeURIComponent(riskFilter)}` : "")),
    ]);
    state.aiOverview = overview;
    renderAiOverview(overview);
    state.aiTraces.clear();
    for (const t of traces.traces) state.aiTraces.set(t.trace_id, t);
    renderAiTraces();
  } catch (e) { /* handled */ }
  renderAiLiveFeed();
}
document.getElementById("aiTraceRisk").onchange = loadAiVisibility;

function renderAiOverview(o) {
  const cards = [
    [t("card_ai_status"), o.active_requests > 0 ? t("status_active") : t("status_idle")],
    [t("card_active_requests"), o.active_requests],
    [t("card_requests_today"), o.requests_today],
    [t("card_models_providers"), (o.providers || []).length],
    [t("card_external_calls"), o.external_calls_today],
    [t("card_security_alerts"), o.security_alerts],
  ];
  document.getElementById("aiVisCards").innerHTML = cards
    .map(([l, n]) => `<div class="card"><div class="n">${esc(n)}</div><div class="l">${esc(l)}</div></div>`)
    .join("");
  document.getElementById("cAiAlerts").textContent = o.security_alerts || 0;
  drawAiRisk(o.by_risk);
}

function renderAiTraces() {
  const rows = [...state.aiTraces.values()].sort((a, b) => (b.started_at || 0) - (a.started_at || 0));
  document.getElementById("aiTracesEmpty").style.display = rows.length ? "none" : "block";
  document.getElementById("aiTraceRows").innerHTML = rows.map((row) => `
    <tr class="clickable" data-trace="${esc(row.trace_id)}">
      <td class="mono muted">${esc(row.trace_id)}</td>
      <td class="muted">${timeAgo(row.started_at)}</td>
      <td>${esc(row.component)}</td>
      <td class="mono">${esc(row.provider)}/${esc(row.model)}</td>
      <td class="muted">${fmtMs(row.duration_ms)}</td>
      <td>${badge(row.status)}</td>
      <td>${badge(row.risk)}</td>
    </tr>`).join("");
  makeRowsFocusable(document.getElementById("aiTraceRows"), "tr.clickable");
}

document.getElementById("aiTraceRows").addEventListener("click", (e) => {
  const tr = e.target.closest("tr[data-trace]");
  if (tr) openAiTrace(tr.getAttribute("data-trace"));
});

function aiLiveIcon(type) {
  if (type === "trace_completed") return "✓";
  if (type === "sensitive_data_scan" || type === "policy_check") return "⚠";
  if (type === "external_call_started" || type === "external_call_finished" || type === "request_sent") return "→";
  if (type === "retry") return "↻";
  return "●";
}

function renderAiLiveFeed() {
  const items = state.aiLive;
  document.getElementById("aiLiveEmpty").style.display = items.length ? "none" : "block";
  document.getElementById("aiLiveFeed").innerHTML = items.map((ev) => `
    <div class="logline" style="grid-template-columns:20px 68px 1fr">
      <span>${esc(aiLiveIcon(ev.type))}</span>
      <span class="dim">${esc(fmtClock(ev.ts * 1000))}</span>
      <span class="logmsg"><strong>${esc(tBackendText(ev.label))}</strong>${ev.detail ? ` <span class="muted">— ${esc(tBackendText(ev.detail))}</span>` : ""}
        <span class="muted mono" style="margin-left:6px">${esc((ev.trace_id || "").slice(0, 10))}</span></span>
    </div>`).join("");
}

function pushAiLiveEvent(ev) {
  state.aiLive.unshift(ev);
  if (state.aiLive.length > 60) state.aiLive.length = 60;
  if (state.view === "ai-visibility") renderAiLiveFeed();
}

function aiFindingsList(findings) {
  if (!findings || !findings.length) return `<p class="muted">${esc(t("findings_empty"))}</p>`;
  return findings.map((f) => `
    <div class="intel-box" style="min-width:0;margin-bottom:8px">
      <div class="row" style="justify-content:space-between">
        <strong>${esc(tSecurityCategory(f.category))}</strong>
        <span class="srcbadge">${esc(f.method === "automatic" ? t("method_automatic") : f.method === "manual" ? t("method_manual") : f.method)}</span>
      </div>
      <div class="mono muted" style="margin-top:5px;word-break:break-all">${esc(f.masked_preview)}</div>
      <div class="dim" style="margin-top:4px;font-size:10.5px">${esc(f.field_path)}</div>
    </div>`).join("");
}

function aiDataCategoriesTable(cats) {
  if (!cats || !cats.length) return `<p class="muted">${esc(t("field_categories_empty"))}</p>`;
  return `<table><thead><tr><th>${esc(t("th_category"))}</th><th>${esc(t("th_field"))}</th><th>${esc(t("th_origin"))}</th><th>${esc(t("th_preview"))}</th></tr></thead><tbody>
    ${cats.map((c) => `<tr>
      <td>${esc(tDataCategory(c.category))}</td>
      <td class="mono">${esc(c.field)}</td>
      <td class="muted">${esc(tBackendText(c.origin))}</td>
      <td class="mono">${esc(c.value_preview)}</td>
    </tr>`).join("")}
  </tbody></table>`;
}

function aiExternalCallsTable(calls) {
  if (!calls || !calls.length) return `<p class="muted">${esc(t("external_calls_empty"))}</p>`;
  return `<table><thead><tr><th>${esc(t("th_service"))}</th><th>${esc(t("th_domain"))}</th><th>${esc(t("th_purpose"))}</th><th>${esc(t("th_when"))}</th><th>${esc(t("th_status"))}</th><th>${esc(t("th_latency"))}</th><th>${esc(t("th_sent"))}</th><th>${esc(t("th_returned"))}</th></tr></thead><tbody>
    ${calls.map((c) => `<tr>
      <td>${esc(c.service)}</td>
      <td class="mono">${esc(c.domain)}</td>
      <td class="muted">${esc(tBackendText(c.purpose))}</td>
      <td class="muted">${esc(fmtClock(c.requested_at * 1000))}</td>
      <td>${badge(c.status)}</td>
      <td class="muted">${fmtMs(c.latency_ms)}</td>
      <td class="muted">${esc(tBackendText(c.data_sent_category))}</td>
      <td class="muted">${esc(tBackendText(c.data_returned_category))}</td>
    </tr>`).join("")}
  </tbody></table>`;
}

function aiTimelineList(events_) {
  if (!events_ || !events_.length) return `<p class="muted">${esc(t("timeline_empty"))}</p>`;
  return events_.map((ev) => `
    <div class="logline" style="grid-template-columns:74px 1fr">
      <span class="dim">${esc(fmtClock(ev.ts * 1000))}</span>
      <span class="logmsg"><strong>${esc(tBackendText(ev.label))}</strong>${ev.detail ? `<br><span class="muted">${esc(tBackendText(ev.detail))}</span>` : ""}</span>
    </div>`).join("");
}

// Walks a redacted-trace sub-object collecting (path, text) for every non-empty string
// leaf, so the manual-redaction UI operates on EXACTLY the text stored server-side —
// never on a truncated preview — so character offsets always line up with what the
// backend will actually overwrite (see src/storage/ai_trace_store.py: apply_manual_redaction).
function collectRedactableFields(obj, prefix, out) {
  if (obj === null || obj === undefined) return;
  if (typeof obj === "string") {
    if (obj.trim()) out.push([prefix, obj]);
    return;
  }
  if (Array.isArray(obj)) {
    obj.forEach((v, i) => collectRedactableFields(v, `${prefix}[${i}]`, out));
    return;
  }
  if (typeof obj === "object") {
    for (const [k, v] of Object.entries(obj)) collectRedactableFields(v, prefix ? `${prefix}.${k}` : k, out);
  }
}

function aiRedactionFields(trace) {
  const fields = [];
  collectRedactableFields(trace.input_redacted, "input_redacted", fields);
  collectRedactableFields(trace.output_redacted, "output_redacted", fields);
  if (!fields.length) return `<p class="muted">${esc(t("field_categories_empty"))}</p>`;
  return fields.map(([path, value], i) => `
    <div class="field">
      <label>${esc(path)}</label>
      <textarea readonly rows="2" id="redact-ta-${i}">${esc(value)}</textarea>
      <div class="hint">${esc(t("redact_hint"))}</div>
      <button class="small danger" style="margin-top:6px" data-redact-btn="${i}" data-path="${esc(path)}">${esc(t("btn_redact"))}</button>
    </div>`).join("");
}

async function openAiTrace(id) {
  showModal(t("modal_loading"), `<p class="muted">${esc(t("modal_fetching_alert"))}</p>`);
  let data;
  try { data = await api(`/ai/traces/${encodeURIComponent(id)}`); }
  catch (e) { showModal(t("modal_error"), `<p class="muted">${esc(tBackendText(e.message))}</p>`); return; }
  renderAiTraceModal(data.trace);
}

function renderAiTraceModal(tr) {
  const ds = tr.decision_summary || {};
  const cfg = tr.config || {};
  const hasTools = tr.tool_calls && tr.tool_calls.length;

  let html = `<div class="kv">
      <div>${esc(t("kv_trace_id"))}</div><div class="mono">${esc(tr.trace_id)}</div>
      <div>${esc(t("kv_correlation_id"))}</div><div class="mono">${esc(tr.correlation_id)}</div>
      <div>${esc(t("kv_component"))}</div><div>${esc(tr.component)} <span class="muted">(${esc(tr.action)})</span></div>
      <div>${esc(t("kv_provider_model"))}</div><div class="mono">${esc(tr.provider)} / ${esc(tr.model)}</div>
      <div>${esc(t("kv_status"))}</div><div>${badge(tr.status)}</div>
      <div>${esc(t("kv_risk"))}</div><div>${badge(tr.risk)}</div>
      <div>${esc(t("kv_started"))}</div><div class="muted">${esc(fmtDateTime(tr.started_at * 1000))}</div>
      <div>${esc(t("kv_duration"))}</div><div class="muted">${esc(fmtMs(tr.duration_ms))}</div>
      <div>${esc(t("kv_external_transfer"))}</div><div>${tr.external_data_transfer
        ? `<span style="color:var(--warning)">${esc(t("external_transfer_yes"))}</span>`
        : `<span class="muted">${esc(t("external_transfer_no"))}</span>`}</div>
      ${tr.usage
        ? kvRow(t("kv_token_usage"), `${t("token_prompt")} ${tr.usage.prompt_tokens ?? "—"} · ${t("token_output")} ${tr.usage.output_tokens ?? "—"} · ${t("token_total")} ${tr.usage.total_tokens ?? "—"}`)
        : kvRow(t("kv_token_usage"), t("token_usage_not_reported"))}
      ${tr.error ? `<div>${esc(t("kv_error"))}</div><div style="color:var(--text-danger)">${esc(tr.error)}</div>` : ""}
    </div>`;

  // ds.task/decision/confidence/note/policy_checks and system_instructions_text are
  // backend-authored diagnostic text with a small known vocabulary — translated via
  // tBackendText() (exact/template match, safe fallback to English if unmatched).
  // ds.context_used lists raw pipeline field names (technical identifiers) and stays
  // as-is, same as any other field-name value shown elsewhere in this modal.
  html += `<h4 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em">${esc(t("h_decision_summary"))}</h4>
    <div class="notif">${esc(t("ds_task"))}: ${esc(tBackendText(ds.task) || tr.objective || "—")}
${esc(t("ds_context"))}: ${esc((ds.context_used || []).join(", ") || "—")}
${esc(t("ds_decision"))}: ${esc(tBackendText(ds.decision) || "—")}
${esc(t("ds_confidence"))}: ${esc(tBackendText(ds.confidence) || t("fallback_not_available"))}
${esc(t("ds_policy"))}: ${esc((ds.policy_checks || []).map((p) => tBackendText(p)).join(", ") || "—")}

<span class="dim">${esc(tBackendText(ds.note) || t("fallback_decision_note"))}</span></div>`;

  html += `<h4 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em">${esc(t("h_data_sent"))}</h4>
    ${aiDataCategoriesTable(tr.data_categories)}
    ${(tr.context_notes || []).length ? `<ul class="muted" style="font-size:12px;margin-top:10px">${tr.context_notes.map((n) => `<li>${esc(tBackendText(n))}</li>`).join("")}</ul>` : ""}`;

  html += `<h4 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em">${esc(t("h_model_config"))}</h4>
    <div class="kv">
      ${kvRow(t("cfg_temperature"), cfg.temperature ?? "—")}
      ${kvRow(t("cfg_max_tokens"), cfg.max_output_tokens ?? "—")}
      ${kvRow(t("cfg_response_format"), cfg.response_mime_type ?? "—")}
      ${kvRow(t("cfg_schema_required"), (cfg.response_schema_required_fields || []).join(", ") || "—")}
      ${kvRow(t("cfg_instructions_version"), cfg.system_instructions_version ?? "—")}
    </div>
    ${cfg.system_instructions_text ? `<pre class="code">${esc(tBackendText(cfg.system_instructions_text))}</pre>` : ""}`;

  html += `<h4 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em">${esc(t("h_tool_calls"))}</h4>
    ${hasTools ? "" : `<p class="muted">${esc(t("tool_calls_none"))}</p>`}`;

  html += `<h4 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em">${esc(t("h_external_contacts"))}</h4>
    ${aiExternalCallsTable(tr.external_calls)}`;

  html += `<h4 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em">${esc(t("h_security_findings"))}</h4>
    ${aiFindingsList(tr.security_findings)}`;

  html += `<h4 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em">${esc(t("h_timeline"))}</h4>
    <div class="scroll" style="max-height:260px">${aiTimelineList(tr.events)}</div>`;

  html += `<h4 style="font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em">${esc(t("h_manual_redaction"))}</h4>
    <p class="muted" style="font-size:12px;margin-top:0">${esc(t("redact_hint_intro"))}</p>
    ${aiRedactionFields(tr)}`;

  showModal(`AI Trace — ${tr.trace_id}`, html);

  document.querySelectorAll("[data-redact-btn]").forEach((btn) => {
    btn.onclick = async () => {
      const idx = btn.getAttribute("data-redact-btn");
      const path = btn.getAttribute("data-path");
      const ta = document.getElementById(`redact-ta-${idx}`);
      const start = ta.selectionStart, end = ta.selectionEnd;
      if (start === end) { toast(t("toast_select_text_first"), true); return; }
      btn.disabled = true;
      try {
        const res = await api(`/ai/traces/${encodeURIComponent(tr.trace_id)}/redact`, {
          method: "POST",
          body: JSON.stringify({ field_path: path, start, end }),
        });
        toast(t("toast_redacted"));
        renderAiTraceModal(res.trace);
        loadAiVisibility();
      } catch (err) {
        toast(t("toast_redact_failed") + tBackendText(err.message), true);
        btn.disabled = false;
      }
    };
  });
}

/* ══════════════ alert detail modal ══════════════ */

function showModal(title, bodyHtml) {
  const overlay = document.getElementById("overlay");
  if (!overlay.classList.contains("show")) {
    state.modalReturnFocus = document.activeElement;
  }
  // Any modal opening replaces whatever was open; openAiModal re-sets this.
  state.openAiItem = null;
  const box = document.getElementById("modalBox");
  box.innerHTML = `
    <div class="head"><h3 id="modalTitle">${esc(title)}</h3><button class="small" id="closeModal">${esc(t("btn_close"))}</button></div>
    <div class="body">${bodyHtml}</div>`;
  box.setAttribute("role", "dialog");
  box.setAttribute("aria-modal", "true");
  box.setAttribute("aria-labelledby", "modalTitle");
  box.setAttribute("tabindex", "-1");
  overlay.classList.add("show");
  document.getElementById("closeModal").onclick = closeModal;
  wireTabs(box);

  // Remember where focus came from, and move it into the dialog. Without this a
  // keyboard user opens a modal and their focus is still behind it, on a row
  // they can no longer see.
  box.focus();
}

/* Keeps Tab inside the open dialog. A modal that can be tabbed out of is a modal
 * only for people using a mouse. */
document.getElementById("overlay").addEventListener("keydown", (e) => {
  if (e.key !== "Tab") return;
  const box = document.getElementById("modalBox");
  const focusable = [...box.querySelectorAll(
    'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])',
  )].filter((el) => el.offsetParent !== null && !el.disabled && el.tabIndex >= 0);
  if (!focusable.length) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (e.shiftKey && (document.activeElement === first || document.activeElement === box)) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault();
    first.focus();
  }
});

function wireTabs(box) {
  box.querySelectorAll(".tabbtn").forEach((tab) => (tab.onclick = () => {
    box.querySelectorAll(".tabbtn").forEach((btn) => {
      btn.classList.remove("active");
      btn.setAttribute("aria-selected", "false");
      btn.tabIndex = -1;
    });
    box.querySelectorAll("[data-panel]").forEach((p) => (p.style.display = "none"));
    tab.classList.add("active");
    tab.setAttribute("aria-selected", "true");
    tab.tabIndex = 0;
    const panel = box.querySelector(`[data-panel="${CSS.escape(tab.dataset.tab)}"]`);
    if (panel) panel.style.display = "block";
  }));
  box.querySelectorAll(".tabs").forEach((tabs) => tabs.addEventListener("keydown", (e) => {
    const buttons = [...tabs.querySelectorAll(".tabbtn")];
    const current = buttons.indexOf(e.target);
    if (current < 0) return;
    let next;
    if (e.key === "ArrowRight") next = (current + 1) % buttons.length;
    else if (e.key === "ArrowLeft") next = (current + buttons.length - 1) % buttons.length;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = buttons.length - 1;
    else return;
    e.preventDefault();
    buttons[next].click();
    buttons[next].focus();
  }));
  const copy = box.querySelector("[data-copy-notification]");
  if (copy) copy.onclick = async () => {
    const active = box.querySelector(".tabbtn.active");
    const panel = active && box.querySelector(`[data-panel="${CSS.escape(active.dataset.tab)}"]`);
    if (!panel) return;
    try {
      await navigator.clipboard.writeText(panel.innerText);
      toast(t("toast_panel_copied"));
    } catch (e) { toast(t("toast_copy_failed"), true); }
  };
}

/* Makes a container's click-to-drill-down rows reachable without a mouse.
 * The rows are <tr>/<div>, which have no implicit role or tab stop, so every
 * drill-down in the app (alerts, AI content, AI traces, emails) was
 * mouse-only. Rather than rewriting each renderer's markup, the rows are
 * annotated after render and Enter/Space are mapped onto the existing click
 * handler — the same behaviour a button would give. */
function makeRowsFocusable(container, selector) {
  if (!container) return;
  container.querySelectorAll(selector).forEach((row) => {
    if (row.dataset.kbd) return;
    row.dataset.kbd = "1";
    row.setAttribute("tabindex", "0");
    row.setAttribute("role", "button");
    row.addEventListener("keydown", (e) => {
      if (e.target !== row) return;
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        row.click();
      }
    });
  });
}

function closeModal() {
  if (!document.getElementById("overlay").classList.contains("show")) return;
  document.getElementById("overlay").classList.remove("show");
  state.openAiItem = null;
  // Put focus back where it was, so closing a modal does not dump a keyboard
  // user at the top of the document.
  const target = state.modalReturnFocus;
  state.modalReturnFocus = null;
  if (target && document.contains(target)) target.focus();
  else if (target) {
    // Live updates and language changes replace list rows. Find the same item
    // by its stable identifier so closing still returns to the original row.
    const attr = ["data-ai-id", "data-id", "data-email", "data-trace"].find((name) => target.hasAttribute(name));
    const replacement = attr && document.querySelector(`[${attr}="${CSS.escape(target.getAttribute(attr))}"]`);
    (replacement || document.querySelector("nav a.tab.active"))?.focus();
  }
}

document.getElementById("overlay").addEventListener("click", (e) => {
  if (e.target.id === "overlay") closeModal();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeModal();
});

const kvRow = (k, v) => `<div>${esc(k)}</div><div>${esc(v)}</div>`;

async function openAlert(id) {
  showModal(t("modal_loading"), `<p class="muted">${esc(t("modal_fetching_alert"))}</p>`);
  let data;
  try { data = await api(`/jobs/${encodeURIComponent(id)}`); }
  catch (e) { showModal(t("modal_error"), `<p class="muted">${esc(tBackendText(e.message))}</p>`); return; }

  const job = data.job, r = data.result;
  const a = r && r.normalized_alert;

  let html = `<div class="kv">
      <div>${esc(t("kv_correlation_id2"))}</div><div class="mono">${esc(job.correlation_id)}</div>
      <div>${esc(t("kv_status2"))}</div><div>${badge(job.status)}</div>
      <div>${esc(t("kv_source"))}</div><div>${badge(job.source)}</div>
      ${kvRow(t("kv_created"), fmtDateTime(job.created_at * 1000))}
      ${kvRow(t("kv_updated"), fmtDateTime(job.updated_at * 1000))}
      ${job.error ? `<div>${esc(t("kv_error2"))}</div><div style="color:var(--text-danger)">${esc(job.error)}</div>` : ""}
    </div>`;

  if (a) {
    html += `<div class="kv">
      ${kvRow(t("kv_detection"), a.detection_name)}
      ${kvRow(t("kv_endpoint"), `${a.endpoint_name} (${a.endpoint_type})`)}
      ${kvRow(t("kv_severity_reported"), tBadgeLabel(a.severity))}
      <div>${esc(t("kv_risk_computed"))}</div><div>${badge(r.risk_level)}</div>
      ${kvRow(t("kv_rationale"), tBackendText(r.risk_rationale))}
      ${kvRow(t("kv_user"), a.user_name)}
      ${kvRow(t("kv_os"), a.os_name)}
      ${kvRow(t("kv_action_taken"), a.action_taken)}
      ${kvRow(t("kv_handled_isolated"), `${tBadgeLabel(a.threat_handled)} / ${tBadgeLabel(a.isolation_status)}`)}
      <div>${esc(t("kv_object_uri"))}</div><div class="mono">${esc(a.object_uri)}</div>
      <div>${esc(t("kv_file_hash"))}</div><div class="mono">${esc(a.file_hash)}</div>
      <div>${esc(t("kv_ip_domain"))}</div><div class="mono">${esc(a.ip_address)} / ${esc(a.domain)}</div>
    </div>`;
  }

  if (r && r.threat_intel) {
    const ti = r.threat_intel;
    html += `<div class="intel-row">
      <div class="intel-box"><h4>VirusTotal</h4>${badge(ti.virustotal.status)}
        <div class="muted" style="margin-top:7px">${esc(ti.virustotal.positives)}/${esc(ti.virustotal.total)} ${esc(t("engines_flagged"))}</div></div>
      <div class="intel-box"><h4>AbuseIPDB</h4>${badge(ti.abuseipdb.status)}
        <div class="muted" style="margin-top:7px">${esc(ti.abuseipdb.abuse_confidence_score)}${esc(t("intel_confidence"))} · ${esc(ti.abuseipdb.total_reports)} ${esc(t("intel_reports"))}</div></div>
    </div>`;
  }

  html += r && r.ai_output
    ? notificationTabs(r.ai_output)
    : `<p class="muted">${esc(t("no_ai_output"))}</p>`;

  showModal(t("modal_alert_detail"), html);
}

/* job.raw_payload (from GET /jobs/{id}) is NOT literally the bytes that arrived
 * over the wire — it is `EsetRawPayload.model_dump()` (src/api/webhook.py), the
 * platform's own envelope: ESET's 24 declared fields (mostly null for a
 * non-ESET-shaped alert) plus, nested one level down under its OWN "raw_payload"
 * key, the actual original submission. It has to be stored in that wrapped shape
 * — src/pipeline/orchestrator.py's retry path reconstructs `EsetRawPayload(**raw_payload)`
 * directly from this exact dict, so re-shaping it here would break Retry.
 * This drills into that nested key to show what the user actually means by "the
 * raw request": the original submitted JSON, not the platform's wrapper around
 * it. Falls back to the outer object for the rare historical row that predates
 * this convention or genuinely had no extra data of its own. */
function originalRequestPayload(job) {
  const outer = (job && job.raw_payload) || {};
  const inner = outer.raw_payload;
  return (inner && typeof inner === "object" && Object.keys(inner).length) ? inner : outer;
}

/* Pretty-printed original request JSON with a copy button — a common reason to
 * open this is pasting it into a bug report or a support ticket. */
function rawPayloadHtml(payload) {
  const pretty = JSON.stringify(payload ?? {}, null, 2);
  return `
    <div class="row" style="justify-content:space-between;margin-bottom:9px">
      <span class="muted" style="font-size:11.5px">${esc(t("stage_ingest_desc"))}</span>
      <button class="small" id="copyRawPayload">${esc(t("btn_copy"))}</button>
    </div>
    <pre class="code" id="rawPayloadPre">${esc(pretty)}</pre>`;
}

function wireRawPayloadCopy(box) {
  const btn = box.querySelector("#copyRawPayload");
  const pre = box.querySelector("#rawPayloadPre");
  if (!btn || !pre) return;
  btn.onclick = () => {
    navigator.clipboard.writeText(pre.textContent).then(
      () => toast(t("toast_copied")),
      () => toast(t("toast_copy_blocked"), true));
  };
}

/** Standalone raw-request viewer, reachable from the Alerts table for ANY alert
 * (not only one currently visible in the session-only Pipeline Flow view — see
 * openStageDetail's INGEST case in dashboard-viz.js, which renders the same HTML
 * from a job it already has in hand, without a second fetch). */
async function openRawPayload(id) {
  showModal(t("modal_raw_request"), `<p class="muted">${esc(t("modal_fetching_alert"))}</p>`);
  let data;
  try { data = await api(`/jobs/${encodeURIComponent(id)}`); }
  catch (e) { showModal(t("modal_error"), `<p class="muted">${esc(tBackendText(e.message))}</p>`); return; }

  showModal(t("modal_raw_request"), rawPayloadHtml(originalRequestPayload(data.job)));
  wireRawPayloadCopy(document.getElementById("modalBox"));
}

/* ══════════════ logs ══════════════ */

// Filtering, sorting and paging all happen server-side
// (src/services/log_reader.py); this holds the current query and the last
// page returned for it.
const logState = {
  page: 1,
  pageSize: 100,
  levels: new Set(),       // empty = every level
  source: "",              // "" | "app" | "http"
  event: "",
  q: "",
  range: 0,                // minutes; 0 = all time
  sort: "desc",
  res: null,
  signature: "",
};
const LOG_LEVELS = ["debug", "info", "warning", "error", "critical"];
const LOG_POLL_MS = 5000;
// Keys already shown in their own column (or internal to the viewer).
const LOG_HIDDEN_KEYS = new Set(["_id", "_source"]);
// Expanded rows, by the server-assigned _id (the line's byte offset), which
// stays the same for a given line across refreshes and pages.
const logExpanded = new Set();
let logTimer = null;
let logEntriesById = new Map();
let logFetchSeq = 0;

function logQueryParams() {
  const p = new URLSearchParams({
    page: String(logState.page),
    page_size: String(logState.pageSize),
    sort: logState.sort,
  });
  if (logState.levels.size) p.set("level", [...logState.levels].join(","));
  if (logState.source) p.set("source", logState.source);
  if (logState.event) p.set("event", logState.event);
  if (logState.q) p.set("q", logState.q);
  if (logState.range) p.set("since_minutes", String(logState.range));
  return p;
}

/** Live refresh only makes sense while looking at the newest entries, and
 * would yank an open row out from under the reader, so it pauses otherwise. */
function logLiveStatus() {
  if (!document.getElementById("logAuto").checked) return "off";
  if (logExpanded.size) return "paused_open";
  if (logState.page !== 1 || logState.sort !== "desc") return "paused_page";
  return "live";
}

function scheduleLogPoll() {
  clearTimeout(logTimer);
  renderLogLiveState();
  if (state.view === "logs" && logLiveStatus() === "live") {
    logTimer = setTimeout(() => loadLogs({ quiet: true }), LOG_POLL_MS);
  }
}

async function loadLogs(opts = {}) {
  const seq = ++logFetchSeq;
  clearTimeout(logTimer);
  try {
    const res = await api("/logs?" + logQueryParams().toString());
    if (seq !== logFetchSeq) return;   // a newer query superseded this one
    logState.res = res;
    logState.page = res.page || 1;
    const signature = (res.lines || []).map((e) => e._id).join(",") + "|" + res.total;
    // Nothing changed since the last poll: leave the DOM (and any text
    // selection or scroll position inside it) alone.
    if (!(opts.quiet && signature === logState.signature)) {
      logState.signature = signature;
      renderLogs();
    }
  } catch (e) { /* api() already surfaced it */ }
  scheduleLogPoll();
}

/** Resets to page 1 and fetches — for every filter change. */
function applyLogFilter() {
  logState.page = 1;
  logExpanded.clear();
  loadLogs();
}

function renderLogs() {
  const res = logState.res || { lines: [], total: 0, page: 1, pages: 1 };
  const lines = res.lines || [];
  logEntriesById = new Map(lines.map((e) => [String(e._id), e]));
  document.getElementById("logsEmpty").style.display = lines.length ? "none" : "block";
  document.getElementById("logList").innerHTML = lines.map(logRowHtml).join("");
  renderLogControls();
}

function logTimeHtml(ts) {
  if (!ts) return `<span class="dim">—</span>`;
  const d = new Date(ts);
  if (isNaN(d)) return `<span class="dim">${esc(ts)}</span>`;
  const date = d.toLocaleDateString(uiLocale(), { month: "2-digit", day: "2-digit" });
  return `<span class="dim" title="${esc(fmtDateTime(d))}">${esc(date)} ${esc(fmtClock(d))}</span>`;
}

function httpStatusClass(status) {
  const n = Number(status);
  if (!n) return status === "accepted" ? "ok" : "warn";
  return n >= 500 ? "bad" : n >= 400 ? "warn" : "ok";
}

function logFieldKeys(e) {
  return Object.keys(e).filter((k) => !LOG_HIDDEN_KEYS.has(k));
}

function logRowHtml(e) {
  const id = String(e._id);
  const open = logExpanded.has(id);
  const lvl = (e.level || "info").toLowerCase();
  let headline;
  if (e._source === "http") {
    headline = `<span class="http-m">${esc(e.http_method || "")}</span>${esc(e.http_path || "")}`
      + `<span class="http-s ${httpStatusClass(e.http_status)}">${esc(e.http_status || "")}</span>`
      + ` <span class="dim">${esc(e.client || "")}</span>`;
  } else {
    const extra = logFieldKeys(e).filter((k) => !["event", "level", "timestamp"].includes(k));
    const summary = extra.map((k) => {
      const v = (e[k] !== null && typeof e[k] === "object") ? JSON.stringify(e[k]) : String(e[k]);
      return `<span class="kvp">${esc(k)}=</span>${esc(v.length > 80 ? v.slice(0, 80) + "…" : v)}`;
    }).join("  ");
    headline = `<strong>${esc(e.event || "")}</strong>${summary ? `<span class="sum">${summary}</span>` : ""}`;
  }
  return `<div class="logline${open ? " open" : ""}" data-logid="${esc(id)}" tabindex="0" role="button" aria-expanded="${open}">
    <svg class="log-caret" aria-hidden="true" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="m9 6 6 6-6 6"/></svg>
    ${logTimeHtml(e.timestamp)}
    <span class="lvl ${esc(lvl)}">${esc(tLogLevel(lvl))}</span>
    <span class="logmsg">${headline}</span>
    ${open ? logDetailHtml(e) : ""}
  </div>`;
}

/** One field's value: dicts/lists pretty-printed, long or multi-line text in
 * a scrollable block, anything short inline. */
function logFieldValueHtml(value) {
  if (value !== null && typeof value === "object") {
    return `<pre class="code">${esc(JSON.stringify(value, null, 2))}</pre>`;
  }
  const text = String(value);
  if (text.length > 90 || text.includes("\n")) return `<pre class="code">${esc(text)}</pre>`;
  return `<span class="mono">${esc(text)}</span>`;
}

function logDetailHtml(e) {
  const id = String(e._id);
  const keys = logFieldKeys(e);
  const cid = e.correlation_id ? String(e.correlation_id) : "";
  const clean = Object.fromEntries(keys.map((k) => [k, e[k]]));
  return `<div class="log-detail" data-detail="${esc(id)}">
    <div class="log-detail-grid">
      ${keys.map((k) => `<div class="log-detail-key">${esc(k)}</div><div>${logFieldValueHtml(e[k])}</div>`).join("")}
    </div>
    <div class="log-detail-actions">
      <button class="small" data-log-act="copy" data-id="${esc(id)}">${esc(t("btn_copy_json"))}</button>
      <button class="small" data-log-act="raw" data-id="${esc(id)}">${esc(t("btn_view_json"))}</button>
      ${e._source !== "http" && e.event ? `<button class="small" data-log-act="event" data-id="${esc(id)}">${esc(t("btn_only_this_event"))}</button>` : ""}
      ${cid ? `<button class="small" data-log-act="cid" data-id="${esc(id)}">${esc(t("btn_trace_correlation"))}</button>` : ""}
      ${cid ? `<button class="small" data-log-act="timeline" data-id="${esc(id)}">${esc(t("btn_timeline"))}</button>` : ""}
    </div>
    <pre class="code rawjson" hidden>${esc(JSON.stringify(clean, null, 2))}</pre>
  </div>`;
}

function toggleLogRow(row) {
  const id = row.dataset.logid;
  const entry = logEntriesById.get(id);
  if (!entry) return;
  if (logExpanded.has(id)) logExpanded.delete(id); else logExpanded.add(id);
  const tmp = document.createElement("div");
  tmp.innerHTML = logRowHtml(entry);
  const fresh = tmp.firstElementChild;
  row.replaceWith(fresh);
  fresh.focus({ preventScroll: true });
  scheduleLogPoll();
}

function logAction(act, entry) {
  if (act === "copy") {
    const clean = Object.fromEntries(logFieldKeys(entry).map((k) => [k, entry[k]]));
    navigator.clipboard.writeText(JSON.stringify(clean, null, 2)).then(
      () => toast(t("toast_copied")), () => toast(t("toast_copy_blocked"), true));
  } else if (act === "event") {
    logState.event = entry.event;
    applyLogFilter();
  } else if (act === "cid") {
    logState.q = String(entry.correlation_id);
    document.getElementById("logSearch").value = logState.q;
    applyLogFilter();
  } else if (act === "timeline" && typeof openAlertTimeline === "function") {
    openAlertTimeline(String(entry.correlation_id));
  }
}

document.getElementById("logList").addEventListener("click", (e) => {
  const btn = e.target.closest("[data-log-act]");
  if (btn) {
    if (btn.dataset.logAct === "raw") {
      const pre = btn.closest(".log-detail").querySelector(".rawjson");
      pre.hidden = !pre.hidden;
      return;
    }
    const entry = logEntriesById.get(btn.dataset.id);
    if (entry) logAction(btn.dataset.logAct, entry);
    return;
  }
  // Clicks inside the open detail panel (selecting text, scrolling a code
  // block) must not collapse it; neither should finishing a text selection.
  if (e.target.closest(".log-detail")) return;
  if (String(window.getSelection && window.getSelection()).length) return;
  const row = e.target.closest(".logline");
  if (row) toggleLogRow(row);
});
document.getElementById("logList").addEventListener("keydown", (e) => {
  if (e.key !== "Enter" && e.key !== " ") return;
  if (!e.target.classList || !e.target.classList.contains("logline")) return;
  e.preventDefault();
  toggleLogRow(e.target);
});

function setSegActive(container, attr, value) {
  container.querySelectorAll("button").forEach((b) => {
    const on = b.getAttribute(attr) === String(value);
    b.classList.toggle("primary", on);
    b.setAttribute("aria-pressed", String(on));
  });
}

function renderLogControls() {
  const res = logState.res || {};
  const facets = res.facets || {};
  const levelCounts = facets.levels || {};

  document.getElementById("logLevels").innerHTML = LOG_LEVELS.map((lv) => `
    <button class="small lvlchip ${lv}" data-level="${lv}" aria-pressed="${logState.levels.has(lv)}">
      <span class="sw"></span>${esc(tLogLevel(lv))}<span class="n">${esc(fmtCount(levelCounts[lv] || 0))}</span>
    </button>`).join("");

  setSegActive(document.getElementById("logRange"), "data-range", logState.range);
  setSegActive(document.getElementById("logSource"), "data-source", logState.source);
  setSegActive(document.getElementById("logPageSize"), "data-size", logState.pageSize);
  const sources = facets.sources || {};
  document.querySelectorAll("#logSource button").forEach((b) => {
    const s = b.dataset.source;
    const n = s ? (sources[s] || 0) : (sources.app || 0) + (sources.http || 0);
    b.textContent = `${t(b.getAttribute("data-i18n"))} · ${fmtCount(n)}`;
  });

  const sel = document.getElementById("logEvent");
  const events = (facets.events || []).slice();
  if (logState.event && !events.some(([name]) => name === logState.event)) events.unshift([logState.event, 0]);
  sel.innerHTML = `<option value="">${esc(t("opt_all_events"))}</option>` + events.map(([name, n]) => {
    const label = name.length > 60 ? name.slice(0, 60) + "…" : name;
    return `<option value="${esc(name)}">${esc(label)} (${esc(fmtCount(n))})</option>`;
  }).join("");
  sel.value = logState.event;

  document.getElementById("logSort").textContent = t(logState.sort === "desc" ? "sort_newest" : "sort_oldest");

  const total = res.total || 0, pages = res.pages || 1, page = res.page || 1;
  const from = total ? (page - 1) * logState.pageSize + 1 : 0;
  const to = Math.min(total, page * logState.pageSize);
  let text = t("logs_showing", fmtCount(from), fmtCount(to), fmtCount(total));
  if (res.window && res.window.truncated) text += " " + t("logs_window_truncated");
  document.getElementById("logRangeText").textContent = text;
  document.getElementById("logPageLabel").textContent = t("page_word");
  const input = document.getElementById("logPageInput");
  input.value = page; input.max = pages;
  document.getElementById("logPageOf").textContent = t("page_of", fmtCount(pages));
  document.getElementById("logFirst").disabled = document.getElementById("logPrev").disabled = page <= 1;
  document.getElementById("logNext").disabled = document.getElementById("logLast").disabled = page >= pages;

  const filtered = logState.levels.size || logState.source || logState.event || logState.q || logState.range;
  document.getElementById("logClear").style.visibility = filtered ? "visible" : "hidden";
  renderLogLiveState();
}

function renderLogLiveState() {
  const el = document.getElementById("logLiveState");
  if (!el) return;
  const status = logLiveStatus();
  el.querySelector(".dot").className = "dot" + (status === "live" ? " ok live" : status === "off" ? "" : " warn");
  el.querySelector("span:last-child").textContent = t("logs_live_" + status);
}

function goToLogPage(page) {
  const pages = (logState.res && logState.res.pages) || 1;
  const target = Math.min(Math.max(1, page), pages);
  if (target === logState.page) return;
  logState.page = target;
  logExpanded.clear();
  loadLogs();
  document.getElementById("logList").scrollTop = 0;
}

document.getElementById("logLevels").addEventListener("click", (e) => {
  const chip = e.target.closest("[data-level]");
  if (!chip) return;
  const lv = chip.dataset.level;
  if (logState.levels.has(lv)) logState.levels.delete(lv); else logState.levels.add(lv);
  applyLogFilter();
});
document.getElementById("logRange").addEventListener("click", (e) => {
  const b = e.target.closest("[data-range]");
  if (b) { logState.range = Number(b.dataset.range); applyLogFilter(); }
});
document.getElementById("logSource").addEventListener("click", (e) => {
  const b = e.target.closest("[data-source]");
  if (b) { logState.source = b.dataset.source; applyLogFilter(); }
});
document.getElementById("logPageSize").addEventListener("click", (e) => {
  const b = e.target.closest("[data-size]");
  if (!b) return;
  // Keep the first visible entry on screen when the page size changes.
  const firstIndex = (logState.page - 1) * logState.pageSize;
  logState.pageSize = Number(b.dataset.size);
  logState.page = Math.floor(firstIndex / logState.pageSize) + 1;
  loadLogs();
});
document.getElementById("logEvent").onchange = (e) => { logState.event = e.target.value; applyLogFilter(); };
document.getElementById("logSort").onclick = () => {
  logState.sort = logState.sort === "desc" ? "asc" : "desc";
  applyLogFilter();
};
document.getElementById("logSearch").oninput = (e) => {
  clearTimeout(logTimer);
  logTimer = setTimeout(() => { logState.q = e.target.value.trim(); applyLogFilter(); }, 300);
};
document.getElementById("logClear").onclick = () => {
  Object.assign(logState, { levels: new Set(), source: "", event: "", q: "", range: 0 });
  document.getElementById("logSearch").value = "";
  applyLogFilter();
};
document.getElementById("logFirst").onclick = () => goToLogPage(1);
document.getElementById("logPrev").onclick = () => goToLogPage(logState.page - 1);
document.getElementById("logNext").onclick = () => goToLogPage(logState.page + 1);
document.getElementById("logLast").onclick = () => goToLogPage((logState.res && logState.res.pages) || 1);
document.getElementById("logPageInput").onchange = (e) => goToLogPage(Number(e.target.value) || 1);
document.getElementById("logRefresh").onclick = () => loadLogs();

/** Downloads every entry matching the current filters (not just this page).
 * Fetched rather than linked because the request needs the key header. */
document.getElementById("logExport").onclick = async () => {
  const btn = document.getElementById("logExport");
  const p = logQueryParams();
  p.delete("page"); p.delete("page_size");
  btn.disabled = true;
  try {
    const res = await fetch(API + "/logs/export?" + p.toString(), {
      headers: dashKey() ? { "X-Dashboard-Key": dashKey() } : {},
    });
    if (!res.ok) throw new Error(String(res.status));
    const blob = await res.blob();
    const name = (res.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name ? name[1] : "soc-lite-logs.ndjson";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    toast(t("toast_logs_exported"));
  } catch (e) {
    toast(t("toast_logs_export_failed"), true);
  }
  btn.disabled = false;
};

// "/" jumps to the log search, as in most log tools — unless already typing.
document.addEventListener("keydown", (e) => {
  if (e.key !== "/" || state.view !== "logs" || e.ctrlKey || e.metaKey || e.altKey) return;
  const tag = (document.activeElement && document.activeElement.tagName) || "";
  if (["INPUT", "TEXTAREA", "SELECT"].includes(tag) || document.activeElement.isContentEditable) return;
  e.preventDefault();
  document.getElementById("logSearch").focus();
});
document.getElementById("logAuto").onchange = () => {
  if (logLiveStatus() === "live") loadLogs(); else scheduleLogPoll();
};
document.addEventListener("visibilitychange", () => {
  if (document.hidden) clearTimeout(logTimer);
  else if (state.view === "logs") loadLogs({ quiet: true });
});

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
      src.textContent = s.recipients[key].source === "dashboard" ? t("src_saved_here") : t("src_from_env");
    }
    document.getElementById("runtimeKv").innerHTML =
      Object.entries(s.runtime).map(([k, v]) =>
        `<div>${esc(RUNTIME_KEY_I18N[k] ? t(RUNTIME_KEY_I18N[k]) : k.replace(/_/g, " "))}</div><div class="mono">${esc(v)}</div>`).join("");
    renderPosture(s.security || []);
    renderAiProvider(s.ai);
  } catch (e) { /* handled */ }
}

/** Settings → AI provider. Read-only by design: provider and model are per-
 * environment deployment config, and the API key lives in the secret store —
 * this shows only where it comes from, never the key. */
function renderAiProvider(ai) {
  const box = document.getElementById("aiProviderKv");
  if (!box || !ai) return;
  const source = `${t("ai_src_" + ai.key_source)}${ai.key_reference ? ` (${ai.key_reference})` : ""}`;
  box.innerHTML = `
    ${kvRow(t("ai_kv_provider"), ai.provider)}
    ${kvRow(t("ai_kv_model"), ai.model || t("ai_not_set"))}
    <div>${esc(t("ai_kv_key_source"))}</div><div><span style="display:inline-block;margin-right:6px;vertical-align:middle" class="dot ${ai.key_source === "aws_secrets_manager" ? "ok" : ai.key_source === "environment" ? "warn" : "bad"}"></span> ${esc(source)}</div>
    ${kvRow(t("ai_kv_limits"), t("ai_limits_value", ai.timeout_seconds, ai.max_attempts, ai.max_output_tokens))}
    ${kvRow(t("ai_kv_masking"), ai.masking_enabled ? t("ai_masking_on") : t("ai_masking_off"))}
    ${kvRow(t("ai_kv_prompt_version"), ai.prompt_version)}`;
}

document.getElementById("testAiConnection").onclick = async (e) => {
  const out = document.getElementById("aiTestResult");
  e.target.disabled = true;
  out.textContent = t("ai_test_running");
  try {
    const r = await api("/settings/ai/test", { method: "POST" });
    out.textContent = r.ok
      ? t("ai_test_ok", r.detail, fmtMs(r.latency_ms), r.request_id || "—")
      : t("ai_test_failed", r.detail);
    out.style.color = r.ok ? "" : "var(--text-danger)";
  } catch (err) {
    out.textContent = t("ai_test_failed", tBackendText(err.message));
    out.style.color = "var(--text-danger)";
  }
  e.target.disabled = false;
};

/** Settings → Security posture: one line per deployment control. */
function renderPosture(items) {
  const dot = { ok: "ok", warn: "warn", bad: "bad" };
  document.getElementById("postureList").innerHTML = items.map((it) => `
    <div class="posture-item">
      <span class="dot ${dot[it.status] || ""}"></span>
      <div><strong>${esc(t(`posture_${it.id}_title`))}</strong>
        <span>${esc(t(`posture_${it.id}_${it.status}`))}</span></div>
    </div>`).join("");
  const open = items.filter((it) => it.status !== "ok").length;
  document.getElementById("postureSummary").textContent =
    open ? t("posture_summary_open", open) : t("posture_summary_all_ok");
}

document.getElementById("saveRecipients").onclick = async () => {
  const btn = document.getElementById("saveRecipients");
  btn.disabled = true;
  const body = {};
  for (const [ui, key] of RECIPIENT_FIELDS) body[key] = document.getElementById("in-" + ui).value.trim();
  try {
    await api("/settings/recipients", { method: "PUT", body: JSON.stringify(body) });
    toast(t("toast_recipients_saved"));
    loadSettings();
  } catch (e) { toast(t("toast_save_failed") + tBackendText(e.message), true); }
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
      () => toast(t("toast_curl_copied")),
      () => toast(t("toast_copy_blocked"), true));
  };

  const routes = [
    ["GET", "/dashboard/api/jobs", t("route_list_jobs")],
    ["GET", "/dashboard/api/jobs/{id}", t("route_job_detail")],
    ["POST", "/dashboard/api/jobs/{id}/retry", t("route_retry")],
    ["GET", "/dashboard/api/alerts", t("route_alerts_index")],
    ["GET", "/dashboard/api/ai-content", t("route_ai_content")],
    ["GET", "/dashboard/api/emails", t("route_emails")],
    ["DELETE", "/dashboard/api/emails/{id}", t("route_delete_email")],
    ["GET", "/dashboard/api/stats", t("route_stats")],
    ["GET", "/dashboard/api/logs", t("route_logs")],
    ["GET", "/dashboard/api/settings", t("route_settings")],
    ["PUT", "/dashboard/api/settings/recipients", t("route_settings_update")],
    ["GET", "/dashboard/api/ai/overview", t("route_ai_overview")],
    ["GET", "/dashboard/api/ai/traces", t("route_ai_traces_list")],
    ["GET", "/dashboard/api/ai/traces/{id}", t("route_ai_trace_detail")],
    ["POST", "/dashboard/api/ai/traces/{id}/redact", t("route_ai_redact")],
    ["WS", "/dashboard/api/ws", t("route_ws")],
  ];
  document.getElementById("apiRows").innerHTML = routes.map(([m, p, d]) =>
    `<tr><td class="mono"><strong>${esc(m)}</strong></td><td class="mono">${esc(p)}</td><td class="muted">${esc(d)}</td></tr>`).join("");
}

/* ══════════════ health ══════════════ */

/* A health dot's only visual state is its colour, so the same fact is written
 * into aria-label as text — otherwise "is the database up?" is unanswerable
 * without colour vision. The service name is read from the markup so the two
 * can never drift apart. */
const setDot = (id, ok) => {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = "dot " + (ok ? "ok" : "bad");
  const name = (el.getAttribute("aria-label") || id).split(":")[0];
  el.setAttribute("aria-label", `${name}: ${t(ok ? "health_ok" : "health_down")}`);
  el.setAttribute("title", `${name}: ${t(ok ? "health_ok" : "health_down")}`);
};

async function loadHealth() {
  try {
    const h = await (await fetch("/health")).json();
    setDot("dbDot", h.database?.status === "ok");
    setDot("aiDot", h.ai_provider?.status === "configured");
    setDot("dirDot", h.output_directory?.status === "ok");
    setDot("udpDot", h.syslog_listener?.udp === "ok");
    setDot("tcpDot", h.syslog_listener?.tcp === "ok");
  } catch (e) { /* transient */ }
}

/* ══════════════ websocket ══════════════ */

/* The access key is offered as a WebSocket SUBPROTOCOL, not as a ?key= query
 * parameter. A query string on the handshake is logged by the server's access
 * log — which this dashboard then serves back to the browser in its own Logs
 * view — and is kept in browser history and by any proxy in between. A
 * subprotocol offer rides in a request header instead. base64url keeps it a
 * legal subprotocol token whatever characters the key contains. */
function wsKeyProtocol(key) {
  const bytes = new TextEncoder().encode(key);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return "socpass." + btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Paints the live-feed pill from state.wsState. Called on every status change
 * AND on every language switch, so the two can never disagree. */
function renderWsStatus() {
  const dot = document.getElementById("wsDot");
  const label = document.getElementById("wsLabel");
  if (!dot || !label) return;
  const spec = {
    live: { cls: "dot ok live", key: "ws_live" },
    reconnecting: { cls: "dot bad", key: "ws_reconnecting" },
    connecting: { cls: "dot", key: "ws_connecting" },
  }[state.wsState] || { cls: "dot", key: "ws_connecting" };
  dot.className = spec.cls;
  label.textContent = t(spec.key);
  // The dot is the only visual state cue, so the same fact has to exist as text
  // for anyone who cannot use colour.
  dot.setAttribute("aria-label", `${t("pill_live_feed")}: ${t(spec.key)}`);
}

function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const key = dashKey();
  const url = `${proto}://${location.host}${API}/ws`;
  const ws = key ? new WebSocket(url, [wsKeyProtocol(key)]) : new WebSocket(url);
  window._ws = ws;

  ws.onopen = () => {
    state.wsState = "live";
    renderWsStatus();
  };
  ws.onclose = () => {
    state.wsState = "reconnecting";
    renderWsStatus();
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
      detection_name: knownValue(d.normalized_alert?.detection_name),
      endpoint_name: knownValue(d.normalized_alert?.endpoint_name),
      indicators: ["ip_address", "file_hash", "domain", "url", "object_uri"]
        .map((key) => d.normalized_alert?.[key]),
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

  } else if (msg.type === "ai_trace_started") {
    pushAiLiveEvent({ ts: d.started_at, type: "request_started", label: t("live_ai_request_started"),
                       detail: `${d.component} → ${d.provider}/${d.model}`, trace_id: d.trace_id });
    if (state.view === "ai-visibility") loadAiVisibility();

  } else if (msg.type === "ai_trace_event") {
    pushAiLiveEvent({ ts: d.ts, type: d.type, label: d.label, detail: d.detail, trace_id: d.trace_id });

  } else if (msg.type === "ai_trace_completed") {
    pushAiLiveEvent({
      ts: Date.now() / 1000, type: "trace_completed",
      label: t("live_ai_trace_label", d.status),
      detail: t("live_risk_detail", d.risk, d.security_findings),
      trace_id: d.trace_id,
    });
    if (d.risk && ["SENSITIVE_DATA_DETECTED", "SECRET_DETECTED", "BLOCKED", "FAILED_SECURITY_CHECK", "ERROR"].includes(d.risk)) {
      toast(t("toast_ai_visibility_alert", d.risk, d.trace_id), true);
    }
    if (state.view === "ai-visibility") loadAiVisibility();
  }
}

/* ══════════════ boot ══════════════ */

async function boot() {
  renderApiDocs();
  try {
    const [jobs, emails] = await Promise.all([api("/jobs?limit=500"), api("/emails")]);
    state.jobs.clear();
    for (const row of jobs.jobs) upsertJob(jobFromRow(row));
    state.emails = emails.emails;
    await loadRiskLevels();
    renderAlerts();
    renderEmails();
  } catch (e) { return; }

  await loadStats();
  loadHealth();
  connectWs();
  startPolling();
}

// boot() also runs on every Refresh click, so the periodic timers are started
// once and only once — otherwise each click stacked another pair of intervals
// on top of the last, and a long session ended up re-rendering the alerts table
// dozens of times a second.
let pollingStarted = false;
function startPolling() {
  if (pollingStarted) return;
  pollingStarted = true;
  setInterval(loadHealth, 20000);
  setInterval(renderAlerts, 15000);   // keep relative timestamps fresh
}

document.getElementById("refreshBtn").onclick = () => {
  boot();
  if (state.view === "logs") loadLogs();
  if (state.view === "ai") loadAiContent();
  if (state.view === "ai-visibility") loadAiVisibility();
  if (state.view === "settings") loadSettings();
};

// Resume an existing session, otherwise show the login gate.
(async () => {
  if (dashKey() && (await attemptLogin(dashKey())) === null) {
    document.getElementById("login").classList.add("hidden");
    document.getElementById("app").classList.add("ready");
    boot();
  } else {
    // No key configured server-side? Then the probe succeeds with an empty key.
    if ((await attemptLogin("")) === null) {
      document.getElementById("login").classList.add("hidden");
      document.getElementById("app").classList.add("ready");
      boot();
    } else {
      document.getElementById("loginKey").focus();
    }
  }
})();
