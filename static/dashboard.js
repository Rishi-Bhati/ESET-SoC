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
  // Rebuilds whichever other modal is open, so a language switch does not leave
  // it in the old language. Set by each modal opener; cleared by showModal().
  reopenModal: null,
  // correlation_id of the alert whose detail modal is currently open, if any.
  // Lets a live recommendation event refresh that one modal without re-opening
  // an unrelated alert.
  openAlertId: null,
  // Last Emails-tab responses, re-rendered on a language switch.
  delivery: null,
  serviceStatus: null,
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
function badge(value) {
  const v = value && BADGES.has(value) ? value : "UNKNOWN";
  return `<span class="badge b-${v}"><span class="g"></span>${esc(tBadgeLabel(value || "UNKNOWN"))}</span>`;
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

function timeAgo(ts) {
  if (!ts) return "—";
  const s = Math.max(0, Date.now() / 1000 - ts);
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
  clearPortalSecret();
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

// Translation-key pairs, looked up live at render time.
const VIEW_META = {
  overview: ["view_overview_title", "view_overview_sub"],
  flow:     ["view_flow_title", "view_flow_sub"],
  alerts:   ["view_alerts_title", "view_alerts_sub"],
  ai:       ["view_ai_title", "view_ai_sub"],
  "ai-visibility": ["view_aivis_title", "view_aivis_sub"],
  emails:   ["view_emails_title", "view_emails_sub"],
  portal:   ["view_portal_title", "view_portal_sub"],
  logs:     ["view_logs_title", "view_logs_sub"],
  settings: ["view_settings_title", "view_settings_sub"],
  api:      ["view_api_title", "view_api_sub"],
};
function updateViewHeader(name) {
  const meta = VIEW_META[name] || VIEW_META.overview;
  document.getElementById("viewTitle").textContent = t(meta[0]);
  document.getElementById("viewSub").textContent = t(meta[1]);
}

function showView(name) {
  // A generated client password must not outlive the visit to the portal tab.
  if (name !== "portal") clearPortalSecret();
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
  if (name === "portal") loadPortalPanels();
  if (name === "emails") loadDelivery();
}

/** Called by i18n.js's setLang() after the language changes. Re-renders whatever
 * the current tab already has cached, WITHOUT re-fetching from the network, except
 * where a fetch is cheap and already the normal render path (settings, api docs). */
function refreshCurrentViewTranslations() {
  updateViewHeader(state.view);
  renderCards();
  renderAlerts();
  renderEmails();
  renderHealth();
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
  if (state.view === "portal") {
    loadPortalSettings();
    // Cached data only — no refetch, and the one-time password box is kept as is.
    if (portalAdmin.users !== null) renderPortalUsers();
    renderPortalReports();
  }
  // Built once at boot and not on tab switch, so it has to follow the toggle
  // whichever tab is open (no network involved).
  renderApiDocs();
  if (state.view === "emails") {
    if (state.delivery) renderDelivery(state.delivery);
    if (state.serviceStatus) renderServiceStatus(state.serviceStatus);
  }
  // A modal built from the old language would otherwise stay in it until
  // closed. The AI analysis modal is re-rendered in place above; any other open
  // modal is cheap to rebuild from the server.
  if (!state.openAiItem && state.reopenModal && document.getElementById("overlay").classList.contains("show")) {
    state.reopenModal();
  }
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

/** A field the alert actually carried. Absent fields are simply missing from the
 * result; result files written before that change still hold "UNKNOWN"
 * placeholders, which are treated as absent too. */
function knownValue(v) {
  return v !== null && v !== undefined && v !== "" && v !== "UNKNOWN" ? v : undefined;
}

/** "HOST (Server)", "HOST", or "Server" — whichever parts the alert carried. */
function endpointLabel(a) {
  const name = knownValue(a.endpoint_name), type = knownValue(a.endpoint_type);
  return name && type ? `${name} (${type})` : name || type;
}

/** Handled / isolated, each half only when reported: "はい / いいえ", "はい", … */
function handledIsolatedLabel(a) {
  const parts = [knownValue(a.threat_handled), knownValue(a.isolation_status)];
  if (!parts.some(Boolean)) return undefined;
  return parts.map((v) => (v ? tBadgeLabel(v) : "—")).join(" / ");
}

/** A key/value row only when the value exists — absent fields get no row at all. */
const kvRowIf = (k, v) => (knownValue(v) !== undefined ? kvRow(k, v) : "");
const kvMonoRowIf = (k, v) => (knownValue(v) !== undefined
  ? `<div>${esc(k)}</div><div class="mono">${esc(v)}</div>` : "");

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
      <td data-rec-count="${esc(j.correlation_id)}">${DASH}</td>
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
  loadRecommendationCounts();
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

/** Downloads EVERY recorded alert as one .xlsx — deliberately not the table's
 * loaded window, filters or page (src/services/alert_export.py). Fetched rather
 * than linked because the request needs the key header. */
document.getElementById("alertsExport").onclick = async () => {
  const btn = document.getElementById("alertsExport");
  btn.disabled = true;
  btn.textContent = t("btn_exporting_alerts");
  try {
    const res = await fetch(API + "/alerts/export", {
      headers: dashKey() ? { "X-Dashboard-Key": dashKey() } : {},
    });
    if (!res.ok) throw new Error(String(res.status));
    const blob = await res.blob();
    const name = (res.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/);
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name ? name[1] : "soc-lite-alerts.xlsx";
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    // The exact count, not fmtCount's compact form: "all 12K alerts" is not a count.
    const count = Number(res.headers.get("X-Alert-Count")) || 0;
    toast(t("toast_alerts_exported", count.toLocaleString(uiLocale())));
  } catch (e) {
    toast(t("toast_alerts_export_failed"), true);
  }
  btn.disabled = false;
  btn.textContent = t("btn_export_alerts_xlsx");
};

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
  document.getElementById("emailCount").textContent = es.length ? t("email_pending_count", es.length) : "";
  document.getElementById("emailsEmpty").style.display = es.length ? "none" : "block";
  document.getElementById("emailRows").innerHTML = es.map((m) => `
    <tr class="clickable" data-email="${esc(m.email_id)}">
      <td>${badge(m.notification_type)}</td>
      <td>${(m.to || []).length ? esc((m.to || []).join(", ")) : DASH}</td>
      <td>${esc(m.subject)}</td>
      <td>${badge(m.risk_level)}</td>
      <td class="muted">${m.created_at ? esc(fmtDateTime(m.created_at)) : "—"}</td>
      <td><button class="small danger" data-del="${esc(m.email_id)}">${esc(t("btn_discard"))}</button></td>
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
      renderEmails(); toast(t("toast_email_discarded"));
    } catch (err) { toast(t("toast_discard_failed") + tBackendText(err.message), true); e.target.disabled = false; }
    return;
  }
  const tr = e.target.closest("tr[data-email]");
  if (tr) openEmail(tr.getAttribute("data-email"));
});

function openEmail(id) {
  const m = state.emails.find((x) => x.email_id === id);
  if (!m) return;
  showModal(t("modal_queued_email"), `
    <div class="kv">
      <div>${esc(t("kv_type"))}</div><div>${badge(m.notification_type)}</div>
      <div>${esc(t("kv_to"))}</div><div>${esc((m.to || []).join(", "))}</div>
      <div>${esc(t("kv_subject"))}</div><div>${esc(m.subject)}</div>
      <div>${esc(t("kv_risk"))}</div><div>${badge(m.risk_level)}</div>
      ${m.endpoint_name ? kvRow(t("kv_endpoint"), m.endpoint_name) : ""}
      ${m.detection_name ? kvRow(t("kv_detection"), m.detection_name) : ""}
      <div>${esc(t("kv_correlation_id2"))}</div><div class="mono">${esc(m.correlation_id)}</div>
      <div>${esc(t("kv_status2"))}</div><div>${badge(m.status)}</div>
    </div>
    <div class="notif">${esc(m.body)}</div>`);
  state.reopenModal = () => openEmail(id);
}

/* ══════════════ mail delivery ══════════════ */

async function loadDelivery() {
  const filter = document.getElementById("deliveryFilter").value;
  try {
    const d = await api("/delivery" + (filter ? `?status=${encodeURIComponent(filter)}` : ""));
    state.delivery = d;
    renderDelivery(d);
  } catch (e) { return; }

  try {
    state.serviceStatus = await api("/delivery/service-status");
    renderServiceStatus(state.serviceStatus);
  } catch (e) { /* non-fatal */ }
}

function renderServiceStatus(svc) {
  const foot = document.getElementById("serviceStatus");
  if (svc.available && svc.queue) {
    const q = svc.queue;
    foot.innerHTML = t("mail_queue_status",
      esc(q.queued ?? 0), esc(q.sending ?? 0), esc(q.sent ?? 0), esc(q.failed ?? 0));
  } else if (svc.reachable) {
    // The service answered its health probe, so this is a configuration
    // problem on our side, not an outage on theirs — say which, because the
    // two have opposite fixes.
    foot.innerHTML = `<span style="color:var(--text-warn)">●</span> ` +
      esc(t("mail_service_unreadable") + tBackendText(svc.error || t("health_unknown")));
  } else {
    foot.innerHTML = `<span style="color:var(--text-danger)">●</span> ` +
      esc(t("mail_service_unreachable") + tBackendText(svc.error || t("health_unknown")));
  }
}

function renderDelivery(d) {
  const cfg = d.config || {};
  const cfgEl = document.getElementById("deliveryConfig");
  if (!cfg.enabled) {
    cfgEl.innerHTML = `<span style="color:var(--warning)">${esc(t("delivery_disabled"))}</span>${esc(t("delivery_disabled_hint"))}`;
  } else if (!cfg.configured) {
    cfgEl.innerHTML = `<span style="color:var(--text-danger)">${esc(t("delivery_not_configured"))}</span> — ${esc(tBackendText(cfg.reason))}`;
  } else {
    cfgEl.innerHTML = `<span style="color:var(--text-good)">●</span> ${esc(t("delivery_mode", cfg.provider, cfg.security_mode))}`;
  }

  const c = d.counts || {};
  const cards = [
    [t("card_awaiting_handoff"), d.pending_in_outbox || 0],
    [t("card_accepted"), c.ACCEPTED || 0],
    [t("card_delivery_failed"), c.FAILED || 0],
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
    if (r.skipped) toast(t("toast_nothing_sent", tBackendText(r.skipped)), true);
    else toast(t("toast_dispatch_result", r.accepted, r.failed, r.pending));
    await boot();
    loadDelivery();
  } catch (err) { toast(t("toast_dispatch_failed") + tBackendText(err.message), true); }
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
        ${knownValue(it.detection_name) ? `<strong>${esc(it.detection_name)}</strong>` : ""}
        ${knownValue(it.endpoint_name) ? `<span class="muted">${esc(t("ai_on_endpoint", it.endpoint_name))}</span>` : ""}
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
  const picked = engineerReport(ai);
  const clientJa = ai && ai.client_notification_ja && ai.client_notification_ja.summary;
  // A Japanese reader of an old result with only the English engineer report
  // gets the (always Japanese) client summary instead of English.
  if (picked.fallback && state_lang.current === "ja" && clientJa) return clientJa;
  return picked.report.alert_summary || clientJa || "";
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

/* Flat schema: the summary and the countermeasures follow the language toggle
 * (JA, or the EN engineer fields); the risk reason and confirmation items exist
 * in Japanese only, by the client's field specification. Results generated
 * before recommended_initial_actions_en existed fall back to the JA list. */
function flatAnalysisPanel(ai) {
  const en = state_lang.current !== "ja";
  const summary = en ? ai.engineer_summary_en : ai.alert_summary_ja;
  const actions = en && (ai.recommended_initial_actions_en || []).length
    ? ai.recommended_initial_actions_en : ai.recommended_initial_actions_ja;
  return `
    <div class="ai-analysis">
      <h4>${esc(t("ai_alert_summary"))}</h4>
      <p class="ai-prose">${esc(summary)}</p>

      <h4>${esc(t("ai_risk_reason"))}</h4>
      <p class="ai-prose">${esc(ai.risk_reason_ja)}</p>

      <div class="ai-cols">
        <div>
          <h4>${esc(t("ai_initial_actions"))}</h4>
          ${aiList(actions)}
        </div>
        <div>
          <h4>${esc(t("ai_confirm_items"))}</h4>
          ${aiList(ai.additional_confirmation_items_ja)}
        </div>
      </div>

      ${(ai.unknown_items || []).length ? `<h4>${esc(t("ai_unknown_items"))}</h4>${aiList(ai.unknown_items)}` : ""}
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
  // A provider the alert gave nothing to look up with (query "NONE",
  // src/models/threat_intel.py: NO_INDICATOR_QUERY) has no verdict to show.
  const ran = (r) => r.query !== "NONE";
  const boxes = [];
  if (ran(ti.virustotal)) {
    boxes.push(`<div class="intel-box"><h4>VirusTotal</h4>${badge(ti.virustotal.status)}
        <div class="muted" style="margin-top:7px">${esc(ti.virustotal.positives)}/${esc(ti.virustotal.total)} ${esc(t("engines_flagged"))}</div></div>`);
  }
  if (ran(ti.abuseipdb)) {
    boxes.push(`<div class="intel-box"><h4>AbuseIPDB</h4>${badge(ti.abuseipdb.status)}
        <div class="muted" style="margin-top:7px">${esc(ti.abuseipdb.abuse_confidence_score)}${esc(t("intel_confidence"))} · ${esc(ti.abuseipdb.total_reports)} ${esc(t("intel_reports"))}</div></div>`);
  }
  return boxes.length ? `<div class="intel-row">${boxes.join("")}</div>` : "";
}

/* The alert the assessment was made from: the deterministic risk call and its
 * rationale (produced by src/services/risk_engine.py, NOT by the AI), the intel
 * verdicts, and the normalized facts. Shown above the AI's own words so the two
 * can be read against each other.
 */
function alertContext(it) {
  const a = it.alert || {};
  let html = `<div class="kv">
      ${kvRowIf(t("kv_detection"), a.detection_name)}
      ${kvRowIf(t("kv_endpoint"), endpointLabel(a))}
      ${knownValue(a.severity) ? kvRow(t("kv_severity_reported"), tBadgeLabel(a.severity)) : ""}
      <div>${esc(t("kv_risk_computed"))}</div><div>${badge(it.risk_level)}</div>
      ${riskFactorsRow(it.risk_factors, it.risk_rationale)}
      ${kvRowIf(t("kv_handled_isolated"), handledIsolatedLabel(a))}
      ${kvMonoRowIf(t("kv_object_uri"), a.object_uri)}
      ${kvMonoRowIf(t("kv_file_hash"), a.file_hash)}
    </div>`;

  if (it.ai_run) html += aiRunKv(it.ai_run);

  html += threatIntelBlock(it.threat_intel);
  return html;
}

function flatNotificationTabs(ai) {
  const bullets = (a) => (a || []).map((x) => `- ${x}`).join("\n");
  // Mirrors src/services/email_composer.py: the section exists only when the AI
  // listed something to confirm.
  const confirm = ai.unknown_items || [];
  return [
    ["client-email", t("tab_client_email"), `件名: ${ai.email_subject_ja}\n\n${ai.email_body_ja}`],
    ["client", t("tab_client"), ai.client_notification_ja],
    ["internal", t("tab_internal"),
      `${ai.internal_summary_ja}\n\n【推奨初動対応】\n${bullets(ai.recommended_initial_actions_ja)}\n\n【追加確認事項】\n${bullets(ai.additional_confirmation_items_ja)}` +
      (confirm.length ? `\n\n【要確認事項】\n${bullets(confirm)}` : "")],
    ["engineer", t("tab_engineer"),
      ai.engineer_summary_en +
      ((ai.recommended_initial_actions_en || []).length
        ? `\n\nRECOMMENDED COUNTERMEASURES\n${ai.recommended_initial_actions_en.map((x, i) => `${i + 1}. ${x}`).join("\n")}` : "") +
      (confirm.length ? `\n\nNEEDS CONFIRMATION\n${bullets(confirm)}` : "")],
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
  const usage = run.usage && run.usage.total_tokens ? ` · ${t("kv_ai_tokens", run.usage.total_tokens)}` : "";
  return `<div class="kv" style="margin-top:8px">
      ${kvRow(t("kv_ai_model"), `${run.provider} / ${run.served_model || run.model}`)}
      ${kvRow(t("kv_ai_request_id"), run.request_id || "—")}
      ${kvRow(t("kv_ai_run"), `${tBadgeLabel(run.status)} · ${run.attempts} ${t("kv_ai_attempts")} · ${fmtMs(run.duration_ms)}${usage} · ${t("kv_ai_prompt", run.prompt_version)}`)}
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
    <div class="notif">${esc(t("ds_task"))}: ${esc(tBackendText(ds.task || tr.objective) || "—")}
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

  showModal(t("modal_ai_trace", tr.trace_id), html);
  state.reopenModal = () => renderAiTraceModal(tr);

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
  // Any modal opening replaces whatever was open; openAiModal and the other
  // openers re-set these after calling showModal.
  state.openAiItem = null;
  state.reopenModal = null;
  state.openAlertId = null;
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
  state.reopenModal = null;
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

/* ══════════════ recommendations ══════════════ */

const REC_AUTHOR_KEY = "soc_lite_recommendation_author";
const REC_BODY_MAX = 4000;
const REC_AUTHOR_MAX = 100;
const REC_REASON_MAX = 500;

/** Author last used on this browser, so the same engineer does not retype it for
 * every recommendation. Storage is optional: a private window must still post. */
function recAuthorStored() {
  try { return localStorage.getItem(REC_AUTHOR_KEY) || ""; } catch (e) { return ""; }
}
function recAuthorRemember(value) {
  try { localStorage.setItem(REC_AUTHOR_KEY, value); } catch (e) { /* storage blocked */ }
}

function recommendationItemHtml(rec) {
  const retracted = !!rec.retracted_at;
  const id = esc(rec.id);
  const when = rec.created_at ? esc(fmtDateTime(rec.created_at * 1000)) : "";
  return `<div class="rec-item${retracted ? " retracted" : ""}" data-rec-id="${id}">
    <div class="rec-meta">
      <strong>${esc(rec.author || "—")}</strong>
      <span class="muted">${when}</span>
      ${retracted ? `<span class="srcbadge" style="margin-left:0">${esc(t("rec_retracted_by", rec.retracted_by || "—"))}</span>` : ""}
    </div>
    <div class="rec-body" style="white-space:pre-wrap">${esc(rec.body)}</div>
    ${retracted
      ? (rec.retract_reason ? `<div class="rec-meta">${esc(t("rec_retracted_reason", rec.retract_reason))}</div>` : "")
      : `<div class="row" style="margin-top:7px">
           <button class="small danger" data-rec-retract="${id}">${esc(t("rec_retract"))}</button>
         </div>
         <div class="rec-retract-row" data-rec-retract-row="${id}">
           <input data-rec-reason="${id}" maxlength="${REC_REASON_MAX}" placeholder="${esc(t("rec_reason_placeholder"))}" aria-label="${esc(t("rec_reason_label"))}" style="flex:1;min-width:180px">
           <button class="small danger" data-rec-retract-confirm="${id}">${esc(t("rec_retract_confirm"))}</button>
           <button class="small" data-rec-retract-cancel="${id}">${esc(t("rec_cancel"))}</button>
         </div>`}
  </div>`;
}

function recommendationsSectionHtml() {
  return `<div id="recSection" style="margin-top:16px;border-top:1px solid var(--border);padding-top:14px">
    <h4 style="margin:0 0 10px;font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em">${esc(t("rec_title"))}</h4>
    <div id="recList"><p class="muted">${esc(t("rec_loading"))}</p></div>
    <div class="field" style="margin:14px 0 0">
      <label for="recBody">${esc(t("rec_body_label"))}</label>
      <textarea id="recBody" rows="3" maxlength="${REC_BODY_MAX}" placeholder="${esc(t("rec_body_placeholder"))}" style="width:100%"></textarea>
      <label for="recAuthor" style="margin-top:9px">${esc(t("rec_author_label"))}</label>
      <input id="recAuthor" maxlength="${REC_AUTHOR_MAX}" placeholder="${esc(t("rec_author_placeholder"))}">
      <div class="row" style="margin-top:9px">
        <button class="primary small" id="recSubmit">${esc(t("rec_submit"))}</button>
        <span class="muted" id="recMsg" style="font-size:11.5px"></span>
      </div>
    </div>
  </div>`;
}

async function loadRecommendations(cid) {
  const list = document.getElementById("recList");
  if (!list) return;
  try {
    const res = await api(`/alerts/${encodeURIComponent(cid)}/recommendations`);
    if (state.openAlertId !== cid || !document.getElementById("recList")) return;
    const items = (res && res.recommendations) || [];
    list.innerHTML = items.length
      ? items.map(recommendationItemHtml).join("")
      : `<p class="muted">${esc(t("rec_empty"))}</p>`;
    wireRecommendations(cid);
  } catch (e) {
    if (state.openAlertId === cid && document.getElementById("recList")) {
      list.innerHTML = `<p class="muted">${esc(tBackendText(e.message))}</p>`;
    }
  }
}

function wireRecommendations(cid) {
  const section = document.getElementById("recSection");
  if (!section) return;
  const bodyIn = document.getElementById("recBody");
  const authorIn = document.getElementById("recAuthor");
  const submit = document.getElementById("recSubmit");
  if (!bodyIn || !authorIn || !submit) return;
  if (!authorIn.value) authorIn.value = recAuthorStored();

  submit.onclick = async () => {
    const body = bodyIn.value.trim();
    const author = authorIn.value.trim();
    if (!body || body.length > REC_BODY_MAX) { toast(t("rec_body_required"), true); return; }
    if (!author || author.length > REC_AUTHOR_MAX) { toast(t("rec_author_required"), true); return; }
    submit.disabled = true;
    submit.textContent = t("rec_submitting");
    try {
      const res = await api(`/alerts/${encodeURIComponent(cid)}/recommendations`, {
        method: "POST", body: JSON.stringify({ body, author }),
      });
      recAuthorRemember(author);
      bodyIn.value = "";
      const note = (res && res.notification) || {};
      if (note.queued) toast(t("rec_notify_queued", note.email_id ?? "?"));
      else if (note.reason) toast(t("rec_notify_skipped", tBackendText(note.reason)), true);
      else toast(t("rec_added_toast"));
      await loadRecommendations(cid);
      if (state.view === "alerts") loadRecommendationCounts();
    } catch (e) {
      toast(t("rec_add_failed") + tBackendText(e.message), true);
    }
    submit.disabled = false;
    submit.textContent = t("rec_submit");
  };

  section.onclick = async (e) => {
    const target = e.target.closest
      ? e.target.closest("[data-rec-retract], [data-rec-retract-confirm], [data-rec-retract-cancel]") : null;
    if (!target) return;
    const revealId = target.getAttribute("data-rec-retract");
    if (revealId) {
      const row = section.querySelector(`[data-rec-retract-row="${CSS.escape(revealId)}"]`);
      if (row) { row.classList.add("show"); const input = row.querySelector("input"); if (input) input.focus(); }
      return;
    }
    const cancelId = target.getAttribute("data-rec-retract-cancel");
    if (cancelId) {
      const row = section.querySelector(`[data-rec-retract-row="${CSS.escape(cancelId)}"]`);
      if (row) row.classList.remove("show");
      return;
    }
    const id = target.getAttribute("data-rec-retract-confirm");
    if (!id) return;
    const row = section.querySelector(`[data-rec-retract-row="${CSS.escape(id)}"]`);
    const input = row && row.querySelector("input");
    const reason = input ? input.value.trim() : "";
    const author = authorIn.value.trim();
    if (!reason) { toast(t("rec_reason_required"), true); if (input) input.focus(); return; }
    if (!author || author.length > REC_AUTHOR_MAX) { toast(t("rec_author_required"), true); authorIn.focus(); return; }
    target.disabled = true;
    try {
      await api(`/recommendations/${encodeURIComponent(id)}/retract`, {
        method: "POST", body: JSON.stringify({ author, reason }),
      });
      recAuthorRemember(author);
      toast(t("rec_retracted_toast"));
      await loadRecommendations(cid);
      if (state.view === "alerts") loadRecommendationCounts();
    } catch (err) {
      toast(t("rec_retract_failed") + tBackendText(err.message), true);
      target.disabled = false;
    }
  };
}

/** Counts for the alerts currently on screen: ONE request for the whole page
 * (the contract caps it at 500 ids), never one request per row. */
async function loadRecommendationCounts() {
  const cells = [...document.querySelectorAll("#alertRows [data-rec-count]")];
  if (!cells.length) return;
  const cids = cells.map((cell) => cell.getAttribute("data-rec-count")).filter(Boolean).slice(0, 500);
  if (!cids.length) return;
  const params = new URLSearchParams({ cids: cids.join(",") });
  try {
    const res = await api("/recommendations/counts?" + params.toString());
    const counts = (res && res.counts) || {};
    for (const cell of cells) {
      const n = Number(counts[cell.getAttribute("data-rec-count")]) || 0;
      cell.innerHTML = n
        ? `<span class="rec-count" title="${esc(t("rec_count_title", n))}">${esc(String(n))}</span>`
        : DASH;
    }
  } catch (e) { /* non-fatal: the column stays "—" */ }
}

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
      ${job.error ? `<div>${esc(t("kv_error2"))}</div><div style="color:var(--text-danger)">${esc(tBackendText(job.error))}</div>` : ""}
    </div>`;

  if (a) {
    html += `<div class="kv">
      ${kvRowIf(t("kv_detection"), a.detection_name)}
      ${kvRowIf(t("kv_endpoint"), endpointLabel(a))}
      ${knownValue(a.severity) ? kvRow(t("kv_severity_reported"), tBadgeLabel(a.severity)) : ""}
      <div>${esc(t("kv_risk_computed"))}</div><div>${badge(r.risk_level)}</div>
      ${riskFactorsRow(r.risk_factors, r.risk_rationale)}
      ${kvRowIf(t("kv_user"), a.user_name)}
      ${kvRowIf(t("kv_os"), a.os_name)}
      ${kvRowIf(t("kv_action_taken"), a.action_taken)}
      ${kvRowIf(t("kv_handled_isolated"), handledIsolatedLabel(a))}
      ${kvMonoRowIf(t("kv_object_uri"), a.object_uri)}
      ${kvMonoRowIf(t("kv_file_hash"), a.file_hash)}
      ${kvMonoRowIf(t("field_url"), a.url)}
      ${kvMonoRowIf(t("kv_ip_domain"),
        [knownValue(a.ip_address), knownValue(a.domain)].filter(Boolean).join(" / "))}
    </div>`;
  }

  if (r) html += threatIntelBlock(r.threat_intel);

  html += r && r.ai_output
    ? notificationTabs(r.ai_output)
    : `<p class="muted">${esc(t("no_ai_output"))}</p>`;

  html += recommendationsSectionHtml();

  showModal(t("modal_alert_detail"), html);
  state.openAlertId = id;
  state.reopenModal = () => openAlert(id);
  loadRecommendations(id);
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
  state.reopenModal = () => openRawPayload(id);
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
  ["recommendation", "recommendation_notification_emails"],
  ["weekly", "weekly_report_emails"],
];

async function loadSettings() {
  try {
    const s = await api("/settings");
    for (const [ui, key] of RECIPIENT_FIELDS) {
      const rec = s.recipients[key] || { value: "", source: "env" };
      document.getElementById("in-" + ui).value = rec.value || "";
      const src = document.getElementById("src-" + ui);
      src.textContent = rec.source === "dashboard" ? t("src_saved_here") : t("src_from_env");
    }
    document.getElementById("runtimeKv").innerHTML =
      Object.entries(s.runtime).map(([k, v]) =>
        `<div>${esc(RUNTIME_KEY_I18N[k] ? t(RUNTIME_KEY_I18N[k]) : k.replace(/_/g, " "))}</div><div class="mono">${esc(typeof v === "boolean" ? tBadgeLabel(String(v)) : v)}</div>`).join("");
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

/* ══════════════ client portal settings ══════════════ */

// Weekly-report settings first: this tab is opened to change when the report is
// sent far more often than for anything else here, so that group leads.
const PORTAL_GROUP_ORDER = ["weekly_report", "portal", "email"];
const PORTAL_GROUP_I18N = {
  weekly_report: "pgroup_weekly_report",
  portal: "pgroup_portal",
  email: "pgroup_email",
};
const PSET_WEEKDAY_I18N = {
  MON: "weekday_mon", TUE: "weekday_tue", WED: "weekday_wed", THU: "weekday_thu",
  FRI: "weekday_fri", SAT: "weekday_sat", SUN: "weekday_sun",
};
const PSET_RISK = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

function psetLabel(key) {
  const k = "pset_k_" + key;
  return t(k) === k ? key.replace(/_/g, " ") : t(k);
}
function psetHint(key, spec) {
  const k = "pset_d_" + key;
  return t(k) === k ? (spec.description || "") : t(k);
}
function psetChoiceLabel(value) {
  if (PSET_WEEKDAY_I18N[value]) return t(PSET_WEEKDAY_I18N[value]);
  if (PSET_RISK.includes(value)) return tBadgeLabel(value);
  return value;
}

function psetControlHtml(key, spec) {
  const id = "pset-" + esc(key);
  const c = spec.constraints || {};
  if (spec.type === "bool") return `<input type="checkbox" id="${id}" style="width:auto">`;
  if (spec.type === "enum") {
    const opts = (c.choices || []).map((v) =>
      `<option value="${esc(v)}">${esc(psetChoiceLabel(v))}</option>`).join("");
    return `<select id="${id}">${opts}</select>`;
  }
  if (spec.type === "int") {
    const min = c.min !== undefined ? ` min="${esc(c.min)}"` : "";
    const max = c.max !== undefined ? ` max="${esc(c.max)}"` : "";
    return `<input type="number" step="1"${min}${max} id="${id}">`;
  }
  if (spec.type === "time_hhmm") {
    return `<input type="time" id="${id}" step="60"> <span class="muted" style="font-size:11.5px">${esc(t("pset_jst"))}</span>`;
  }
  const maxlength = c.max_length ? ` maxlength="${esc(c.max_length)}"` : "";
  return `<input type="${spec.secret ? "password" : "text"}"${maxlength} id="${id}">`;
}

function psetRowHtml(key, spec) {
  return `<div class="pset-row" data-pset-row="${esc(key)}">
    <div class="pset-label">
      <label for="pset-${esc(key)}">${esc(psetLabel(key))}</label>
      <span class="key">${esc(key)}</span>
      <span class="hint">${esc(psetHint(key, spec))}</span>
    </div>
    <div>
      <div class="pset-control">
        ${psetControlHtml(key, spec)}
        <button class="small primary" data-pset-save="${esc(key)}">${esc(t("pset_save"))}</button>
        <button class="small" data-pset-reset="${esc(key)}">${esc(t("pset_reset"))}</button>
        <span class="srcbadge" style="margin-left:0">${esc(spec.source === "db" ? t("src_saved_here") : t("src_from_env"))}</span>
      </div>
      <div class="pset-err" role="alert" data-pset-err="${esc(key)}"></div>
    </div>
  </div>`;
}

function psetSetValue(key, spec, value) {
  const el = document.getElementById("pset-" + key);
  if (!el) return;
  if (spec.type === "bool") el.checked = !!value;
  else if (spec.type === "list") el.value = Array.isArray(value) ? value.join(", ") : (value || "");
  else el.value = value === null || value === undefined ? "" : String(value);
}

function renderPortalSettings(settings) {
  const box = document.getElementById("portalSettingsBody");
  if (!box) return;
  const groups = {};
  if (!Object.keys(settings || {}).length) {
    box.innerHTML = `<p class="muted">${esc(t("pset_empty"))}</p>`;
    return;
  }
  for (const [settingKey, spec] of Object.entries(settings || {})) {
    // The API keys the dict by setting name; the spec itself carries no "key".
    spec.key = settingKey;
    const group = spec.group || "other";
    if (!groups[group]) groups[group] = [];
    groups[group].push(spec);
  }
  const groupKeys = [
    ...PORTAL_GROUP_ORDER.filter((g) => groups[g]),
    ...Object.keys(groups).filter((g) => !PORTAL_GROUP_ORDER.includes(g)).sort(),
  ];
  box.innerHTML = groupKeys.map((group) => `
    <div class="pset-group">
      <h4>${esc(PORTAL_GROUP_I18N[group] ? t(PORTAL_GROUP_I18N[group]) : t("pgroup_other"))}</h4>
      ${groups[group].map((spec) => psetRowHtml(spec.key, spec)).join("")}
    </div>`).join("");

  for (const [key, spec] of Object.entries(settings || {})) {
    psetSetValue(key, spec, spec.value);
    const err = box.querySelector(`[data-pset-err="${CSS.escape(key)}"]`);
    if (err) { err.textContent = ""; err.classList.remove("show"); }
    const save = box.querySelector(`[data-pset-save="${CSS.escape(key)}"]`);
    if (save) save.onclick = () => savePortalSetting(key, spec);
    const reset = box.querySelector(`[data-pset-reset="${CSS.escape(key)}"]`);
    if (reset) reset.onclick = () => resetPortalSetting(key);
  }
}

function psetErrorMessage(e) {
  return tBackendText(e.message || String(e)) || t("unknown_error");
}

async function savePortalSetting(key, spec) {
  const el = document.getElementById("pset-" + key);
  const err = document.querySelector(`[data-pset-err="${CSS.escape(key)}"]`);
  if (!el) return;
  if (err) { err.textContent = ""; err.classList.remove("show"); }
  let value;
  if (spec.type === "bool") value = el.checked;
  else if (spec.type === "int") {
    const raw = el.value.trim();
    if (raw === "" || !/^-?\d+$/.test(raw)) {
      if (err) { err.textContent = t("pset_err_int"); err.classList.add("show"); }
      return;
    }
    value = Number(raw);
  } else if (spec.type === "list") {
    value = el.value.split(",").map((part) => part.trim()).filter(Boolean);
  } else {
    value = el.value;
  }
  try {
    await api(`/portal-settings/${encodeURIComponent(key)}`, {
      method: "PUT", body: JSON.stringify({ value }),
    });
    toast(t("pset_saved", psetLabel(key)));
    await loadPortalSettings();
  } catch (e) {
    if (err) { err.textContent = psetErrorMessage(e); err.classList.add("show"); }
    else toast(t("toast_save_failed") + psetErrorMessage(e), true);
  }
}

async function resetPortalSetting(key) {
  const err = document.querySelector(`[data-pset-err="${CSS.escape(key)}"]`);
  if (err) { err.textContent = ""; err.classList.remove("show"); }
  try {
    await api(`/portal-settings/${encodeURIComponent(key)}`, { method: "DELETE" });
    toast(t("pset_reset_done", psetLabel(key)));
    await loadPortalSettings();
  } catch (e) {
    if (err) { err.textContent = psetErrorMessage(e); err.classList.add("show"); }
    else toast(t("toast_save_failed") + psetErrorMessage(e), true);
  }
}

async function loadPortalSettings() {
  const box = document.getElementById("portalSettingsBody");
  if (!box) return;
  if (!box.innerHTML) box.innerHTML = `<p class="muted">${esc(t("pset_loading"))}</p>`;
  try {
    const res = await api("/portal-settings");
    renderPortalSettings((res && res.settings) || {});
  } catch (e) {
    box.innerHTML = `<p class="muted">${esc(t("pset_load_failed"))}${esc(psetErrorMessage(e))}</p>`;
  }
}

/* ══════════════ client portal: accounts + weekly reports ══════════════
 *
 * Every value that came from the API (usernames, display names, error text,
 * detection names, AI summaries) goes through esc() before reaching innerHTML.
 * A generated password lives ONLY in portalAdmin.secret (memory) and in the
 * dismissible box's text node: never in web storage, never logged, and cleared
 * as soon as the box is dismissed or the engineer leaves this view.
 */

const PORTAL_CLIENT_PATH = "/client";
const portalAdmin = {
  users: null,          // [User] from the last successful load
  enabled: null,        // client_portal_enabled, or null when unknown
  secret: null,         // { username, password } — shown once, then dropped
  noticeErr: "",
  resetFor: null,       // user id whose inline reset form is open
  deleteFor: null,      // user id whose inline delete confirm is open
  busy: false,
};
const portalReports = {
  data: null,           // last GET /reports/weekly response
  regenFor: null,       // period_key whose inline regenerate confirm is open
  openFindings: new Set(),
  busy: false,
};

const PW_STATUS_BADGE = {
  CLAIMED: "PROCESSING", GENERATED: "SUCCESS", QUEUED: "STARTED", SENT: "SUCCESS",
  NO_RECIPIENTS: "PARTIAL", FAILED: "FAILED", SKIPPED: "PENDING",
};

function portalPill(cls, label) {
  return `<span class="badge b-${esc(cls)}"><span class="g"></span>${esc(label)}</span>`;
}

/** Epoch seconds (what the portal APIs return) in the dashboard's usual local format. */
function fmtEpoch(sec) {
  return typeof sec === "number" && isFinite(sec) && sec > 0 ? fmtDateTime(new Date(sec * 1000)) : "";
}

function portalErrText(e) {
  if (e && e.status === 422) return t("pu_invalid_input");
  return tBackendText((e && e.message) || "") || t("unknown_error");
}

function showPortalErr(id, msg) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = msg || "";
  el.classList.toggle("show", !!msg);
}

async function copyPortalText(text) {
  try {
    await navigator.clipboard.writeText(text);
    toast(t("pu_copied"));
  } catch (e) {
    toast(t("toast_copy_blocked"), true);
  }
}

/** Drops the one-time password from memory and from the DOM. */
function clearPortalSecret() {
  portalAdmin.secret = null;
  const box = document.getElementById("pu-secret");
  if (box) box.innerHTML = "";
}

/* ---------- client accounts ---------- */

function ensurePortalUsersShell() {
  const root = document.getElementById("portalUsersBody");
  if (!root) return null;
  if (root.querySelector("#pu-table")) return root;
  root.innerHTML = `
    <div id="pu-notice"></div>
    <div class="pp-bar">
      <span class="muted" data-i18n="pu_url_label"></span>
      <code class="mono" id="pu-url"></code>
      <button class="small" id="pu-copy-url" data-i18n="pu_copy"></button>
    </div>
    <div id="pu-secret" aria-live="polite"></div>
    <div class="pp-form" id="pu-form">
      <div class="fld"><label for="pu-username" data-i18n="pu_f_username"></label>
        <input type="text" id="pu-username" maxlength="64" autocomplete="off" spellcheck="false"></div>
      <div class="fld"><label for="pu-display" data-i18n="pu_f_display_name"></label>
        <input type="text" id="pu-display" maxlength="100" autocomplete="off"></div>
      <div class="fld"><label for="pu-password" data-i18n="pu_f_password"></label>
        <input type="password" id="pu-password" autocomplete="new-password" spellcheck="false"></div>
      <button class="primary" id="pu-add" data-i18n="pu_add"></button>
      <p class="hint" data-i18n="pu_pw_hint"></p>
      <div class="pp-err" id="pu-form-err" role="alert"></div>
    </div>
    <div class="pp-err" id="pu-row-err" role="alert"></div>
    <div id="pu-table"><p class="muted">${esc(t("pu_loading"))}</p></div>`;
  document.getElementById("pu-url").textContent = location.origin + PORTAL_CLIENT_PATH;
  document.getElementById("pu-copy-url").onclick = () => copyPortalText(location.origin + PORTAL_CLIENT_PATH);
  document.getElementById("pu-add").onclick = addPortalUser;
  root.addEventListener("keydown", (e) => {
    if (e.key !== "Enter") return;
    if (e.target.closest("#pu-form")) { e.preventDefault(); addPortalUser(); }
    const reset = e.target.closest("[data-pu-reset-input]");
    if (reset) { e.preventDefault(); runPortalUserAction(reset.dataset.puResetInput, "reset"); }
  });
  root.addEventListener("click", onPortalUsersClick);
  applyStaticI18n();
  return root;
}

function portalUserById(id) {
  return (portalAdmin.users || []).find((u) => u.id === id);
}

function renderPortalNotice() {
  const box = document.getElementById("pu-notice");
  if (!box) return;
  if (portalAdmin.enabled === null) { box.innerHTML = ""; return; }
  const on = portalAdmin.enabled === true;
  box.innerHTML = `<div class="pp-note${on ? "" : " warn"}">
    <div>${esc(t(on ? "pu_portal_on" : "pu_portal_off"))}</div>
    <div class="row">
      <button class="small${on ? "" : " primary"}" data-pu-toggle-portal>${esc(t(on ? "pu_disable_portal" : "pu_enable_portal"))}</button>
    </div>
    <div class="pp-err${portalAdmin.noticeErr ? " show" : ""}" role="alert">${esc(portalAdmin.noticeErr)}</div>
  </div>`;
}

function renderPortalSecret() {
  const box = document.getElementById("pu-secret");
  if (!box) return;
  const s = portalAdmin.secret;
  if (!s) { box.innerHTML = ""; return; }
  box.innerHTML = `<div class="pp-secret" role="alert">
    <h4>${esc(t("pu_secret_title"))}</h4>
    <div class="muted" style="font-size:12px">${esc(t("pu_secret_account", s.username))}</div>
    <div class="pw" id="pu-secret-value">${esc(s.password)}</div>
    <div class="warnline">${esc(t("pu_secret_warn"))}</div>
    <div class="row" style="margin-top:8px">
      <button class="small primary" data-pu-secret-copy>${esc(t("pu_copy"))}</button>
      <button class="small" data-pu-secret-dismiss>${esc(t("pu_secret_dismiss"))}</button>
    </div>
  </div>`;
}

function puRowActions(u) {
  const id = esc(u.id);
  const btn = (act, key, cls) =>
    `<button class="small${cls ? " " + cls : ""}" data-pu-act="${act}" data-uid="${id}">${esc(t(key))}</button>`;
  let html = `<div class="pp-actions">
    ${btn("reset", "pu_act_reset")}
    ${u.disabled ? btn("enable", "pu_act_enable") : btn("disable", "pu_act_disable")}
    ${u.locked ? btn("unlock", "pu_act_unlock") : ""}
    ${btn("revoke-sessions", "pu_act_signout")}
    ${btn("delete", "pu_act_delete", "danger")}
  </div>`;
  if (portalAdmin.resetFor === u.id) {
    html += `<div class="pp-inline">
      <label for="pu-reset-${id}">${esc(t("pu_reset_label"))}</label>
      <input type="password" id="pu-reset-${id}" autocomplete="new-password" spellcheck="false" data-pu-reset-input="${id}">
      <button class="small primary" data-pu-act="reset-submit" data-uid="${id}">${esc(t("pu_reset_submit"))}</button>
      <button class="small" data-pu-act="cancel" data-uid="${id}">${esc(t("pu_cancel"))}</button>
    </div>`;
  }
  if (portalAdmin.deleteFor === u.id) {
    html += `<div class="pp-inline" role="alert">
      <span>${esc(t("pu_confirm_delete", u.username))}</span>
      <button class="small danger" data-pu-act="delete-confirm" data-uid="${id}">${esc(t("pu_confirm_delete_yes"))}</button>
      <button class="small" data-pu-act="cancel" data-uid="${id}">${esc(t("pu_cancel"))}</button>
    </div>`;
  }
  return html;
}

function renderPortalUsers() {
  if (!ensurePortalUsersShell()) return;
  renderPortalNotice();
  renderPortalSecret();
  const box = document.getElementById("pu-table");
  const users = portalAdmin.users;
  if (users === null) return;
  if (!users.length) {
    box.innerHTML = `<div class="empty">${esc(t("pu_empty"))}</div>`;
    return;
  }
  const rows = users.map((u) => {
    const badges = (u.disabled ? portalPill("PENDING", t("pu_status_disabled")) : "")
      + (u.locked ? portalPill("BLOCKED", t("pu_status_locked")) : "")
      + (!u.disabled && !u.locked ? portalPill("SUCCESS", t("pu_status_active")) : "");
    const last = fmtEpoch(u.last_login_at);
    return `<tr>
      <td><strong>${esc(u.username)}</strong></td>
      <td>${u.display_name ? esc(u.display_name) : DASH}</td>
      <td>${badges}</td>
      <td>${last ? esc(last) : `<span class="dim">${esc(t("pu_never"))}</span>`}</td>
      <td>${esc(u.active_sessions || 0)}</td>
      <td>${puRowActions(u)}</td>
    </tr>`;
  }).join("");
  box.innerHTML = `<div class="pp-tablewrap"><table>
    <thead><tr>
      <th>${esc(t("pu_th_username"))}</th><th>${esc(t("pu_th_display_name"))}</th>
      <th>${esc(t("pu_th_status"))}</th><th>${esc(t("pu_th_last_login"))}</th>
      <th>${esc(t("pu_th_sessions"))}</th><th>${esc(t("pu_th_actions"))}</th>
    </tr></thead><tbody>${rows}</tbody></table></div>`;
}

async function loadPortalUsers() {
  if (!ensurePortalUsersShell()) return;
  const [usersRes, settingsRes] = await Promise.allSettled([
    api("/portal/users"), api("/portal-settings"),
  ]);
  if (settingsRes.status === "fulfilled") {
    const spec = settingsRes.value && settingsRes.value.settings
      && settingsRes.value.settings.client_portal_enabled;
    portalAdmin.enabled = spec && typeof spec.value === "boolean" ? spec.value : null;
  }
  if (usersRes.status === "fulfilled") {
    portalAdmin.users = (usersRes.value && usersRes.value.users) || [];
    showPortalErr("pu-row-err", "");
  } else if (portalAdmin.users === null) {
    document.getElementById("pu-table").innerHTML =
      `<p class="muted">${esc(t("pu_load_failed"))}${esc(portalErrText(usersRes.reason))}</p>`;
  } else {
    showPortalErr("pu-row-err", t("pu_load_failed") + portalErrText(usersRes.reason));
  }
  renderPortalUsers();
}

async function addPortalUser() {
  if (portalAdmin.busy) return;
  const nameEl = document.getElementById("pu-username");
  const displayEl = document.getElementById("pu-display");
  const pwEl = document.getElementById("pu-password");
  const username = nameEl.value.trim();
  showPortalErr("pu-form-err", "");
  if (!username) { showPortalErr("pu-form-err", t("pu_username_required")); nameEl.focus(); return; }
  const body = { username };
  if (displayEl.value.trim()) body.display_name = displayEl.value.trim();
  if (pwEl.value) body.password = pwEl.value;
  portalAdmin.busy = true;
  const addBtn = document.getElementById("pu-add");
  addBtn.disabled = true;
  try {
    const res = await api("/portal/users", { method: "POST", body: JSON.stringify(body) });
    nameEl.value = ""; displayEl.value = ""; pwEl.value = "";
    const created = (res && res.user && res.user.username) || username;
    if (res && res.generated_password) portalAdmin.secret = { username: created, password: res.generated_password };
    else clearPortalSecret();
    toast(t("pu_created", created));
    await loadPortalUsers();
  } catch (e) {
    showPortalErr("pu-form-err", portalErrText(e));
  }
  portalAdmin.busy = false;
  addBtn.disabled = false;
}

const PU_ACTIONS = {
  disable: { path: "disable", done: "pu_disabled_done" },
  enable: { path: "enable", done: "pu_enabled_done" },
  unlock: { path: "unlock", done: "pu_unlocked_done" },
  "revoke-sessions": { path: "revoke-sessions", done: "pu_signed_out_done" },
};

async function runPortalUserAction(id, act) {
  const user = portalUserById(id);
  if (!user || portalAdmin.busy) return;
  const enc = encodeURIComponent(id);
  portalAdmin.busy = true;
  showPortalErr("pu-row-err", "");
  try {
    if (act === "reset") {
      const input = document.getElementById("pu-reset-" + id);
      const pw = input ? input.value : "";
      const res = await api(`/portal/users/${enc}/password`, {
        method: "POST", body: JSON.stringify(pw ? { password: pw } : {}),
      });
      portalAdmin.resetFor = null;
      if (res && res.generated_password) portalAdmin.secret = { username: user.username, password: res.generated_password };
      else clearPortalSecret();
      toast(t("pu_password_reset_done", user.username));
    } else if (act === "delete") {
      await api(`/portal/users/${enc}`, { method: "DELETE" });
      portalAdmin.deleteFor = null;
      if (portalAdmin.secret && portalAdmin.secret.username === user.username) clearPortalSecret();
      toast(t("pu_deleted_done", user.username));
    } else {
      const spec = PU_ACTIONS[act];
      const res = await api(`/portal/users/${enc}/${spec.path}`, { method: "POST" });
      toast(t(spec.done, user.username, res && res.revoked !== undefined ? res.revoked : 0));
    }
    await loadPortalUsers();
  } catch (e) {
    showPortalErr("pu-row-err", t("pu_action_failed") + portalErrText(e));
  }
  portalAdmin.busy = false;
}

async function togglePortalEnabled() {
  if (portalAdmin.busy || portalAdmin.enabled === null) return;
  const next = !portalAdmin.enabled;
  portalAdmin.busy = true;
  portalAdmin.noticeErr = "";
  try {
    await api("/portal-settings/client_portal_enabled", {
      method: "PUT", body: JSON.stringify({ value: next }),
    });
    portalAdmin.enabled = next;
    toast(t(next ? "pu_portal_enabled_done" : "pu_portal_disabled_done"));
    loadPortalSettings();
  } catch (e) {
    // e.g. 409 "dashboard key too short": shown right where the switch is.
    portalAdmin.noticeErr = t("pu_portal_toggle_failed") + portalErrText(e);
  }
  portalAdmin.busy = false;
  renderPortalNotice();
}

function onPortalUsersClick(e) {
  if (e.target.closest("[data-pu-toggle-portal]")) { togglePortalEnabled(); return; }
  if (e.target.closest("[data-pu-secret-copy]")) {
    if (portalAdmin.secret) copyPortalText(portalAdmin.secret.password);
    return;
  }
  if (e.target.closest("[data-pu-secret-dismiss]")) { clearPortalSecret(); return; }
  const b = e.target.closest("[data-pu-act]");
  if (!b) return;
  const id = b.dataset.uid;
  const act = b.dataset.puAct;
  if (act === "reset") {
    portalAdmin.resetFor = portalAdmin.resetFor === id ? null : id;
    portalAdmin.deleteFor = null;
    renderPortalUsers();
    const input = document.getElementById("pu-reset-" + id);
    if (input) input.focus();
  } else if (act === "reset-submit") runPortalUserAction(id, "reset");
  else if (act === "delete") {
    portalAdmin.deleteFor = portalAdmin.deleteFor === id ? null : id;
    portalAdmin.resetFor = null;
    renderPortalUsers();
  } else if (act === "delete-confirm") runPortalUserAction(id, "delete");
  else if (act === "cancel") {
    portalAdmin.resetFor = null; portalAdmin.deleteFor = null;
    renderPortalUsers();
  } else if (PU_ACTIONS[act]) runPortalUserAction(id, act);
}

/* ---------- weekly reports ---------- */

function pwPeriodLabel(p) {
  if (!p) return "";
  const start = String(p.period_start || "").slice(0, 10);
  const last = String(p.last_day || "");
  return start || last ? `${p.period_key} (${start} – ${last})` : String(p.period_key || "");
}

function pwStatusLabel(status) {
  const k = "pw_status_" + status;
  return t(k) === k ? String(status || "") : t(k);
}

function pwTriggerLabel(trigger) {
  const k = "pw_trigger_" + trigger;
  return t(k) === k ? String(trigger || "") : t(k);
}

function pwCountsHtml(c) {
  const n = (v) => esc(typeof v === "number" ? v : 0);
  return `<span class="pp-counts">${["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    .map((lvl) => `<span>${esc(tBadgeLabel(lvl))} ${n((c || {})[lvl])}</span>`).join("")}</span>`;
}

function pwFindingsHtml(r) {
  const list = Array.isArray(r.findings) ? r.findings : [];
  if (!list.length) return "";
  const rows = list.map((f) => `<tr>
    <td class="mono">${esc(f.eset_alert_id || f.alert_id)}</td>
    <td>${badge(f.risk_level)}</td>
    <td>${esc(f.detection_name)}</td>
    <td>${esc(f.endpoint_name)}</td>
    <td class="pp-clip">${esc(f.ai_summary)}</td>
  </tr>`).join("");
  const open = portalReports.openFindings.has(r.period_key) ? " open" : "";
  return `<details class="pp-find" data-pw-find="${esc(r.period_key)}"${open}>
    <summary>${esc(t("pw_findings_toggle", list.length))}</summary>
    <div class="pp-tablewrap"><table><thead><tr>
      <th>${esc(t("pw_f_alert"))}</th><th>${esc(t("pw_f_risk"))}</th><th>${esc(t("pw_f_detection"))}</th>
      <th>${esc(t("pw_f_endpoint"))}</th><th>${esc(t("pw_f_summary"))}</th>
    </tr></thead><tbody>${rows}</tbody></table></div>
  </details>`;
}

function pwRowHtml(r) {
  const key = esc(r.period_key);
  const completed = fmtEpoch(r.completed_at);
  let actions = `<div class="pp-actions">
    ${r.has_file ? `<button class="small" data-pw-act="download" data-period="${key}">${esc(t("pw_download"))}</button>` : ""}
    <button class="small" data-pw-act="regen" data-period="${key}">${esc(t("pw_regenerate"))}</button>
  </div>`;
  if (portalReports.regenFor === r.period_key) {
    actions += `<div class="pp-inline" role="alert">
      <span>${esc(t("pw_confirm_regenerate", r.period_key))}</span>
      <button class="small primary" data-pw-act="regen-confirm" data-period="${key}">${esc(t("pw_confirm_regenerate_yes"))}</button>
      <button class="small" data-pw-act="regen-cancel" data-period="${key}">${esc(t("pu_cancel"))}</button>
    </div>`;
  }
  const err = r.error
    ? `<div class="pp-err show">${esc(t("pw_error_prefix"))}${esc(r.error)}</div>` : "";
  return `<tr>
    <td>${esc(pwPeriodLabel(r))}</td>
    <td>${portalPill(PW_STATUS_BADGE[r.status] || "UNKNOWN", pwStatusLabel(r.status))}${err}</td>
    <td>${pwCountsHtml(r.counts)}</td>
    <td>${esc(t(r.has_file ? "pw_file_yes" : "pw_file_no"))}</td>
    <td>${esc(pwTriggerLabel(r.trigger))}</td>
    <td>${completed ? esc(completed) : DASH}</td>
    <td>${actions}</td>
  </tr>${(r.findings || []).length ? `<tr><td colspan="7" style="padding-top:0">${pwFindingsHtml(r)}</td></tr>` : ""}`;
}

function renderPortalReports() {
  const box = document.getElementById("portalReportsBody");
  if (!box) return;
  const d = portalReports.data;
  if (!d) return;
  const sch = d.schedule || {};
  const dayKey = PSET_WEEKDAY_I18N[sch.weekday];
  const nextRun = d.next_run_at ? fmtDateTime(d.next_run_at) : "";
  const reports = Array.isArray(d.reports) ? d.reports : [];
  const table = reports.length
    ? `<div class="pp-tablewrap"><table><thead><tr>
        <th>${esc(t("pw_th_period"))}</th><th>${esc(t("pw_th_status"))}</th><th>${esc(t("pw_th_counts"))}</th>
        <th>${esc(t("pw_th_file"))}</th><th>${esc(t("pw_th_trigger"))}</th><th>${esc(t("pw_th_completed"))}</th>
        <th>${esc(t("pw_th_actions"))}</th>
      </tr></thead><tbody>${reports.map(pwRowHtml).join("")}</tbody></table></div>`
    : `<div class="empty">${esc(t("pw_empty"))}</div>`;
  box.innerHTML = `
    <div class="pp-bar">
      ${portalPill(d.enabled ? "SUCCESS" : "PENDING", t(d.enabled ? "pw_auto_on" : "pw_auto_off"))}
      <span>${esc(t("pw_schedule", dayKey ? t(dayKey) : sch.weekday, sch.time))}</span>
    </div>
    <div class="pp-bar">
      <span><span class="muted">${esc(t("pw_next_run"))}:</span> ${nextRun ? esc(nextRun) : DASH}</span>
      <span><span class="muted">${esc(t("pw_next_period"))}:</span> ${esc(pwPeriodLabel(d.next_period))}</span>
      <span><span class="muted">${esc(t("pw_due_period"))}:</span> ${esc(pwPeriodLabel(d.latest_due_period))}</span>
    </div>
    <div class="pp-note${d.email_enabled ? "" : " warn"}">
      <div>${esc(t(d.email_enabled ? "pw_email_on" : "pw_email_off"))}</div>
      <div class="muted" style="font-size:11.5px;margin-top:3px">${esc(t("pw_settings_hint"))}</div>
    </div>
    <div class="pp-bar">
      <button class="primary" data-pw-act="run">${esc(t("pw_run"))}</button>
      <button data-pw-act="preview">${esc(t("pw_preview"))}</button>
    </div>
    <div class="pp-err" id="pw-err" role="alert"></div>
    ${table}`;
}

async function loadPortalReports() {
  const box = document.getElementById("portalReportsBody");
  if (!box) return;
  if (!portalReports.data && !box.querySelector(".pp-bar")) {
    box.innerHTML = `<p class="muted">${esc(t("pw_loading"))}</p>`;
  }
  try {
    portalReports.data = await api("/reports/weekly");
    renderPortalReports();
  } catch (e) {
    if (portalReports.data) { renderPortalReports(); showPortalErr("pw-err", t("pw_load_failed") + portalErrText(e)); }
    else box.innerHTML = `<p class="muted">${esc(t("pw_load_failed"))}${esc(portalErrText(e))}</p>`;
  }
}

/** Same fetch -> blob -> a[download] pattern as the alert export: the request
 * needs the key header, so a plain link would not authenticate. */
async function downloadPortalFile(path, fallbackName) {
  const res = await fetch(API + path, {
    headers: dashKey() ? { "X-Dashboard-Key": dashKey() } : {},
  });
  if (res.status === 401) { lock(); throw new Error("unauthorized"); }
  if (!res.ok) throw new Error(String(res.status));
  const blob = await res.blob();
  const name = (res.headers.get("Content-Disposition") || "").match(/filename="([^"]+)"/);
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = name ? name[1] : fallbackName;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

async function runPortalReport(periodKey, regenerate) {
  if (portalReports.busy) return;
  portalReports.busy = true;
  showPortalErr("pw-err", "");
  try {
    const body = {};
    if (periodKey) body.period_key = periodKey;
    if (regenerate) body.regenerate = true;
    const res = await api("/reports/weekly/run", { method: "POST", body: JSON.stringify(body) });
    portalReports.regenFor = null;
    if (res && res.action === "failed") {
      showPortalErr("pw-err", t("pw_run_failed") + (tBackendText(res.error || "") || t("unknown_error")));
    } else if (res && res.action === "none") {
      toast(t("pw_run_none"), true);
    } else {
      toast(t("pw_run_generated", (res && res.period_key) || periodKey || ""));
    }
    await loadPortalReports();
  } catch (e) {
    showPortalErr("pw-err", t("pw_run_failed") + portalErrText(e));
  }
  portalReports.busy = false;
}

async function onPortalReportsClick(e) {
  const b = e.target.closest("[data-pw-act]");
  if (!b) return;
  const act = b.dataset.pwAct;
  const key = b.dataset.period;
  if (act === "run") runPortalReport(null, false);
  else if (act === "preview") {
    b.disabled = true;
    try {
      const due = portalReports.data && portalReports.data.latest_due_period;
      const qs = due && due.period_key ? `?period_key=${encodeURIComponent(due.period_key)}` : "";
      await downloadPortalFile("/reports/weekly/preview" + qs, "preview_weekly_report.xlsx");
      toast(t("pw_preview_done"));
    } catch (err) { toast(t("pw_preview_failed"), true); }
    b.disabled = false;
  } else if (act === "download") {
    b.disabled = true;
    try {
      await downloadPortalFile(`/reports/weekly/${encodeURIComponent(key)}/download`, `weekly_report_${key}.xlsx`);
    } catch (err) { toast(t("pw_download_failed"), true); }
    b.disabled = false;
  } else if (act === "regen") {
    portalReports.regenFor = portalReports.regenFor === key ? null : key;
    renderPortalReports();
  } else if (act === "regen-cancel") {
    portalReports.regenFor = null;
    renderPortalReports();
  } else if (act === "regen-confirm") runPortalReport(key, true);
}

(function wirePortalReportsPanel() {
  const box = document.getElementById("portalReportsBody");
  if (!box) return;
  box.addEventListener("click", onPortalReportsClick);
  // <details> toggle does not bubble, so listen in the capture phase to remember
  // which findings lists are open across re-renders.
  box.addEventListener("toggle", (e) => {
    const d = e.target.closest && e.target.closest("[data-pw-find]");
    if (!d) return;
    if (d.open) portalReports.openFindings.add(d.dataset.pwFind);
    else portalReports.openFindings.delete(d.dataset.pwFind);
  }, true);
})();

function loadPortalPanels() {
  loadPortalSettings();
  loadPortalUsers();
  loadPortalReports();
}

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
    ["GET", "/dashboard/api/alerts/{cid}/recommendations", t("route_rec_list")],
    ["POST", "/dashboard/api/alerts/{cid}/recommendations", t("route_rec_create")],
    ["POST", "/dashboard/api/recommendations/{id}/retract", t("route_rec_retract")],
    ["GET", "/dashboard/api/recommendations/counts", t("route_rec_counts")],
    ["GET", "/dashboard/api/portal-settings", t("route_portal_settings")],
    ["PUT", "/dashboard/api/portal-settings/{key}", t("route_portal_settings_update")],
    ["DELETE", "/dashboard/api/portal-settings/{key}", t("route_portal_settings_reset")],
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
 * without colour vision. The service name is the markup's data-health-name
 * translation key, so it follows the language toggle. */
const HEALTH_DOTS = ["dbDot", "aiDot", "dirDot", "udpDot", "tcpDot"];
const healthState = {};   // dot id -> true | false; absent = not checked yet

function renderHealth() {
  for (const id of HEALTH_DOTS) {
    const el = document.getElementById(id);
    if (!el) continue;
    const ok = healthState[id];
    el.className = "dot" + (ok === undefined ? "" : ok ? " ok" : " bad");
    const label = `${t(el.dataset.healthName)}: ${
      ok === undefined ? t("health_unknown") : t(ok ? "health_ok" : "health_down")}`;
    el.setAttribute("aria-label", label);
    el.setAttribute("title", label);
  }
}

async function loadHealth() {
  try {
    const h = await (await fetch("/health")).json();
    healthState.dbDot = h.database?.status === "ok";
    healthState.aiDot = h.ai_provider?.status === "configured";
    healthState.dirDot = h.output_directory?.status === "ok";
    healthState.udpDot = h.syslog_listener?.udp === "ok";
    healthState.tcpDot = h.syslog_listener?.tcp === "ok";
  } catch (e) { /* transient */ }
  renderHealth();
}
renderHealth();

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

  } else if (msg.type === "recommendation_added") {
    if (state.openAlertId && state.openAlertId === d.correlation_id
        && document.getElementById("overlay").classList.contains("show")) {
      loadRecommendations(state.openAlertId);
    }
    if (state.view === "alerts") loadRecommendationCounts();

  } else if (msg.type === "email_queued") {
    state.emails.unshift(d);
    renderEmails();

  } else if (msg.type === "email_accepted") {
    // Handed to the mail service — it leaves our pending outbox
    state.emails = state.emails.filter((m) => m.email_id !== d.email_id);
    renderEmails();
    if (state.view === "emails") loadDelivery();
    toast(t("toast_email_accepted", d.remote_id ?? "?"));

  } else if (msg.type === "email_failed") {
    state.emails = state.emails.filter((m) => m.email_id !== d.email_id);
    renderEmails();
    if (state.view === "emails") loadDelivery();
    toast(t("toast_email_failed", d.error ? tBackendText(d.error) : t("unknown_error")), true);

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
