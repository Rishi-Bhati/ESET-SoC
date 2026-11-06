/* ESET SOC Lite — client portal.
 *
 * Standalone page (no engineering JS, no /static/* assets, no WebSocket). It only
 * talks to /client/api/* with the X-Client-Session header. All dynamic text is
 * either put through esc() before it enters markup or assigned via textContent;
 * every ${...} that reaches innerHTML is esc(...), encodeURIComponent(...), a
 * pre-escaped *Html value, or sevBadge(...) (tests/integration/test_client_portal_page.py
 * enforces this).
 */
"use strict";

const API = "/client/api";
const SESSION_KEY = "client_session";
const LANG_KEY = "client_lang";
const THEME_KEY = "client_theme";
const EXPORT_PREFS_KEY = "client_export_prefs";
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];   // display order
const FILTER_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
const DETAIL_HASH = /^#\/alerts\/([^/?#]+)$/;

const state = {
  lang: "ja",
  token: "",
  user: null,
  tab: "alerts",
  filters: { risk: new Set(), from: "", to: "", sort: "desc", size: 25, page: 1 },
  list: null,            // last /alerts response
  alertsSeq: 0,
  catalog: null,         // /export/fields response
  detailId: null,
  detailSeq: 0,
  detail: null,          // last /alerts/{id} response
  detailError: "",
  reports: null,
  reportsError: "",
  keepHash: false,
  exp: null,             // export dialog state
  exportAbort: null,
};

const $ = (id) => document.getElementById(id);

// ------------------------------------------------------------------ helpers

const ESC_MAP = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
function esc(v) {
  if (v === null || v === undefined) return "";
  return String(v).replace(/[&<>"']/g, (c) => ESC_MAP[c]);
}

function storeGet(kind, key) {
  try { return (kind === "session" ? sessionStorage : localStorage).getItem(key); } catch (e) { return null; }
}
function storeSet(kind, key, value) {
  try { (kind === "session" ? sessionStorage : localStorage).setItem(key, value); } catch (e) { /* blocked */ }
}
function storeDel(kind, key) {
  try { (kind === "session" ? sessionStorage : localStorage).removeItem(key); } catch (e) { /* blocked */ }
}

function t(key, ...args) {
  const table = CLIENT_I18N[state.lang] || CLIENT_I18N.en;
  const tpl = Object.prototype.hasOwnProperty.call(table, key) ? table[key] : key;
  return tpl.replace(/\{(\d+)\}/g, (m, i) => (args[Number(i)] !== undefined ? String(args[Number(i)]) : ""));
}

function uiLocale() { return state.lang === "ja" ? "ja-JP" : "en-GB"; }

const _fmtCache = {};
function jstFormatter() {
  const loc = uiLocale();
  if (!_fmtCache[loc]) {
    _fmtCache[loc] = new Intl.DateTimeFormat(loc, {
      timeZone: "Asia/Tokyo", year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", hour12: false,
    });
  }
  return _fmtCache[loc];
}
/** Epoch seconds -> "2026/11/05 14:03 JST". */
function fmtJst(epoch) {
  if (typeof epoch !== "number" || !isFinite(epoch)) return "—";
  return jstFormatter().format(new Date(epoch * 1000)) + " JST";
}
function fmtNum(n) { return Number(n || 0).toLocaleString(uiLocale()); }
function fmtDay(v) { return typeof v === "string" ? v.slice(0, 10) : "—"; }

function isSeverity(level) { return SEVERITIES.includes(level); }
function sevBadge(level) {
  const known = isSeverity(level);
  const cls = known ? level : "UNKNOWN";
  const label = known ? t("sev_" + level) : (level || "—");
  return `<span class="badge sev-${esc(cls)}">${esc(label)}</span>`;
}

/** `text` when `cond`, else nothing (keeps conditional markup out of ${...} ternaries). */
function flag(cond, text) { return cond ? text : ""; }

function show(el, on) { el.hidden = !on; }
function setNotice(el, text) { el.textContent = text || ""; show(el, !!text); }

let toastTimer = 0;
function toast(text, isError) {
  const el = $("toast");
  el.textContent = text;
  el.classList.toggle("error", !!isError);
  show(el, true);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => show(el, false), 5000);
}

class ApiError extends Error {
  constructor(status, detail, retryAfter) {
    super("api " + status);
    this.status = status;
    this.detail = detail || "";
    this.retryAfter = retryAfter ? Number(retryAfter) : 0;
  }
}

/** fetch against /client/api. Throws ApiError for non-2xx and network failures
 * (status 0); AbortError passes through. 401 anywhere ends the session. */
async function apiFetch(path, opts = {}) {
  const headers = {};
  if (state.token && opts.auth !== false) headers["X-Client-Session"] = state.token;
  const init = { method: opts.method || "GET", headers, signal: opts.signal, credentials: "same-origin", cache: "no-store" };
  if (opts.body !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  let res;
  try {
    res = await fetch(API + path, init);
  } catch (e) {
    if (e && e.name === "AbortError") throw e;
    throw new ApiError(0, "");
  }
  if (res.ok) return res;
  let detail = "";
  try {
    const j = await res.json();
    if (j && typeof j.detail === "string") detail = j.detail;
  } catch (e) { /* not JSON */ }
  const err = new ApiError(res.status, detail, res.headers.get("Retry-After"));
  if (opts.auth !== false && state.token) {
    if (res.status === 401) endSession("expired");
    else if (res.status === 404 && detail === "client portal disabled") endSession("disabled");
  }
  throw err;
}
async function api(path, opts) { return (await apiFetch(path, opts)).json(); }

function filenameFrom(res, fallback) {
  const m = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(res.headers.get("Content-Disposition") || "");
  let name = m ? m[1] : fallback;
  try { name = decodeURIComponent(name); } catch (e) { /* keep as is */ }
  name = name.replace(/[\\/:*?"<>|\u0000-\u001f]/g, "_").trim();
  return name || fallback;
}
function saveBlob(blob, name) {
  const a = document.createElement("a");
  const url = URL.createObjectURL(blob);
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// -------------------------------------------------------------- language/theme

function initialLang() {
  const saved = storeGet("local", LANG_KEY);
  if (saved === "ja" || saved === "en") return saved;
  const nav = (navigator.languages && navigator.languages[0]) || navigator.language || "";
  return String(nav).toLowerCase().startsWith("ja") ? "ja" : "en";
}

function applyStaticI18n() {
  document.documentElement.lang = state.lang;
  document.title = t("page_title");
  document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
  document.querySelectorAll("[data-i18n-aria]").forEach((el) => { el.setAttribute("aria-label", t(el.dataset.i18nAria)); });
  document.querySelectorAll("[data-i18n-title]").forEach((el) => { el.setAttribute("title", t(el.dataset.i18nTitle)); });
  $("langJa").setAttribute("aria-pressed", String(state.lang === "ja"));
  $("langEn").setAttribute("aria-pressed", String(state.lang === "en"));
  if (state.user) {
    const name = state.user.display_name || state.user.username || "";
    $("userName").textContent = t("signed_in_as", name);
  }
}

function setLang(lang) {
  if (lang !== "ja" && lang !== "en") return;
  state.lang = lang;
  storeSet("local", LANG_KEY, lang);
  applyStaticI18n();
  if (state.token) renderAll();
}

function applyTheme(theme) {
  if (theme === "light" || theme === "dark") document.documentElement.setAttribute("data-theme", theme);
}
function toggleTheme() {
  const explicit = document.documentElement.getAttribute("data-theme");
  const light = explicit ? explicit === "light"
    : !!(window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches);
  const next = light ? "dark" : "light";
  applyTheme(next);
  storeSet("local", THEME_KEY, next);
}

function renderAll() {
  renderSevFilter();
  renderList();
  if (state.tab === "reports") renderReports();
  if ($("detailDialog").open) renderDetail();
  if ($("exportDialog").open) buildExport();
}

// -------------------------------------------------------------------- session

function showLogin(notice, error) {
  show($("appView"), false);
  show($("loginView"), true);
  show($("logoutBtn"), false);
  show($("userName"), false);
  setNotice($("loginNotice"), notice || "");
  setNotice($("loginError"), error || "");
  $("loginPass").value = "";
}

function endSession(reason) {
  state.token = "";
  state.user = null;
  state.list = null;
  state.detail = null;
  state.reports = null;
  storeDel("session", SESSION_KEY);
  if (state.exportAbort) state.exportAbort.abort();
  state.keepHash = true;               // keep a #/alerts/<id> deep link for after the next login
  for (const id of ["detailDialog", "exportDialog"]) {
    const d = $(id);
    if (d.open) d.close();
  }
  state.keepHash = false;
  if (reason === "expired") showLogin(t("notice_session_expired"));
  else if (reason === "disabled") showLogin("", t("err_portal_disabled"));
  else showLogin(t("notice_signed_out"));
  $("loginUser").focus();
}

function showApp() {
  show($("loginView"), false);
  show($("appView"), true);
  show($("logoutBtn"), true);
  show($("userName"), true);
  applyStaticI18n();
  renderSevFilter();
  syncFilterInputs();
  loadAlerts();
  ensureCatalog();
  applyRoute();
}

async function onLogin(ev) {
  ev.preventDefault();
  const username = $("loginUser").value.trim();
  const password = $("loginPass").value;
  setNotice($("loginNotice"), "");
  if (!username || !password) { setNotice($("loginError"), t("err_login_required")); return; }
  setNotice($("loginError"), "");
  const btn = $("loginSubmit");
  btn.disabled = true;
  btn.textContent = t("login_busy");
  try {
    const data = await api("/auth/login", { method: "POST", body: { username, password }, auth: false });
    state.token = data.token;
    state.user = data.user || { username };
    storeSet("session", SESSION_KEY, state.token);
    $("loginPass").value = "";
    showApp();
  } catch (e) {
    let msg = t("err_generic");
    if (e.status === 401) msg = t("err_login_invalid");
    else if (e.status === 429) msg = t("err_login_throttled", e.retryAfter || 60);
    else if (e.status === 404) msg = t("err_portal_disabled");
    else if (e.status === 0) msg = t("err_network");
    setNotice($("loginError"), msg);
    $("loginPass").value = "";
    $("loginPass").focus();
  } finally {
    btn.disabled = false;
    btn.textContent = t("login_submit");
  }
}

async function onLogout() {
  const btn = $("logoutBtn");
  btn.disabled = true;
  try { await apiFetch("/auth/logout", { method: "POST" }); } catch (e) { /* the session is dropped locally regardless */ }
  btn.disabled = false;
  if (state.token) endSession("signed_out");
}

// -------------------------------------------------------------------- filters

function renderSevFilter() {
  const boxHtml = FILTER_SEVERITIES.map((lvl) => `
    <label class="sev-opt"><input type="checkbox" data-risk="${esc(lvl)}"${flag(state.filters.risk.has(lvl), " checked")}>
      ${sevBadge(lvl)}</label>`).join("");
  $("sevFilter").innerHTML = boxHtml;
}

function syncFilterInputs() {
  const f = state.filters;
  $("fFrom").value = f.from;
  $("fTo").value = f.to;
  $("fSort").value = f.sort;
  $("fSize").value = String(f.size);
}

function filtersChanged() { state.filters.page = 1; loadAlerts(); }

function onSevChange(ev) {
  const box = ev.target.closest("input[data-risk]");
  if (!box) return;
  const lvl = box.dataset.risk;
  if (box.checked) state.filters.risk.add(lvl); else state.filters.risk.delete(lvl);
  filtersChanged();
}

function onChipClick(ev) {
  const chip = ev.target.closest("button[data-risk]");
  if (!chip) return;
  const lvl = chip.dataset.risk;
  if (state.filters.risk.has(lvl)) state.filters.risk.delete(lvl); else state.filters.risk.add(lvl);
  renderSevFilter();
  filtersChanged();
}

function alertsQuery(page) {
  const f = state.filters;
  const q = new URLSearchParams();
  if (f.risk.size) q.set("risk", FILTER_SEVERITIES.filter((l) => f.risk.has(l)).join(","));
  if (f.from) q.set("from", f.from);
  if (f.to) q.set("to", f.to);
  q.set("page", String(page));
  q.set("page_size", String(f.size));
  q.set("sort", f.sort);
  return q;
}

// --------------------------------------------------------------------- alerts

async function loadAlerts() {
  const seq = ++state.alertsSeq;
  const stateEl = $("alertsState");
  stateEl.classList.remove("error");
  stateEl.textContent = t("loading");
  show(stateEl, true);
  try {
    const data = await api("/alerts?" + alertsQuery(state.filters.page).toString());
    if (seq !== state.alertsSeq) return;
    state.list = data;
    if (data.pages && state.filters.page > data.pages) { state.filters.page = data.pages; return loadAlerts(); }
    renderList();
  } catch (e) {
    if (seq !== state.alertsSeq || !state.token || (e && e.name === "AbortError")) return;
    stateEl.classList.add("error");
    stateEl.innerHTML = `${esc(t("err_load_alerts"))} <button type="button" class="btn btn-sm" id="alertsRetry">${esc(t("btn_retry"))}</button>`;
    $("alertsRetry").addEventListener("click", loadAlerts);
  }
}

function renderList() {
  const data = state.list;
  const chips = $("countChips");
  const rows = $("alertRows");
  if (!data) { chips.innerHTML = ""; rows.innerHTML = ""; return; }

  const counts = data.counts_by_risk || {};
  chips.innerHTML = SEVERITIES.map((lvl) => `
    <button type="button" class="chip" data-risk="${esc(lvl)}" aria-pressed="${esc(state.filters.risk.has(lvl))}">
      ${sevBadge(lvl)}<span class="n">${esc(fmtNum(counts[lvl]))}</span></button>`).join("");

  const items = Array.isArray(data.items) ? data.items : [];
  const stateEl = $("alertsState");
  if (!items.length) {
    stateEl.classList.remove("error");
    stateEl.textContent = t("empty_alerts");
    show(stateEl, true);
  } else {
    show(stateEl, false);
  }
  rows.innerHTML = items.map((a) => {
    const recHtml = a.recommendation_count > 0
      ? `<span class="rec-flag" title="${esc(fmtJst(a.latest_recommendation_at))}">${esc(t("rec_badge", a.recommendation_count))}</span>`
      : '<span class="muted">—</span>';
    return `
    <tr class="clickable" tabindex="0" data-id="${esc(a.alert_id)}">
      <td class="nowrap">${esc(fmtJst(a.received_at))}</td>
      <td>${sevBadge(a.risk_level)}</td>
      <td>${esc(a.detection_name || "—")}</td>
      <td>${esc(a.endpoint_name || "—")}</td>
      <td class="col-summary"><div class="cell-clip">${esc(a.ai_summary_excerpt)}</div></td>
      <td>${recHtml}</td>
    </tr>`;
  }).join("");

  const page = data.page || 1, pages = data.pages || 1;
  $("pageInfo").textContent = t("pager_info", fmtNum(data.total), page, pages);
  $("pagePrev").disabled = page <= 1;
  $("pageNext").disabled = page >= pages;
}

function onRowActivate(ev) {
  if (ev.type === "keydown" && ev.key !== "Enter" && ev.key !== " ") return;
  const tr = ev.target.closest("tr[data-id]");
  if (!tr) return;
  ev.preventDefault();
  location.hash = "#/alerts/" + encodeURIComponent(tr.dataset.id);
}

// --------------------------------------------------------------------- detail

async function ensureCatalog() {
  if (state.catalog) return state.catalog;
  try {
    state.catalog = await api("/export/fields");
  } catch (e) { /* the detail view falls back to raw keys; export reports its own error */ }
  return state.catalog;
}

function fieldLabel(key) {
  const f = state.catalog && Array.isArray(state.catalog.fields) ? state.catalog.fields.find((x) => x.key === key) : null;
  if (!f) return key;
  return (state.lang === "ja" ? f.label_ja : f.label_en) || key;
}

async function openDetail(id) {
  const dlg = $("detailDialog");
  const seq = ++state.detailSeq;
  state.detailId = id;
  state.detail = null;
  state.detailError = "";
  if (!dlg.open) dlg.showModal();
  $("detailBody").textContent = t("loading");
  try {
    const [data] = await Promise.all([api("/alerts/" + encodeURIComponent(id)), ensureCatalog()]);
    if (seq !== state.detailSeq) return;
    state.detail = data;
  } catch (e) {
    if (seq !== state.detailSeq || !state.token) return;
    state.detailError = e.status === 404 || e.status === 400 ? t("err_detail_notfound") : t("err_load_detail");
  }
  renderDetail();
}

function valueHtml(key, v) {
  if (v === null || v === undefined || v === "") return '<span class="muted">—</span>';
  if (key === "risk_level") return sevBadge(String(v));
  return esc(v);
}

function prettyJson(text) {
  try { return JSON.stringify(JSON.parse(text), null, 2); } catch (e) { return String(text); }
}

function renderDetail() {
  const body = $("detailBody");
  if (state.detailError) { body.innerHTML = `<div class="state error">${esc(state.detailError)}</div>`; return; }
  const data = state.detail;
  if (!data) return;
  const alert = data.alert || {};
  const groups = data.groups || {};
  const flat = {};
  Object.keys(alert).forEach((g) => Object.assign(flat, alert[g]));

  const recs = Array.isArray(data.recommendations) ? data.recommendations : [];
  const recsHtml = recs.length
    ? recs.map((r) => `
        <article class="rec">
          <div class="rec-meta">${esc(r.author || "—")} · ${esc(fmtJst(r.created_at))}</div>
          <div class="pre">${esc(r.body)}</div>
        </article>`).join("")
    : `<p class="muted">${esc(t("recs_empty"))}</p>`;

  const groupsHtml = Object.keys(groups).filter((g) => g !== "recommendation" && alert[g]).map((g) => {
    const label = (groups[g] && groups[g][state.lang]) || g;
    const rowsHtml = Object.keys(alert[g]).filter((k) => k !== "raw_alert_json").map((k) =>
      `<dt>${esc(fieldLabel(k))}</dt><dd class="pre">${valueHtml(k, alert[g][k])}</dd>`).join("");
    return rowsHtml ? `<section class="group"><h3>${esc(label)}</h3><dl class="kv">${rowsHtml}</dl></section>` : "";
  }).join("");

  const rawHtml = flat.raw_alert_json
    ? `<details class="raw"><summary>${esc(t("raw_json"))}</summary><pre>${esc(prettyJson(flat.raw_alert_json))}</pre></details>`
    : "";

  body.innerHTML = `
    <div class="detail-head">${sevBadge(flat.risk_level)}
      <h3>${esc(flat.detection_name || state.detailId)}</h3>
      <span class="muted mono">${esc(flat.alert_id || state.detailId)}</span></div>
    <section class="recs" aria-labelledby="recsTitle">
      <h3 id="recsTitle">${esc(t("section_recs"))}</h3>${recsHtml}</section>
    ${groupsHtml}${rawHtml}`;
}

function onDetailClosed() {
  state.detailId = null;
  state.detailSeq++;
  if (!state.keepHash && DETAIL_HASH.test(location.hash)) {
    history.replaceState(null, "", location.pathname + location.search + "#/alerts");
  }
}

// ----------------------------------------------------------------------- tabs

function routeTarget() { return location.hash === "#/reports" ? "reports" : "alerts"; }

function showTab(name, skipHash) {
  state.tab = name;
  for (const tab of document.querySelectorAll(".tab")) {
    const on = tab.dataset.tab === name;
    tab.setAttribute("aria-selected", String(on));
    tab.tabIndex = on ? 0 : -1;
  }
  show($("panelAlerts"), name === "alerts");
  show($("panelReports"), name === "reports");
  if (!skipHash && !DETAIL_HASH.test(location.hash)) {
    history.replaceState(null, "", location.pathname + location.search + (name === "reports" ? "#/reports" : "#/alerts"));
  }
  if (name === "reports") loadReports();
}

function onTabKey(ev) {
  if (ev.key !== "ArrowLeft" && ev.key !== "ArrowRight") return;
  const tabs = [...document.querySelectorAll(".tab")];
  const i = tabs.indexOf(document.activeElement);
  if (i < 0) return;
  const next = tabs[(i + (ev.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
  next.focus();
  showTab(next.dataset.tab);
}

function applyRoute() {
  if (!state.token) return;
  const m = DETAIL_HASH.exec(location.hash);
  const dlg = $("detailDialog");
  if (m) {
    let id;
    try { id = decodeURIComponent(m[1]); } catch (e) { return; }
    if (state.tab !== "alerts") showTab("alerts", true);
    if (!(dlg.open && state.detailId === id)) openDetail(id);
  } else {
    if (dlg.open) dlg.close();
    const want = routeTarget();
    if (want !== state.tab) showTab(want, true);
  }
}

// -------------------------------------------------------------------- reports

async function loadReports() {
  const el = $("reportsState");
  el.classList.remove("error");
  el.textContent = t("loading");
  show(el, true);
  show($("reportsTable"), false);
  state.reportsError = "";
  try {
    const data = await api("/reports");
    state.reports = Array.isArray(data.reports) ? data.reports : [];
  } catch (e) {
    if (!state.token) return;
    // An endpoint that is not deployed yet reads as "nothing to show", not as a failure.
    if (e.status === 404 || e.status === 405 || e.status === 501) state.reports = [];
    else { state.reports = null; state.reportsError = t("err_load_reports"); }
  }
  renderReports();
}

function renderReports() {
  const el = $("reportsState");
  const table = $("reportsTable");
  if (state.reportsError) {
    el.classList.add("error");
    el.innerHTML = `${esc(state.reportsError)} <button type="button" class="btn btn-sm" id="reportsRetry">${esc(t("btn_retry"))}</button>`;
    show(el, true);
    show(table, false);
    $("reportsRetry").addEventListener("click", loadReports);
    return;
  }
  const list = state.reports;
  if (list === null) return;
  if (!list.length) {
    el.classList.remove("error");
    el.textContent = t("empty_reports");
    show(el, true);
    show(table, false);
    return;
  }
  show(el, false);
  show(table, true);
  $("reportRows").innerHTML = list.map((r) => {
    const counts = r.counts || {};
    const chipsHtml = SEVERITIES.filter((l) => Number(counts[l]) > 0)
      .map((l) => `<span class="badge sev-${esc(l)}">${esc(t("sev_" + l))} ${esc(fmtNum(counts[l]))}</span>`).join(" ");
    const generated = typeof r.generated_at === "number" ? fmtJst(r.generated_at) : (r.generated_at || "—");
    const downloadHtml = r.has_file
      ? `<button type="button" class="btn btn-sm" data-period="${esc(r.period_key)}">${esc(t("btn_download"))}</button>`
      : `<span class="muted">${esc(t("report_unavailable"))}</span>`;
    return `
    <tr>
      <td class="nowrap">${esc(fmtDay(r.period_start))} – ${esc(fmtDay(r.last_day || r.period_end))}</td>
      <td class="nowrap">${esc(generated)}</td>
      <td><strong>${esc(t("reports_total", fmtNum(counts.total)))}</strong> ${chipsHtml}</td>
      <td>${downloadHtml}</td>
    </tr>`;
  }).join("");
}

async function onReportDownload(ev) {
  const btn = ev.target.closest("button[data-period]");
  if (!btn) return;
  const label = btn.textContent;
  btn.disabled = true;
  btn.textContent = t("download_busy");
  try {
    const res = await apiFetch("/reports/" + encodeURIComponent(btn.dataset.period) + "/download");
    const blob = await res.blob();
    saveBlob(blob, filenameFrom(res, "soc-lite-weekly-report.xlsx"));
  } catch (e) {
    if (state.token) toast(t("err_download"), true);
  } finally {
    btn.disabled = false;
    btn.textContent = label;
  }
}

// --------------------------------------------------------------------- export

function loadExportPrefs() {
  try {
    const p = JSON.parse(storeGet("local", EXPORT_PREFS_KEY) || "null");
    return p && typeof p === "object" ? p : {};
  } catch (e) { return {}; }
}

function catalogKeys() { return (state.catalog && state.catalog.fields ? state.catalog.fields : []).map((f) => f.key); }

function presetFields(name) {
  const c = state.catalog || {};
  if (name === "all") return catalogKeys();
  if (name === "none") return [];
  const base = (c.weekly_fields && c.weekly_fields.length ? c.weekly_fields : c.default_fields) || [];
  return base.filter((k) => catalogKeys().includes(k));
}

async function openExport() {
  const dlg = $("exportDialog");
  setNotice($("exportStatus"), "");
  show($("exportProgress"), false);
  dlg.showModal();
  $("exportBody").textContent = t("loading");
  $("exportGo").disabled = true;
  const catalog = await ensureCatalog();
  if (!catalog) {
    $("exportBody").innerHTML = `<div class="state error">${esc(t("err_export_failed"))}</div>`;
    return;
  }
  const prefs = loadExportPrefs();
  const valid = new Set(catalogKeys());
  const saved = Array.isArray(prefs.fields) ? prefs.fields.filter((k, i, a) => valid.has(k) && a.indexOf(k) === i) : null;
  state.exp = {
    selected: saved && saved.length ? saved : presetFields("essential"),
    limit: Number(prefs.limit) > 0 ? Number(prefs.limit) : catalog.max_alerts,
    headerLang: prefs.header_lang === "en" || prefs.header_lang === "ja" ? prefs.header_lang : state.lang,
    sort: state.filters.sort,
    info: prefs.include_info_sheet === true,
  };
  buildExport();
  $("exportGo").disabled = false;
}

function captureExportOpts() {
  if (!state.exp || !$("expLimit")) return;
  const n = parseInt($("expLimit").value, 10);
  state.exp.limit = isNaN(n) ? state.exp.limit : n;
  state.exp.headerLang = $("expHeaderLang").value;
  state.exp.sort = $("expSort").value;
  state.exp.info = $("expInfo").checked;
}

function buildExport() {
  if (!state.exp || !state.catalog) return;
  captureExportOpts();
  const c = state.catalog;
  const e = state.exp;
  $("exportScope").textContent = t("export_scope", fmtNum(state.list ? state.list.total : 0));

  const groupKeys = Object.keys(c.groups || {});
  c.fields.forEach((f) => { if (!groupKeys.includes(f.group)) groupKeys.push(f.group); });
  const checklistHtml = groupKeys.map((g) => {
    const fields = c.fields.filter((f) => f.group === g);
    if (!fields.length) return "";
    const title = (c.groups && c.groups[g] && c.groups[g][state.lang]) || g;
    const boxesHtml = fields.map((f) => `
      <label class="check"><input type="checkbox" data-key="${esc(f.key)}"${flag(e.selected.includes(f.key), " checked")}>
        <span>${esc(state.lang === "ja" ? f.label_ja : f.label_en)}</span></label>`).join("");
    return `<div class="fgroup"><div class="fgroup-title">${esc(title)}</div>${boxesHtml}</div>`;
  }).join("");

  const maxAlerts = c.max_alerts;
  $("exportBody").innerHTML = `
    <div class="presets" role="group" aria-label="${esc(t("preset_label"))}">
      <strong>${esc(t("preset_label"))}</strong>
      <button type="button" class="btn btn-sm" data-preset="essential">${esc(t("preset_essential"))}</button>
      <button type="button" class="btn btn-sm" data-preset="all">${esc(t("preset_all"))}</button>
      <button type="button" class="btn btn-sm" data-preset="none">${esc(t("preset_none"))}</button>
    </div>
    <div class="exp-grid">
      <div class="exp-section"><h3>${esc(t("export_fields"))}</h3>${checklistHtml}</div>
      <div class="exp-section"><h3>${esc(t("export_order"))}</h3>
        <p class="muted">${esc(t("export_order_help"))}</p>
        <ol class="order" id="expOrder"></ol></div>
    </div>
    <div class="opts">
      <label class="field" for="expLimit"><span>${esc(t("export_limit", maxAlerts))}</span>
        <input id="expLimit" type="number" min="1" max="${esc(maxAlerts)}" step="1" value="${esc(e.limit)}"></label>
      <label class="field" for="expHeaderLang"><span>${esc(t("export_header_lang"))}</span>
        <select id="expHeaderLang">
          <option value="ja"${flag(e.headerLang === "ja", " selected")}>${esc(t("export_lang_ja"))}</option>
          <option value="en"${flag(e.headerLang === "en", " selected")}>${esc(t("export_lang_en"))}</option>
        </select></label>
      <label class="field" for="expSort"><span>${esc(t("filter_sort"))}</span>
        <select id="expSort">
          <option value="desc"${flag(e.sort === "desc", " selected")}>${esc(t("sort_desc"))}</option>
          <option value="asc"${flag(e.sort === "asc", " selected")}>${esc(t("sort_asc"))}</option>
        </select></label>
    </div>
    <p><label class="check"><input type="checkbox" id="expInfo"${flag(e.info, " checked")}><span>${esc(t("export_info_sheet"))}</span></label></p>`;
  renderOrder();
}

function renderOrder(focus) {
  const list = $("expOrder");
  if (!list) return;
  const sel = state.exp.selected;
  if (!sel.length) { list.innerHTML = `<li class="muted">${esc(t("export_none_selected"))}</li>`; return; }
  list.innerHTML = sel.map((k, i) => `
    <li><span class="lbl">${esc(fieldLabel(k))}</span>
      <button type="button" class="btn btn-sm" data-move="up" data-key="${esc(k)}"${flag(i === 0, " disabled")}
        aria-label="${esc(t("btn_move_up", fieldLabel(k)))}">↑</button>
      <button type="button" class="btn btn-sm" data-move="down" data-key="${esc(k)}"${flag(i === sel.length - 1, " disabled")}
        aria-label="${esc(t("btn_move_down", fieldLabel(k)))}">↓</button></li>`).join("");
  if (focus) {
    const btn = [...list.querySelectorAll("button[data-move]")].find((b) => b.dataset.key === focus.key && b.dataset.move === focus.dir && !b.disabled)
      || [...list.querySelectorAll("button[data-move]")].find((b) => b.dataset.key === focus.key && !b.disabled);
    if (btn) btn.focus();
  }
}

function syncChecks() {
  const sel = new Set(state.exp.selected);
  $("exportBody").querySelectorAll("input[data-key]").forEach((box) => { box.checked = sel.has(box.dataset.key); });
}

function onExportChange(ev) {
  const box = ev.target.closest("input[data-key]");
  if (!box || !state.exp) return;
  const k = box.dataset.key;
  const sel = state.exp.selected;
  if (box.checked && !sel.includes(k)) sel.push(k);
  if (!box.checked) { const i = sel.indexOf(k); if (i >= 0) sel.splice(i, 1); }
  renderOrder();
}

function onExportClick(ev) {
  if (!state.exp) return;
  const preset = ev.target.closest("button[data-preset]");
  if (preset) {
    state.exp.selected = presetFields(preset.dataset.preset);
    syncChecks();
    renderOrder();
    return;
  }
  const mv = ev.target.closest("button[data-move]");
  if (mv) {
    const sel = state.exp.selected;
    const i = sel.indexOf(mv.dataset.key);
    const j = mv.dataset.move === "up" ? i - 1 : i + 1;
    if (i < 0 || j < 0 || j >= sel.length) return;
    [sel[i], sel[j]] = [sel[j], sel[i]];
    renderOrder({ key: mv.dataset.key, dir: mv.dataset.move });
  }
}

function setExportBusy(busy) {
  show($("exportProgress"), busy);
  $("exportGo").disabled = busy;
  $("exportBody").querySelectorAll("input,select,button").forEach((el) => { el.disabled = busy; });
  if (!busy) renderOrder();
}

async function onExportSubmit(ev) {
  ev.preventDefault();
  if (!state.exp || !state.catalog) return;
  captureExportOpts();
  const e = state.exp;
  const status = $("exportStatus");
  status.classList.remove("notice-error", "notice-ok");
  const max = state.catalog.max_alerts;
  if (!e.selected.length) { status.classList.add("notice-error"); setNotice(status, t("err_export_fields")); return; }
  if (!Number.isInteger(e.limit) || e.limit < 1 || e.limit > max) {
    status.classList.add("notice-error");
    setNotice(status, t("err_export_limit", max));
    return;
  }
  const f = state.filters;
  const body = {
    risk: FILTER_SEVERITIES.filter((l) => f.risk.has(l)),
    limit: e.limit, fields: e.selected.slice(), header_lang: e.headerLang, sort: e.sort,
    include_info_sheet: e.info,
  };
  if (f.from) body.from = f.from;
  if (f.to) body.to = f.to;
  storeSet("local", EXPORT_PREFS_KEY, JSON.stringify({
    fields: body.fields, limit: body.limit, header_lang: body.header_lang, include_info_sheet: body.include_info_sheet,
  }));

  status.classList.add("notice");
  setNotice(status, t("export_working"));
  setExportBusy(true);
  const ctl = new AbortController();
  state.exportAbort = ctl;
  try {
    const res = await apiFetch("/alerts/export", { method: "POST", body, signal: ctl.signal });
    const blob = await res.blob();
    saveBlob(blob, filenameFrom(res, "soc-lite-alerts.xlsx"));
    const count = Number(res.headers.get("X-Alert-Count")) || 0;
    status.classList.add("notice-ok");
    setNotice(status, t("export_done", fmtNum(count)));
  } catch (err) {
    if (err && err.name === "AbortError") { setNotice(status, ""); }
    else if (state.token) {
      status.classList.add("notice-error");
      setNotice(status, err.status === 429 ? t("err_export_busy")
        : err.status === 400 && err.detail ? t("err_export_failed") + " " + err.detail
        : err.status === 0 ? t("err_network") : t("err_export_failed"));
    }
  } finally {
    state.exportAbort = null;
    if (state.token) setExportBusy(false);
  }
}

function closeExport() {
  if (state.exportAbort) state.exportAbort.abort();
  $("exportDialog").close();
}

// ----------------------------------------------------------------------- init

function bind() {
  $("langJa").addEventListener("click", () => setLang("ja"));
  $("langEn").addEventListener("click", () => setLang("en"));
  $("themeBtn").addEventListener("click", toggleTheme);
  $("logoutBtn").addEventListener("click", onLogout);
  $("loginForm").addEventListener("submit", onLogin);

  $("sevFilter").addEventListener("change", onSevChange);
  $("countChips").addEventListener("click", onChipClick);
  $("fFrom").addEventListener("change", () => { state.filters.from = $("fFrom").value; filtersChanged(); });
  $("fTo").addEventListener("change", () => { state.filters.to = $("fTo").value; filtersChanged(); });
  $("fSort").addEventListener("change", () => { state.filters.sort = $("fSort").value; filtersChanged(); });
  $("fSize").addEventListener("change", () => { state.filters.size = Number($("fSize").value) || 25; filtersChanged(); });
  $("clearFilters").addEventListener("click", () => {
    Object.assign(state.filters, { risk: new Set(), from: "", to: "", page: 1 });
    renderSevFilter();
    syncFilterInputs();
    loadAlerts();
  });
  $("refreshBtn").addEventListener("click", loadAlerts);
  $("pagePrev").addEventListener("click", () => { state.filters.page = Math.max(1, state.filters.page - 1); loadAlerts(); });
  $("pageNext").addEventListener("click", () => { state.filters.page += 1; loadAlerts(); });
  $("alertRows").addEventListener("click", onRowActivate);
  $("alertRows").addEventListener("keydown", onRowActivate);

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => showTab(tab.dataset.tab));
    tab.addEventListener("keydown", onTabKey);
  });
  $("reportRows").addEventListener("click", onReportDownload);

  $("detailClose").addEventListener("click", () => $("detailDialog").close());
  $("detailDialog").addEventListener("close", onDetailClosed);
  window.addEventListener("hashchange", applyRoute);

  $("exportBtn").addEventListener("click", openExport);
  $("exportClose").addEventListener("click", closeExport);
  $("exportCancel").addEventListener("click", closeExport);
  $("exportDialog").addEventListener("close", () => { if (state.exportAbort) state.exportAbort.abort(); });
  $("exportForm").addEventListener("submit", onExportSubmit);
  $("exportBody").addEventListener("change", onExportChange);
  $("exportBody").addEventListener("click", onExportClick);
}

async function init() {
  state.lang = initialLang();
  applyTheme(storeGet("local", THEME_KEY));
  applyStaticI18n();
  bind();
  const saved = storeGet("session", SESSION_KEY);
  if (!saved) { showLogin(); return; }
  state.token = saved;
  try {
    const me = await api("/auth/me");
    state.user = me.user;
    showApp();
  } catch (e) {
    if (state.token) {           // 401/404-disabled already ended the session with its own notice
      state.token = "";
      storeDel("session", SESSION_KEY);
      showLogin("", e.status === 0 ? t("err_network") : "");
    }
  }
}

init();
