/* ESET SOC Lite — client portal.
 *
 * Standalone page (no engineering JS, no /static/* assets, no WebSocket). It only
 * talks to /client/api/* with the X-Client-Session header. All dynamic text is
 * either put through esc() before it enters markup or assigned via textContent;
 * every ${...} that reaches innerHTML is esc(...), encodeURIComponent(...), a
 * pre-escaped *Html value, or sevBadge(...) (tests/integration/test_client_portal_page.py
 * enforces this).
 *
 * Layout, for a non-technical reader:
 *   Overview      one status sentence for the last OVERVIEW_DAYS days, counts by
 *                 severity, the latest high-priority alerts and the latest report.
 *   All alerts    severity chips + a period picker; dates, order and page size sit
 *                 behind "More options". Alerts are a readable list, not a grid.
 *   Weekly reports one row per week with a plain count and the download.
 * The alert detail leads with what happened and the engineer's advice; every other
 * field stays reachable under "Technical details".
 */
"use strict";

const API = "/client/api";
const SESSION_KEY = "client_session";
const LANG_KEY = "client_lang";
const THEME_KEY = "client_theme";
const EXPORT_PREFS_KEY = "client_export_prefs";
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];   // display order
const FILTER_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
const SERIOUS = ["CRITICAL", "HIGH"];
const OVERVIEW_DAYS = 7;
const PERIODS = ["all", "7", "30", "90", "custom"];
const DETAIL_HASH = /^#\/alerts\/([^/?#]+)$/;
const TAB_HASH = { overview: "#/overview", alerts: "#/alerts", reports: "#/reports" };

// Detail view: the facts a client needs, in this order, with plain-language labels.
// (Device and received time are in the detail header, so they are not repeated here.)
const KEY_FACTS = [
  ["user_name", "fact_user"],
  ["occurred_at_jst", "fact_detected"],
  ["action_taken", "fact_action"],
  ["threat_handled", "fact_handled"],
];
const SUMMARY_KEYS = ["risk_level", "detection_name", "endpoint_name", "received_at_jst",
  "ai_alert_summary_ja", "ai_risk_reason_ja"];
const AI_MORE_KEYS = ["ai_client_notification_ja", "ai_recommended_actions_ja", "ai_confirmation_items_ja"];
const BOOL_KEYS = ["threat_handled", "isolation_status"];

const state = {
  lang: "ja",
  token: "",
  user: null,
  tab: "",
  filters: { risk: new Set(), period: "all", from: "", to: "", sort: "desc", size: 25, page: 1 },
  list: null,            // last /alerts response
  alertsSeq: 0,
  overview: null,        // /alerts response for the overview window (HIGH/CRITICAL items)
  overviewError: "",
  overviewSeq: 0,
  catalog: null,         // /export/fields response
  detailId: null,
  detailSeq: 0,
  detail: null,          // last /alerts/{id} response
  detailError: "",
  reports: null,
  reportsError: "",
  reportsSeq: 0,
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
function jstFormatter(withTime) {
  const key = uiLocale() + (withTime ? ":t" : ":d");
  if (!_fmtCache[key]) {
    const opts = { timeZone: "Asia/Tokyo", year: "numeric", month: state.lang === "ja" ? "long" : "short", day: "numeric" };
    if (withTime) Object.assign(opts, { hour: "2-digit", minute: "2-digit", hour12: false });
    _fmtCache[key] = new Intl.DateTimeFormat(uiLocale(), opts);
  }
  return _fmtCache[key];
}
/** Epoch seconds -> "2026年11月5日 14:03" / "5 Nov 2026, 14:03" (Japan time; the page says so once). */
function fmtWhen(epoch) {
  if (typeof epoch !== "number" || !isFinite(epoch)) return "—";
  return jstFormatter(true).format(new Date(epoch * 1000));
}
/** "2026-11-05" (a JST calendar day) -> "2026年11月5日" / "5 Nov 2026". */
function fmtDay(v) {
  if (typeof v !== "string" || !/^\d{4}-\d{2}-\d{2}/.test(v)) return "—";
  // Noon JST on that day, so the formatter's Asia/Tokyo zone lands on the same date.
  return jstFormatter(false).format(new Date(v.slice(0, 10) + "T12:00:00+09:00"));
}
function fmtNum(n) { return Number(n || 0).toLocaleString(uiLocale()); }

const _isoDay = new Intl.DateTimeFormat("en-CA", { timeZone: "Asia/Tokyo", year: "numeric", month: "2-digit", day: "2-digit" });
/** The JST calendar date `n` days before today, as YYYY-MM-DD. */
function jstDaysAgo(n) { return _isoDay.format(new Date(Date.now() - n * 86400000)); }

function isSeverity(level) { return SEVERITIES.includes(level); }
function sevClass(level) { return isSeverity(level) ? level : "UNKNOWN"; }
function sevBadge(level) {
  const known = isSeverity(level);
  const label = known ? t("sev_" + level) : (level || "—");
  return `<span class="badge sev-${esc(sevClass(level))}">${esc(label)}</span>`;
}
function sumCounts(counts, levels) {
  return (levels || SEVERITIES).reduce((s, l) => s + Number((counts || {})[l] || 0), 0);
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

/** A "Try again" line for a failed load; the button gets `onRetry`. */
function renderRetry(el, message, onRetry) {
  el.classList.add("error");
  el.innerHTML = `${esc(message)} <button type="button" class="btn btn-sm">${esc(t("btn_retry"))}</button>`;
  el.querySelector("button").addEventListener("click", onRetry);
  show(el, true);
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
  renderOverview();
  renderList();
  renderReports();
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
  state.tab = "";
  state.list = null;
  state.overview = null;
  state.overviewError = "";
  state.detail = null;
  state.reports = null;
  state.reportsError = "";
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

// ------------------------------------------------------------------- overview

async function loadOverview() {
  const seq = ++state.overviewSeq;
  state.overviewError = "";
  if (!state.overview) renderOverview();
  const q = new URLSearchParams({
    from: jstDaysAgo(OVERVIEW_DAYS - 1), risk: SERIOUS.join(","), page: "1", page_size: "5", sort: "desc",
  });
  if (state.reports === null) loadReports();
  try {
    const data = await api("/alerts?" + q.toString());
    if (seq !== state.overviewSeq) return;
    state.overview = data;
  } catch (e) {
    if (seq !== state.overviewSeq || !state.token || (e && e.name === "AbortError")) return;
    state.overview = null;
    state.overviewError = t("err_load_overview");
  }
  renderOverview();
}

function renderOverview() {
  const card = $("ovStatus");
  const headline = $("ovHeadline");
  const sub = $("ovSub");
  const action = $("ovAction");
  const data = state.overview;
  $("ovGlance").textContent = t("ov_glance_title", OVERVIEW_DAYS);
  renderOverviewReport();

  if (state.overviewError || !data) {
    card.dataset.tone = state.overviewError ? "error" : "loading";
    headline.textContent = state.overviewError || t("loading");
    sub.textContent = "";
    show(action, !!state.overviewError);
    action.textContent = t("btn_retry");
    action.dataset.go = "retry";
    $("ovTiles").innerHTML = "";
    $("ovList").innerHTML = "";
    show($("ovListState"), false);
    return;
  }

  const counts = data.counts_by_risk || {};
  const serious = sumCounts(counts, SERIOUS);
  const total = sumCounts(counts);
  if (serious > 0) {
    card.dataset.tone = "attention";
    headline.textContent = t("ov_attention", fmtNum(serious), OVERVIEW_DAYS);
    sub.textContent = t("ov_attention_sub");
    action.textContent = t("ov_review");
    action.dataset.go = "serious";
  } else if (total > 0) {
    card.dataset.tone = "ok";
    headline.textContent = t("ov_ok", OVERVIEW_DAYS);
    sub.textContent = t("ov_ok_sub", fmtNum(total));
    action.textContent = t("ov_view_alerts");
    action.dataset.go = "all";
  } else {
    card.dataset.tone = "clear";
    headline.textContent = t("ov_clear", OVERVIEW_DAYS);
    sub.textContent = t("ov_clear_sub");
    action.dataset.go = "";
  }
  show(action, !!action.dataset.go);

  $("ovTiles").innerHTML = SEVERITIES.map((lvl) => `
    <button type="button" class="tile tile-${esc(lvl)}" data-risk="${esc(lvl)}"
      aria-label="${esc(t("tile_aria", t("sev_" + lvl), fmtNum(counts[lvl])))}">
      <span class="tile-n">${esc(fmtNum(counts[lvl]))}</span>
      <span class="tile-label">${sevBadge(lvl)}</span>
    </button>`).join("");

  const items = Array.isArray(data.items) ? data.items : [];
  const stateEl = $("ovListState");
  stateEl.classList.remove("error");
  stateEl.textContent = t("ov_list_empty", OVERVIEW_DAYS);
  show(stateEl, !items.length);
  $("ovList").innerHTML = items.map((a) => alertItemHtml(a)).join("");
}

function renderOverviewReport() {
  const box = $("ovReport");
  if (state.reportsError) { box.innerHTML = `<p class="muted">${esc(state.reportsError)}</p>`; return; }
  if (state.reports === null) { box.innerHTML = `<p class="muted">${esc(t("loading"))}</p>`; return; }
  const r = state.reports[0];
  if (!r) { box.innerHTML = `<p class="muted">${esc(t("empty_reports"))}</p>`; return; }
  const downloadHtml = reportDownloadHtml(r);
  box.innerHTML = `
    <p class="report-period">${esc(reportPeriod(r))}</p>
    <p class="muted">${esc(reportCountText(r))}</p>
    ${downloadHtml}`;
}

function onOverviewAction() {
  const go = $("ovAction").dataset.go;
  if (go === "retry") loadOverview();
  else if (go === "serious") goToAlerts(SERIOUS, String(OVERVIEW_DAYS));
  else if (go === "all") goToAlerts([], String(OVERVIEW_DAYS));
}

function onTileClick(ev) {
  const tile = ev.target.closest("button[data-risk]");
  if (tile) goToAlerts([tile.dataset.risk], String(OVERVIEW_DAYS));
}

/** Switch to All alerts with the given severities and period. */
function goToAlerts(risks, period) {
  state.filters.risk = new Set(risks);
  setPeriod(period);
  state.filters.page = 1;
  syncFilterInputs();
  showTab("alerts");
  loadAlerts();
  window.scrollTo(0, 0);
}

// -------------------------------------------------------------------- filters

function setPeriod(period) {
  const f = state.filters;
  f.period = PERIODS.includes(period) ? period : "all";
  if (f.period === "all") { f.from = ""; f.to = ""; }
  else if (f.period !== "custom") { f.from = jstDaysAgo(Number(f.period) - 1); f.to = ""; }
}

function syncFilterInputs() {
  const f = state.filters;
  $("fPeriod").value = f.period;
  show($("customDates"), f.period === "custom");
  $("fFrom").value = f.from;
  $("fTo").value = f.to;
  $("fSort").value = f.sort;
  $("fSize").value = String(f.size);
}

function filtersChanged() { state.filters.page = 1; loadAlerts(); }

function resetFilters() {
  Object.assign(state.filters, { risk: new Set(), period: "all", from: "", to: "", page: 1 });
  syncFilterInputs();
  loadAlerts();
}

function onChipClick(ev) {
  const chip = ev.target.closest("button[data-risk]");
  if (!chip) return;
  const lvl = chip.dataset.risk;
  if (!lvl) state.filters.risk.clear();
  else if (state.filters.risk.has(lvl)) state.filters.risk.delete(lvl);
  else state.filters.risk.add(lvl);
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

/** The active filters in words, or "" when nothing is filtered. */
function filterWords() {
  const f = state.filters;
  const parts = [];
  if (f.risk.size) parts.push(SEVERITIES.filter((l) => f.risk.has(l)).map((l) => t("sev_" + l)).join(t("list_sep")));
  if (f.period === "custom" && (f.from || f.to)) parts.push(t("range", f.from ? fmtDay(f.from) : "…", f.to ? fmtDay(f.to) : "…"));
  else if (f.period !== "all" && f.period !== "custom") parts.push(t("period_" + f.period));
  return parts.join(" · ");
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
    renderRetry(stateEl, t("err_load_alerts"), loadAlerts);
  }
}

/** One alert as a list row: severity, name, device and time, engineer advice. */
function alertItemHtml(a) {
  const title = a.detection_name || t("alert_untitled");
  const deviceHtml = a.endpoint_name ? `<span>${esc(t("on_device", a.endpoint_name))}</span>` : "";
  const summaryHtml = a.ai_summary_excerpt ? `<span class="ai-summary">${esc(a.ai_summary_excerpt)}</span>` : "";
  const recHtml = a.recommendation_count > 0
    ? `<span class="rec-flag" title="${esc(fmtWhen(a.latest_recommendation_at))}">${esc(t("rec_badge", a.recommendation_count))}</span>`
    : "";
  return `
    <li><a class="alert-item edge-${esc(sevClass(a.risk_level))}" href="#/alerts/${encodeURIComponent(a.alert_id)}">
      <span class="ai-sev">${sevBadge(a.risk_level)}</span>
      <span class="ai-main">
        <span class="ai-title">${esc(title)}</span>
        <span class="ai-meta"><span>${esc(fmtWhen(a.received_at))}</span>${deviceHtml}</span>
        ${summaryHtml}${recHtml}
      </span>
      <span class="chev" aria-hidden="true">›</span>
    </a></li>`;
}

function renderChips() {
  const data = state.list;
  const counts = data ? data.counts_by_risk || {} : {};
  const r = state.filters.risk;
  const allHtml = `<button type="button" class="chip" data-risk="" aria-pressed="${esc(r.size === 0)}">
      <span>${esc(t("chip_all"))}</span><span class="n">${esc(data ? fmtNum(sumCounts(counts)) : "")}</span></button>`;
  const sevHtml = SEVERITIES.map((lvl) => `
    <button type="button" class="chip chip-${esc(lvl)}" data-risk="${esc(lvl)}" aria-pressed="${esc(r.has(lvl))}">
      <span class="dot" aria-hidden="true"></span><span>${esc(t("sev_" + lvl))}</span><span class="n">${esc(data ? fmtNum(counts[lvl]) : "")}</span></button>`).join("");
  $("countChips").innerHTML = allHtml + sevHtml;
}

function renderList() {
  renderChips();
  const data = state.list;
  const rows = $("alertRows");
  const summary = $("filterSummary");
  if (!data) { rows.innerHTML = ""; summary.textContent = ""; return; }

  const words = filterWords();
  if (words) {
    summary.innerHTML = `${esc(t("summary_filtered", fmtNum(data.total), words))}
      <button type="button" class="btn btn-link btn-inline" id="summaryReset">${esc(t("btn_clear_filters"))}</button>`;
    $("summaryReset").addEventListener("click", resetFilters);
  } else {
    summary.textContent = t("summary_all", fmtNum(data.total));
  }

  const items = Array.isArray(data.items) ? data.items : [];
  const stateEl = $("alertsState");
  stateEl.classList.remove("error");
  if (!items.length) {
    stateEl.textContent = words ? t("empty_alerts") : t("empty_alerts_none");
    show(stateEl, true);
  } else {
    show(stateEl, false);
  }
  rows.innerHTML = items.map((a) => alertItemHtml(a)).join("");

  const page = data.page || 1, pages = data.pages || 1;
  $("pageInfo").textContent = t("pager_info", fmtNum(data.total), page, pages);
  $("pagePrev").disabled = page <= 1;
  $("pageNext").disabled = page >= pages;
  show(document.querySelector(".pager"), pages > 1);
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

function isBlank(v) { return v === null || v === undefined || v === ""; }

/** The server's "2026-09-22 15:56:10" (already JST) in the page's date style; anything else as sent. */
function fmtJstText(s) {
  const m = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})(:\d{2})?$/.exec(String(s));
  if (!m) return String(s);
  const d = new Date(m[1] + "T" + m[2] + ":00+09:00");
  return isNaN(d.getTime()) ? String(s) : fmtWhen(d.getTime() / 1000);
}

function valueHtml(key, v) {
  if (isBlank(v)) return '<span class="muted">—</span>';
  if (key === "risk_level") return sevBadge(String(v));
  if (/_jst$/.test(key)) return esc(fmtJstText(v));
  if (BOOL_KEYS.includes(key) && (v === true || v === false || v === "true" || v === "false")) {
    return esc(t(v === true || v === "true" ? "val_yes" : "val_no"));
  }
  return esc(v);
}

function prettyJson(text) {
  try { return JSON.stringify(JSON.parse(text), null, 2); } catch (e) { return String(text); }
}

/** <dl> rows for `keys` that have a value; `labelFor(key)` names each row. */
function kvRowsHtml(source, keys, labelFor) {
  return keys.filter((k) => !isBlank(source[k])).map((k) =>
    `<dt>${esc(labelFor(k))}</dt><dd class="pre">${valueHtml(k, source[k])}</dd>`).join("");
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
  const level = flat.risk_level;

  // 1. What happened (the automatic analysis, written for the client).
  const story = flat.ai_alert_summary_ja || flat.ai_client_notification_ja || "";
  const storyHtml = story
    ? `<p class="pre story">${esc(story)}</p><p class="muted small">${esc(t("ai_note"))}</p>`
    : `<p class="muted">${esc(t("story_empty"))}</p>`;
  const reasonHtml = flat.ai_risk_reason_ja
    ? `<h4>${esc(t("section_reason"))}</h4><p class="pre">${esc(flat.ai_risk_reason_ja)}</p>`
    : "";

  // 2. The engineer's advice: the one thing a client may need to act on.
  const recs = Array.isArray(data.recommendations) ? data.recommendations : [];
  const recsHtml = recs.length
    ? recs.map((r) => `
        <article class="rec">
          <div class="pre">${esc(r.body)}</div>
          <div class="rec-meta">${esc(r.author || "—")} · ${esc(fmtWhen(r.created_at))}</div>
        </article>`).join("")
    : `<p class="muted">${esc(t("recs_empty"))}</p>`;

  // 3. Key facts, plain labels, only those present.
  const factLabel = Object.fromEntries(KEY_FACTS);
  const factsHtml = kvRowsHtml(flat, KEY_FACTS.map((f) => f[0]), (k) => t(factLabel[k]));

  // 4. More of the automatic analysis (collapsed).
  const aiMoreHtml = kvRowsHtml(flat, AI_MORE_KEYS.filter((k) => !(k === "ai_client_notification_ja" && story === flat[k])), fieldLabel);

  // 5. Everything else, grouped as the server groups it (collapsed).
  const shown = new Set([...SUMMARY_KEYS, ...AI_MORE_KEYS, ...KEY_FACTS.map((f) => f[0]), "raw_alert_json"]);
  const groupsHtml = Object.keys(groups).filter((g) => g !== "recommendation" && alert[g]).map((g) => {
    const label = (groups[g] && groups[g][state.lang]) || g;
    const rowsHtml = kvRowsHtml(alert[g], Object.keys(alert[g]).filter((k) => !shown.has(k)), fieldLabel);
    return rowsHtml ? `<section class="group"><h4>${esc(label)}</h4><dl class="kv">${rowsHtml}</dl></section>` : "";
  }).join("");
  const rawHtml = flat.raw_alert_json
    ? `<details class="raw"><summary>${esc(t("raw_json"))}</summary><pre>${esc(prettyJson(flat.raw_alert_json))}</pre></details>`
    : "";

  const metaHtml = [
    flat.endpoint_name ? `<span>${esc(t("on_device", flat.endpoint_name))}</span>` : "",
    flat.received_at_jst ? `<span>${esc(t("received_on", fmtJstText(flat.received_at_jst)))}</span>` : "",
  ].join("");
  const factsSectionHtml = factsHtml
    ? `<section class="d-section"><h3>${esc(t("section_facts"))}</h3><dl class="kv">${factsHtml}</dl></section>` : "";
  const aiMoreSectionHtml = aiMoreHtml
    ? `<details class="disclose"><summary>${esc(t("section_ai_more"))}</summary>
        <div class="disclose-body"><dl class="kv">${aiMoreHtml}</dl></div></details>` : "";

  body.innerHTML = `
    <div class="detail-hero edge-${esc(sevClass(level))}">
      ${sevBadge(level)}
      <h3 class="detail-name">${esc(flat.detection_name || t("alert_untitled"))}</h3>
      <p class="detail-meta muted">${metaHtml}</p>
    </div>
    <section class="d-section">
      <h3>${esc(t("section_story"))}</h3>${storyHtml}${reasonHtml}
    </section>
    <section class="recs${flag(recs.length, " has-recs")}" aria-labelledby="recsTitle">
      <h3 id="recsTitle">${esc(t("section_recs"))}</h3>${recsHtml}</section>
    ${factsSectionHtml}
    ${aiMoreSectionHtml}
    <details class="disclose"><summary>${esc(t("section_technical"))}</summary>
      <div class="disclose-body">${groupsHtml}${rawHtml}</div></details>`;
}

function onDetailClosed() {
  state.detailId = null;
  state.detailSeq++;
  if (!state.keepHash && DETAIL_HASH.test(location.hash)) {
    history.replaceState(null, "", location.pathname + location.search + (TAB_HASH[state.tab] || TAB_HASH.overview));
  }
}

// ----------------------------------------------------------------------- tabs

function routeTarget() {
  if (location.hash === TAB_HASH.reports) return "reports";
  if (location.hash === TAB_HASH.alerts) return "alerts";
  return "overview";
}

function showTab(name, skipHash) {
  state.tab = name;
  for (const tab of document.querySelectorAll(".tab")) {
    const on = tab.dataset.tab === name;
    tab.setAttribute("aria-selected", String(on));
    tab.tabIndex = on ? 0 : -1;
  }
  show($("panelOverview"), name === "overview");
  show($("panelAlerts"), name === "alerts");
  show($("panelReports"), name === "reports");
  if (!skipHash && !DETAIL_HASH.test(location.hash)) {
    history.replaceState(null, "", location.pathname + location.search + TAB_HASH[name]);
  }
  if (name === "overview") loadOverview();
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
    if (!state.tab) showTab("alerts", true);           // a deep link: show the list behind the detail
    if (!(dlg.open && state.detailId === id)) openDetail(id);
  } else {
    if (dlg.open) dlg.close();
    const want = routeTarget();
    if (want !== state.tab) showTab(want, true);
  }
}

// -------------------------------------------------------------------- reports

async function loadReports() {
  const seq = ++state.reportsSeq;
  const el = $("reportsState");
  if (state.reports === null) {
    el.classList.remove("error");
    el.textContent = t("loading");
    show(el, true);
  }
  state.reportsError = "";
  try {
    const data = await api("/reports");
    if (seq !== state.reportsSeq) return;
    state.reports = Array.isArray(data.reports) ? data.reports : [];
  } catch (e) {
    if (seq !== state.reportsSeq || !state.token) return;
    // An endpoint that is not deployed yet reads as "nothing to show", not as a failure.
    if (e.status === 404 || e.status === 405 || e.status === 501) state.reports = [];
    else { state.reports = null; state.reportsError = t("err_load_reports"); }
  }
  renderReports();
  renderOverviewReport();
}

function reportPeriod(r) { return t("range", fmtDay(r.period_start), fmtDay(r.last_day || r.period_end)); }

function reportCountText(r) {
  const total = Number((r.counts || {}).total) || 0;
  return total ? t("reports_total", fmtNum(total)) : t("report_no_alerts");
}

function reportDownloadHtml(r) {
  if (r.has_file) return `<button type="button" class="btn" data-period="${esc(r.period_key)}">${esc(t("btn_download"))}</button>`;
  // No workbook: a week with no alerts says so already; a week with only High/Critical needs the reason.
  const onlySerious = Number((r.counts || {}).total) > 0;
  return `<span class="muted small">${esc(t(onlySerious ? "report_unavailable_serious" : "report_unavailable"))}</span>`;
}

function renderReports() {
  const el = $("reportsState");
  const rows = $("reportRows");
  if (state.reportsError) {
    rows.innerHTML = "";
    renderRetry(el, state.reportsError, loadReports);
    return;
  }
  const list = state.reports;
  if (list === null) return;
  el.classList.remove("error");
  if (!list.length) {
    el.textContent = t("empty_reports");
    show(el, true);
    rows.innerHTML = "";
    return;
  }
  show(el, false);
  rows.innerHTML = list.map((r) => {
    const counts = r.counts || {};
    const chipsHtml = SEVERITIES.filter((l) => Number(counts[l]) > 0)
      .map((l) => `<span class="badge sev-${esc(l)}">${esc(t("sev_" + l))} ${esc(fmtNum(counts[l]))}</span>`).join(" ");
    const downloadHtml = reportDownloadHtml(r);
    const preparedHtml = typeof r.generated_at === "number"
      ? `<p class="muted small">${esc(t("report_prepared", fmtWhen(r.generated_at)))}</p>` : "";
    return `
    <li class="card report-item">
      <div class="report-main">
        <h2 class="report-period">${esc(reportPeriod(r))}</h2>
        <p class="report-counts"><strong>${esc(reportCountText(r))}</strong> ${chipsHtml}</p>
        ${preparedHtml}
      </div>
      <div class="report-action">${downloadHtml}</div>
    </li>`;
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
  const colsOpen = $("expCols") ? $("expCols").open : false;
  const optsOpen = $("expOpts") ? $("expOpts").open : false;
  const words = filterWords();
  $("exportScope").textContent = words
    ? t("export_scope_filtered", fmtNum(state.list ? state.list.total : 0), words)
    : t("export_scope", fmtNum(state.list ? state.list.total : 0));

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
    <p class="export-cols"><span id="expColCount"></span></p>
    <details class="disclose" id="expCols"${flag(colsOpen, " open")}>
      <summary>${esc(t("export_customize"))}</summary>
      <div class="disclose-body">
        <div class="presets" role="group" aria-label="${esc(t("preset_label"))}">
          <span class="muted">${esc(t("preset_label"))}</span>
          <button type="button" class="btn btn-sm" data-preset="essential">${esc(t("preset_essential"))}</button>
          <button type="button" class="btn btn-sm" data-preset="all">${esc(t("preset_all"))}</button>
          <button type="button" class="btn btn-sm" data-preset="none">${esc(t("preset_none"))}</button>
        </div>
        <div class="exp-grid">
          <div class="exp-section"><h3>${esc(t("export_fields"))}</h3>${checklistHtml}</div>
          <div class="exp-section"><h3>${esc(t("export_order"))}</h3>
            <p class="muted small">${esc(t("export_order_help"))}</p>
            <ol class="order" id="expOrder"></ol></div>
        </div>
      </div>
    </details>
    <details class="disclose" id="expOpts"${flag(optsOpen, " open")}>
      <summary>${esc(t("more_options"))}</summary>
      <div class="disclose-body">
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
        <p><label class="check"><input type="checkbox" id="expInfo"${flag(e.info, " checked")}><span>${esc(t("export_info_sheet"))}</span></label></p>
      </div>
    </details>`;
  renderOrder();
}

function renderOrder(focus) {
  const count = $("expColCount");
  if (count) count.textContent = t("export_cols_count", state.exp.selected.length);
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
  if (!e.selected.length) {
    status.classList.add("notice-error");
    $("expCols").open = true;
    setNotice(status, t("err_export_fields"));
    return;
  }
  if (!Number.isInteger(e.limit) || e.limit < 1 || e.limit > max) {
    status.classList.add("notice-error");
    $("expOpts").open = true;
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

  $("ovAction").addEventListener("click", onOverviewAction);
  $("ovTiles").addEventListener("click", onTileClick);
  $("ovAllAlerts").addEventListener("click", () => goToAlerts([], "all"));
  $("ovAllReports").addEventListener("click", () => { showTab("reports"); window.scrollTo(0, 0); });
  $("ovReport").addEventListener("click", onReportDownload);

  $("countChips").addEventListener("click", onChipClick);
  $("fPeriod").addEventListener("change", () => {
    setPeriod($("fPeriod").value);
    syncFilterInputs();
    filtersChanged();
  });
  $("fFrom").addEventListener("change", () => { state.filters.from = $("fFrom").value; filtersChanged(); });
  $("fTo").addEventListener("change", () => { state.filters.to = $("fTo").value; filtersChanged(); });
  $("fSort").addEventListener("change", () => { state.filters.sort = $("fSort").value; filtersChanged(); });
  $("fSize").addEventListener("change", () => { state.filters.size = Number($("fSize").value) || 25; filtersChanged(); });
  $("clearFilters").addEventListener("click", resetFilters);
  $("refreshBtn").addEventListener("click", loadAlerts);
  $("pagePrev").addEventListener("click", () => { state.filters.page = Math.max(1, state.filters.page - 1); loadAlerts(); });
  $("pageNext").addEventListener("click", () => { state.filters.page += 1; loadAlerts(); });

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
