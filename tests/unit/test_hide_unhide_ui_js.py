"""
Hide / Unhide in the engineering dashboard (static/dashboard.js), run with Node.js
on the real functions against an in-memory stand-in for the hidden-alerts API
(src/api/hidden_alerts.py) and the jobs list it filters. Skipped without Node.js.

Covered: hide -> the alert leaves the Alerts list and its count; the Hidden alerts
panel lists it (escaped); unhide (row button and toast Undo) -> it comes back;
a failed request is shown inline and leaves everything as it was.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js not installed")

DASHBOARD = (ROOT / "static/dashboard.js").read_text(encoding="utf-8")

FUNCTIONS = [
    "esc", "knownValue", "uiLocale", "fmtDateTime", "fmtCount", "upsertJob", "jobFromRow",
    "loadRiskLevels", "loadJobs", "loadHidden", "renderHiddenControls", "toggleAlertSelected",
    "hideErrorText", "refreshAfterVisibilityChange", "hideAlerts", "unhideAlerts", "toast",
    "toastHidden", "hideFormHtml", "wireHideForm", "alertActionsHtml", "hiddenRowHtml",
]
CONSTANTS = ["ESC_MAP", "DASH", "HIDE_REASON_MAX", "hiddenPanelSel"]


def _function(name: str) -> str:
    """Source of a top-level `[async] function name(...) {...}` (ends at the first line that is just '}')."""
    m = re.search(rf"^(?:async )?function {name}\(.*?^\}}$", DASHBOARD, re.MULTILINE | re.DOTALL)
    assert m, f"{name} not found in static/dashboard.js"
    return m.group(0)


def _constant(name: str) -> str:
    m = re.search(rf"^const {name} = .*?;(?=\s*(?://.*)?$)", DASHBOARD, re.MULTILINE)
    assert m, f"const {name} not found in static/dashboard.js"
    return m.group(0)


HARNESS = r"""
const fs = require("fs"), vm = require("vm");

// Minimal DOM: elements by id, with the few properties the code touches.
function el(id) {
  const classes = new Set();
  return {
    id, textContent: "", value: "", disabled: false, checked: false, style: {}, children: [],
    className: "", onclick: null, onkeydown: null,
    classList: { add: (c) => classes.add(c), remove: (c) => classes.delete(c), contains: (c) => classes.has(c) },
    appendChild(child) { this.children.push(child); },
    focus() {},
    querySelector(sel) { return elements[sel.replace(/^#/, "")] || null; },
  };
}
const elements = {};
for (const id of ["toast", "alertsHidden", "alertsHideSelected", "alertsSelectAll",
                  "hideConfirm", "hideCancel", "hideReason", "hideErr"]) elements[id] = el(id);

const ctx = vm.createContext({
  localStorage: { getItem: () => null, setItem() {} },
  navigator: { language: "en" }, window: { addEventListener() {} },
  setTimeout: () => 0, clearTimeout() {}, console,
  document: {
    documentElement: {}, addEventListener() {},
    getElementById: (id) => elements[id] || null,
    querySelectorAll: () => [],
    createElement: () => el("created"),
  },
});
vm.runInContext(fs.readFileSync("static/i18n.js", "utf8"), ctx);
vm.runInContext('state_lang.current = "en"', ctx);

// In-memory server: jobs a, b, c; GET /jobs and /alerts leave hidden ones out.
const server = { hidden: new Map(), calls: [], fail: null };
const JOBS = ["a", "b", "c"].map((id, i) => ({
  correlation_id: id, source: "WEBHOOK", status: "SUCCESS", created_at: 1000 + i, updated_at: 1000 + i,
  raw_payload: { detection_name: "Det-" + id, endpoint_name: "PC-" + id },
}));
ctx.api = async (path, opts = {}) => {
  server.calls.push([opts.method || "GET", path, opts.body ? JSON.parse(opts.body) : null]);
  if (server.fail) { const f = server.fail; server.fail = null; throw f(); }
  const visible = (rows) => rows.filter((r) => !server.hidden.has(r.correlation_id));
  if (path === "/jobs?limit=500") return { jobs: visible(JOBS) };
  if (path === "/alerts") return { alerts: visible(JOBS).map((j) => ({ correlation_id: j.correlation_id, risk_level: "LOW" })) };
  if (path === "/alerts/hidden") return { hidden: [...server.hidden.values()], count: server.hidden.size };
  const body = JSON.parse(opts.body);
  if (path === "/alerts/hide") {
    for (const id of body.correlation_ids) {
      const job = JOBS.find((j) => j.correlation_id === id);
      server.hidden.set(id, { correlation_id: id, hidden_at: 1767225600, hidden_by: "dashboard", reason: body.reason,
                              detection_name: job.raw_payload.detection_name, endpoint_name: job.raw_payload.endpoint_name });
    }
    return { hidden: body.correlation_ids.length };
  }
  if (path === "/alerts/unhide") { for (const id of body.correlation_ids) server.hidden.delete(id); return { unhidden: 1 }; }
  throw new Error("unexpected " + path);
};
const counters = { renderAlerts: 0, loadStats: 0, closeModal: 0 };
ctx.renderAlerts = () => { counters.renderAlerts++; };
ctx.loadStats = () => { counters.loadStats++; };
ctx.closeModal = () => { counters.closeModal++; };
ctx.state = { jobs: new Map(), hidden: new Map(), selected: new Set(), recCounts: new Map() };
"""


def _run(body: str) -> dict:
    code = "\n".join([_constant(c) for c in CONSTANTS] + [_function(f) for f in FUNCTIONS])
    script = HARNESS + f"vm.runInContext({json.dumps(code)}, ctx);\n" + (
        "const ids = () => [...ctx.state.jobs.keys()].sort();\n"
        "const lastCall = () => server.calls[server.calls.length - 1];\n"
        "(async () => {\n" + body + "\n})().catch((e) => { console.error(e); process.exit(1); });"
    )
    out = subprocess.run([NODE, "-e", script], capture_output=True, text=True, encoding="utf-8",
                         cwd=ROOT, timeout=60)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def test_hide_removes_the_alert_and_the_hidden_panel_lists_it_then_unhide_brings_it_back():
    out = _run(r"""
await ctx.loadJobs(); await ctx.loadHidden();
const before = { ids: ids(), button: elements.alertsHidden.textContent };

await ctx.hideAlerts(["b"], "ESET notification-rule test send");
const hideCall = server.calls.find((c) => c[1] === "/alerts/hide");
const afterHide = {
  ids: ids(), button: elements.alertsHidden.textContent, hidden: [...ctx.state.hidden.keys()],
  row: ctx.hiddenRowHtml(ctx.state.hidden.get("b")),
  detail: ctx.alertActionsHtml("b"), detailVisible: ctx.alertActionsHtml("a"),
};

await ctx.unhideAlerts(["b"]);
process.stdout.write(JSON.stringify({ before, hideCall, afterHide,
  afterUnhide: { ids: ids(), button: elements.alertsHidden.textContent, hidden: ctx.state.hidden.size,
                 unhideCall: lastCall()[0] === "GET" ? server.calls.find((c) => c[1] === "/alerts/unhide") : lastCall() },
  counters }));
""")
    assert out["before"] == {"ids": ["a", "b", "c"], "button": "Hidden alerts (0)"}
    assert out["hideCall"] == ["POST", "/alerts/hide",
                               {"correlation_ids": ["b"], "reason": "ESET notification-rule test send"}]
    hide = out["afterHide"]
    assert hide["ids"] == ["a", "c"]                       # gone from the Alerts list ...
    assert hide["button"] == "Hidden alerts (1)"           # ... and counted as hidden
    assert hide["hidden"] == ["b"]
    for text in ("Det-b", "PC-b", "ESET notification-rule test send", "dashboard", 'data-hidden-unhide="b"'):
        assert text in hide["row"]
    assert 'id="alertUnhide"' in hide["detail"] and 'id="alertHide"' not in hide["detail"]
    assert 'id="alertHide"' in hide["detailVisible"]

    back = out["afterUnhide"]
    assert back["ids"] == ["a", "b", "c"] and back["button"] == "Hidden alerts (0)" and back["hidden"] == 0
    assert back["unhideCall"] == ["POST", "/alerts/unhide", {"correlation_ids": ["b"]}]
    # The list and the Overview stats were refreshed after each change.
    assert out["counters"]["renderAlerts"] >= 2 and out["counters"]["loadStats"] >= 2


def test_bulk_selection_and_hide_selected():
    out = _run(r"""
await ctx.loadJobs(); await ctx.loadHidden();
ctx.toggleAlertSelected("a", true); ctx.toggleAlertSelected("c", true);
const label = elements.alertsHideSelected.textContent, shown = elements.alertsHideSelected.style.display;
await ctx.hideAlerts([...ctx.state.selected], "");
process.stdout.write(JSON.stringify({ label, shown, ids: ids(), selected: ctx.state.selected.size,
  call: server.calls.find((c) => c[1] === "/alerts/hide"),
  after: elements.alertsHideSelected.style.display, button: elements.alertsHidden.textContent }));
""")
    assert out["label"] == "Hide selected (2)" and out["shown"] == ""
    assert out["call"] == ["POST", "/alerts/hide", {"correlation_ids": ["a", "c"], "reason": None}]
    assert out["ids"] == ["b"] and out["selected"] == 0 and out["after"] == "none"
    assert out["button"] == "Hidden alerts (2)"


def test_confirm_form_hides_closes_and_offers_undo():
    out = _run(r"""
await ctx.loadJobs(); await ctx.loadHidden();
const root = { querySelector: (sel) => elements[sel.replace(/^#/, "")] };
ctx.wireHideForm(root, ["c"], () => {});
elements.hideReason.value = "  test send  ";
await elements.hideConfirm.onclick();
const toastText = elements.toast.textContent, toastClass = elements.toast.className;
const undo = elements.toast.children[0];
const afterHide = { ids: ids(), closed: counters.closeModal, undoLabel: undo.textContent,
                    reason: server.calls.find((c) => c[1] === "/alerts/hide")[2].reason };
undo.onclick();
await new Promise((r) => setImmediate(r)); await new Promise((r) => setImmediate(r));
await new Promise((r) => setImmediate(r)); await new Promise((r) => setImmediate(r));
process.stdout.write(JSON.stringify({ toastText, toastClass, afterHide, afterUndo: ids(),
                                      finalToast: elements.toast.textContent }));
""")
    assert out["toastText"] == "Alert hidden" and "has-action" in out["toastClass"]
    assert out["afterHide"] == {"ids": ["a", "b"], "closed": 1, "undoLabel": "Undo", "reason": "test send"}
    assert out["afterUndo"] == ["a", "b", "c"]
    assert out["finalToast"] == "Alert unhidden"


@pytest.mark.parametrize("failure, message", [
    ("() => new TypeError('Failed to fetch')", "Could not reach the server"),
    ("() => new Error('unauthorized')", "dashboard key was rejected"),
    ("() => new Error('invalid alert ids')", "invalid alert ids"),
])
def test_a_failed_hide_is_shown_inline_and_changes_nothing(failure, message):
    out = _run(r"""
await ctx.loadJobs(); await ctx.loadHidden();
const root = { querySelector: (sel) => elements[sel.replace(/^#/, "")] };
ctx.wireHideForm(root, ["a"], () => {});
server.fail = %s;
await elements.hideConfirm.onclick();
process.stdout.write(JSON.stringify({ ids: ids(), err: elements.hideErr.textContent,
  shown: elements.hideErr.classList.contains("show"), confirmEnabled: !elements.hideConfirm.disabled,
  closed: counters.closeModal, toast: elements.toast.textContent }));
""" % failure)
    assert out["ids"] == ["a", "b", "c"]
    assert out["err"].startswith("Could not hide: ") and message in out["err"] and out["shown"]
    assert out["confirmEnabled"] and out["closed"] == 0 and out["toast"] == ""


def test_hidden_panel_row_escapes_every_value():
    out = _run(r"""
const row = ctx.hiddenRowHtml({ correlation_id: "x\"><img src=x>", hidden_at: 1767225600, hidden_by: "<b>me</b>",
  reason: "<script>alert(1)</script>", detection_name: "<i>d</i>", endpoint_name: "UNKNOWN" });
process.stdout.write(JSON.stringify({ row }));
""")
    row = out["row"]
    assert "<script>" not in row and "<img" not in row and "<b>me" not in row and "<i>d" not in row
    assert "&lt;script&gt;" in row and "&lt;b&gt;me&lt;/b&gt;" in row
    assert 'data-hidden-unhide="x&quot;&gt;&lt;img src=x&gt;"' in row


def test_new_labels_exist_in_both_languages():
    script = HARNESS + r"""
const keys = ["btn_hide_alert", "btn_unhide_alert", "btn_hidden_alerts", "btn_hide_selected", "btn_unhide_selected",
  "hide_confirm_title", "hide_confirm_body", "hide_reason_label", "hide_reason_placeholder", "hide_confirm",
  "hide_cancel", "hide_hiding", "hide_failed", "unhide_failed", "hide_err_unauthorized", "hide_err_network",
  "toast_alert_hidden", "toast_alert_unhidden", "toast_undo", "hidden_title", "hidden_intro", "hidden_empty",
  "hidden_loading", "hidden_badge", "th_hidden_reason", "th_hidden_by", "th_hidden_at", "hidden_select_all",
  "hidden_select_row", "alerts_select_page", "alerts_select_row", "route_hidden_list", "route_hide", "route_unhide"];
const out = {};
for (const lang of ["ja", "en"]) {
  const table = vm.runInContext("I18N." + lang, ctx);
  out[lang] = keys.filter((k) => table[k] === undefined);
}
vm.runInContext('state_lang.current = "ja"', ctx);
out.ja_hidden = vm.runInContext('t("btn_hidden_alerts", 3)', ctx);
out.ja_hide = vm.runInContext('t("btn_hide_alert")', ctx);
out.ja_toast = vm.runInContext('t("toast_alert_hidden", 1)', ctx);
process.stdout.write(JSON.stringify(out));
"""
    res = subprocess.run([NODE, "-e", script], capture_output=True, text=True, encoding="utf-8", cwd=ROOT, timeout=60)
    assert res.returncode == 0, res.stderr
    out = json.loads(res.stdout)
    assert out["ja"] == [] and out["en"] == []
    assert out["ja_hidden"] == "非表示のアラート (3)"
    assert out["ja_hide"] == "アラートを非表示"
    assert out["ja_toast"] == "アラートを非表示にしました"


def test_buttons_are_wired_in_the_page():
    html = (ROOT / "static/dashboard.html").read_text(encoding="utf-8")
    for anchor in ('id="alertsHidden"', 'id="alertsHideSelected"', 'id="alertsSelectAll"'):
        assert anchor in html
    assert 'getElementById("alertsHidden").onclick = openHiddenAlerts' in DASHBOARD
    assert "let html = alertActionsHtml(id)" in DASHBOARD and "wireAlertActions(id);" in DASHBOARD
    # A live update for a hidden alert must not put it back in the table.
    assert "state.hidden.has(d.correlation_id)) return;" in DASHBOARD
