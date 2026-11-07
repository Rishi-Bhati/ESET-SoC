"""Static guards for the dashboard's Client accounts and Weekly reports panels (T8).

The dashboard is plain JS/HTML, so the contracts that matter — translation
parity, escaping of API-supplied data, never exposing a generated password,
no blocking dialogs, the CSP's no-new-inline-script rule — are checked at the
source level, plus a small behavioural check of the escaping helpers under node.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parents[2] / "static"
JS = (STATIC / "dashboard.js").read_text(encoding="utf-8")
HTML = (STATIC / "dashboard.html").read_text(encoding="utf-8")

NEED_NODE = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


def _panel_js() -> str:
    start = JS.index("client portal: accounts + weekly reports")
    return JS[start:JS.index("API docs ══", start)]


def _tables():
    script = (
        "global.localStorage={getItem(){return null},setItem(){}};"
        "global.document={addEventListener(){},documentElement:{}};"
        f"eval(require('fs').readFileSync({json.dumps(str(STATIC / 'i18n.js'))},'utf8')"
        "+';console.log(JSON.stringify({ja:Object.keys(I18N.ja),en:Object.keys(I18N.en)}))');"
    )
    out = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def _used_keys() -> set[str]:
    return set(re.findall(r'\bt\("((?:pu|pw)_[A-Za-z_]+)"', _panel_js())) | \
        set(re.findall(r'\b(pu_[a-z_]+|pw_[a-z_]+)"', _panel_js()))


@NEED_NODE
def test_panel_keys_exist_in_both_languages():
    keys = _tables()
    used = {k for k in _used_keys() if not k.endswith("_")}
    assert used, "no panel i18n keys found"
    for key in used:
        assert key in keys["ja"], f"missing ja: {key}"
        assert key in keys["en"], f"missing en: {key}"
    for status in ("CLAIMED", "GENERATED", "QUEUED", "SENT", "NO_RECIPIENTS", "FAILED", "SKIPPED"):
        assert f"pw_status_{status}" in keys["ja"] and f"pw_status_{status}" in keys["en"]
    for trigger in ("scheduled", "manual", "baseline"):
        assert f"pw_trigger_{trigger}" in keys["ja"] and f"pw_trigger_{trigger}" in keys["en"]


@NEED_NODE
def test_panel_keys_are_symmetric_and_placeholders_removed():
    keys = _tables()
    panel = lambda lang: {k for k in keys[lang] if k.startswith(("pu_", "pw_"))}  # noqa: E731
    assert panel("ja") == panel("en")
    assert len(panel("ja")) >= 60
    for gone in ("panel_portal_users_hint", "panel_portal_reports_hint"):
        assert gone not in keys["ja"] and gone not in keys["en"]
        assert gone not in HTML


def test_panel_keys_not_defined_twice_per_table():
    js = (STATIC / "i18n.js").read_text(encoding="utf-8")
    en_start = js.index("  en: {")
    for name, chunk in (("ja", js[js.index("  ja: {"):en_start]), ("en", js[en_start:js.index("\n};", en_start)])):
        keys = re.findall(r"^    ((?:pu|pw)_[A-Za-z_]+):", chunk, re.M)
        assert len(keys) == len(set(keys)), f"duplicate {name} keys"


def test_placeholder_ids_still_exist():
    start = HTML.index('id="view-portal"')
    section = HTML[start:HTML.index("</section>", start)]
    for anchor in ('id="portalSettingsBody"', 'id="portalUsersPanel"', 'id="portalReportsPanel"',
                   'id="portalUsersBody"', 'id="portalReportsBody"'):
        assert anchor in section
    assert "Coming soon" not in section


def test_no_inline_script_was_added():
    assert HTML.count("<script>") == 1


def test_api_data_is_escaped_in_panels():
    js = _panel_js()
    for expr in ("u.username", "u.display_name", "f.detection_name", "f.endpoint_name",
                 "f.ai_summary", "r.error", "r.period_key", "u.id"):
        for m in re.finditer(r"\$\{([^}]*" + re.escape(expr) + r"[^}]*)\}", js):
            inner = m.group(1)
            ok = "esc(" in inner or "portalPill(" in inner or "t(" in inner or "badge(" in inner
            # t(...) arguments are escaped by the surrounding esc(t(...)) call.
            assert ok, f"unescaped interpolation of {expr}: ${{{inner}}}"
    # Raw interpolations that must never appear.
    for token in ("${u.username}", "${u.display_name}", "${f.detection_name}", "${f.endpoint_name}",
                  "${f.ai_summary}", "${r.error}", "${res.generated_password}",
                  "${s.password}", "${portalAdmin.secret.password}", "${portalAdmin.noticeErr}"):
        assert token not in js, f"unescaped interpolation: {token}"
    assert "esc(s.password)" in js
    assert "esc(f.ai_summary)" in js
    assert "esc(r.error)" in js
    assert "esc(u.username)" in js
    assert "esc(u.display_name)" in js
    assert "esc(f.detection_name)" in js
    assert "esc(portalAdmin.noticeErr)" in js


def test_panel_js_has_no_blocking_dialogs():
    assert not re.search(r"(?<![A-Za-z0-9_$.])(?:window\.)?(?:alert|confirm|prompt)\(", JS)
    assert "data-pu-act" in JS and "delete-confirm" in JS and "regen-confirm" in JS


def test_generated_password_is_never_persisted_or_logged():
    js = _panel_js()
    assert "generated_password" in js
    for forbidden in ("localStorage", "sessionStorage", "console.", "document.cookie", "indexedDB"):
        assert forbidden not in js, f"{forbidden} used in the portal panels"
    # No line that mentions a password may also log or store it.
    for line in js.splitlines():
        if re.search(r"password|secret", line, re.I):
            assert not re.search(r"console\.|Storage|toast\(.*(generated_password|\.password|secret)", line), line
    # The secret is dropped on dismiss, on leaving the view and on lock.
    assert "function clearPortalSecret" in js
    assert re.search(r'if \(name !== "portal"\) clearPortalSecret\(\)', JS)
    lock = JS[JS.index("function lock()"):JS.index("/** Resolves to null")]
    assert "clearPortalSecret()" in lock
    assert "navigator.clipboard" in js and "toast_copy_blocked" in js


def test_panels_use_dashboard_key_fetch_wrapper_and_blob_downloads():
    js = _panel_js()
    for path in ('"/portal/users"', '/portal/users/${enc}/password', '"/portal-settings/client_portal_enabled"',
                 '"/reports/weekly"', '"/reports/weekly/run"', "/reports/weekly/preview",
                 "/download`"):
        assert path in js, path
    assert "X-Dashboard-Key" in js
    assert "URL.createObjectURL" in js and "a.download" in js
    assert "PUT" in js and "DELETE" in js
    assert "regenerate" in js


@NEED_NODE
def test_helpers_escape_hostile_values_under_node():
    """Run the real esc()/portalPill() on hostile input."""
    helpers = JS[JS.index("const ESC_MAP"):JS.index("const BADGES")] + \
        JS[JS.index("function portalPill"):JS.index("/** Epoch seconds")]
    script = helpers + (
        "console.log(JSON.stringify([esc('<img src=x onerror=alert(1)>\"&\\''),"
        "portalPill('X\"><script>','<b>l</b>')]));"
    )
    out = json.loads(subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout)
    assert "<" not in out[0] and ">" not in out[0] and '"' not in out[0]
    assert "<script>" not in out[1] and "<b>" not in out[1]


@NEED_NODE
@pytest.mark.parametrize("name", ["dashboard.js", "i18n.js"])
def test_scripts_parse(name):
    subprocess.run(["node", "--check", str(STATIC / name)], check=True)


# ------------------------------------------------- tab layout for the operating engineer

def _portal_section() -> str:
    start = HTML.index('id="view-portal"')
    return HTML[start:HTML.index("</section>", start)]


def test_status_summary_leads_and_settings_come_last():
    section = _portal_section()
    order = [section.index(f'id="{pid}"') for pid in
             ("portalStatusPanel", "portalUsersPanel", "portalReportsPanel", "portalSettingsPanel")]
    assert order == sorted(order), "status, accounts, reports, then settings"
    assert 'id="portalStatusBody"' in section and 'data-i18n="pp_intro"' in section


def test_status_summary_answers_the_operator_questions():
    js = _panel_js()
    for fn in ("function ppPortalCard", "function ppAccountsCard", "function ppWeeklyCard",
               "function ppLatestCard", "function ppNextSteps"):
        assert fn in js, fn
    # The on/off switch lives in the status summary (one place, not two panels).
    assert "data-pu-toggle-portal" in js[js.index("function ppPortalCard"):js.index("function ppAccountsCard")]
    # Times on this tab follow the JST schedule.
    assert 'timeZone: "Asia/Tokyo"' in js


def test_live_probe_sends_no_credentials():
    """The status check asks /client/api/auth/me with no session: a missing session
    is not counted as a failed sign-in, so the probe cannot throttle anyone."""
    js = _panel_js()
    probe = js[js.index("async function probePortalLive"):js.index("function ppScrollTo")]
    assert '"/api/auth/me"' in probe and 'credentials: "omit"' in probe
    assert "X-Client-Session" not in probe and "X-Dashboard-Key" not in probe


def test_panels_do_not_retranslate_the_whole_page():
    """applyStaticI18n() rewrites every [data-i18n] on the page, including the view
    header, which made this tab's title read "Overview"."""
    js = _panel_js()
    assert "applyStaticI18n()" not in js
    assert "function translateWithin(" in js


def test_every_portal_setting_has_a_named_section():
    from src.storage.runtime_settings import REGISTRY

    block = JS[JS.index("const PSET_SECTIONS"):JS.index("const PSET_WEEKDAY_I18N")]
    placed = set(re.findall(r'"([a-z_]+)"', block))
    missing = sorted(k for k in REGISTRY if k not in placed)
    assert missing == [], f"settings without a section (would fall into Advanced): {missing}"
    # Only the weekly-report schedule starts expanded.
    assert 'open: new Set(["schedule"])' in JS


@NEED_NODE
def test_tab_keys_exist_in_both_languages():
    keys = _tables()
    used = set(re.findall(r'\bt\("((?:pp|pps)_[a-z_]+)"', JS))
    used |= set(re.findall(r'data-i18n="((?:pp|pps)_[a-z_]+)"', JS + HTML))
    used |= set(re.findall(r'(?:title|sub): "(pps_[a-z_]+)"', JS))
    assert used, "no tab keys found"
    for key in sorted(used):
        assert key in keys["ja"], f"missing ja: {key}"
        assert key in keys["en"], f"missing en: {key}"
