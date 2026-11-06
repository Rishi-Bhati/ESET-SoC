"""Static UI guards for the Client Portal tab and alert recommendations (D3).

The dashboard ships as plain JS/HTML, so the contracts that matter here —
translation parity, escaping of rendered data, stable placeholder ids, and the
CSP's no-new-inline-script rule — are checked at the source level.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

STATIC = Path(__file__).resolve().parents[2] / "static"

NEW_KEYS = [
    "nav_portal", "view_portal_title", "view_portal_sub",
    "panel_portal_settings", "panel_portal_users", "panel_portal_reports",
    "pgroup_weekly_report", "pset_k_weekly_report_enabled",
    "pset_k_weekly_report_weekday", "pset_k_weekly_report_time",
    "label_recommendation_emails", "hint_recommendation_emails",
    "label_weekly_report_emails", "hint_weekly_report_emails",
    "th_recommendations", "rec_title", "rec_body_label",
    "rec_retract", "route_rec_list", "route_portal_settings",
]

# Only the D3 feature's own keys are checked for duplicates: a duplicate inside
# one table silently overrides the earlier definition, so the visible text would
# depend on source order rather than on the table.
_D3_PREFIX = re.compile(
    r"^(pset_|rec_|pgroup_|weekday_|nav_portal$|view_portal_|panel_portal_|"
    r"label_recommendation|hint_recommendation|label_weekly_report|"
    r"hint_weekly_report|th_recommendations$|route_rec_|route_portal_)"
)


def _tables():
    script = (
        "global.localStorage={getItem(){return null},setItem(){}};"
        "global.document={addEventListener(){},documentElement:{}};"
        f"eval(require('fs').readFileSync({json.dumps(str(STATIC / 'i18n.js'))},'utf8')"
        "+';console.log(JSON.stringify({ja:Object.keys(I18N.ja),en:Object.keys(I18N.en)}))');"
    )
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_new_keys_exist_in_both_languages():
    keys = _tables()
    for key in NEW_KEYS:
        assert key in keys["ja"], f"missing ja translation: {key}"
        assert key in keys["en"], f"missing en translation: {key}"


def test_d3_keys_are_not_defined_twice_per_table():
    js = (STATIC / "i18n.js").read_text(encoding="utf-8")
    en_start = js.index("  en: {")
    ja = js[js.index("  ja: {"):en_start]
    en = js[en_start:js.index("\n};", en_start)]
    for name, chunk in (("ja", ja), ("en", en)):
        seen, dupes = set(), set()
        for match in re.finditer(r"^    ([a-z0-9_]+):", chunk, re.M):
            key = match.group(1)
            if not _D3_PREFIX.match(key):
                continue
            if key in seen:
                dupes.add(key)
            seen.add(key)
        assert not dupes, f"duplicate {name} keys: {sorted(dupes)}"


def test_recommendation_data_is_escaped_and_prewrapped():
    js = (STATIC / "dashboard.js").read_text(encoding="utf-8")
    assert "esc(rec.body)" in js
    assert "${rec.body}" not in js
    assert "esc(rec.author" in js
    assert 'esc(t("rec_retracted_reason", rec.retract_reason))' in js
    assert "white-space:pre-wrap" in js


def test_recommendation_actions_avoid_blocking_dialogs():
    js = (STATIC / "dashboard.js").read_text(encoding="utf-8")
    for forbidden in ("window.prompt(", "window.alert(", "window.confirm("):
        assert forbidden not in js
    assert "data-rec-retract" in js
    assert "recommendation_added" in js
    # One batched request for the visible page, capped at the API's 500 ids.
    assert "/recommendations/counts?" in js
    assert "slice(0, 500)" in js


def test_portal_view_and_placeholder_panels_have_stable_ids():
    html = (STATIC / "dashboard.html").read_text(encoding="utf-8")
    for anchor in ('id="view-portal"', 'id="portalSettingsBody"',
                   'id="portalUsersPanel"', 'id="portalReportsPanel"'):
        assert anchor in html
    start = html.index('id="view-portal"')
    section = html[start:html.index("</section>", start)]
    assert 'id="portalUsersPanel"' in section
    assert 'id="portalReportsPanel"' in section


def test_new_recipient_fields_are_wired():
    js = (STATIC / "dashboard.js").read_text(encoding="utf-8")
    html = (STATIC / "dashboard.html").read_text(encoding="utf-8")
    assert '"recommendation_notification_emails"' in js
    assert '"weekly_report_emails"' in js
    assert 'id="in-recommendation"' in html
    assert 'id="in-weekly"' in html


def test_weekly_report_time_is_labelled_jst():
    i18n = (STATIC / "i18n.js").read_text(encoding="utf-8")
    js = (STATIC / "dashboard.js").read_text(encoding="utf-8")
    assert "送信する時刻(JST)" in i18n
    assert "Send time (JST)" in i18n
    assert 't("pset_jst")' in js


def test_no_inline_script_was_added():
    """CSP hashes the page's single existing inline script; new inline scripts
    would silently not run. Every other <script> must be an external src=."""
    html = (STATIC / "dashboard.html").read_text(encoding="utf-8")
    assert html.count("<script>") == 1


def test_portal_settings_errors_are_made_visible():
    """`.pset-err` is display:none until `.show` is added, so a message set
    without that class is invisible to the operator."""
    js = (STATIC / "dashboard.js").read_text(encoding="utf-8")
    assert 'err.classList.add("show")' in js
    assert 'err.classList.remove("show")' in js


def test_portal_settings_render_sets_key_from_dict_name():
    """GET /dashboard/api/portal-settings keys the dict by setting name; the spec
    has no "key" field, so the renderer must inject it (regression: "Cannot read
    properties of undefined (reading 'replace')")."""
    from pathlib import Path

    js = (Path(__file__).resolve().parents[2] / "static" / "dashboard.js").read_text(encoding="utf-8")
    assert "spec.key = settingKey;" in js
