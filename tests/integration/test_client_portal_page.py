"""
The client portal web UI (static/client/*), served at /client with its assets
under /client/assets. These are static-file / header checks; the API behind the
page is covered by the other client tests.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from src.main import app

CLIENT_DIR = Path(__file__).resolve().parents[2] / "static" / "client"
ASSETS = ["client.js", "client.css", "client-i18n.js"]


@pytest.fixture
def web() -> TestClient:
    return TestClient(app)


def _strip_comments(js: str) -> str:
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", js)


@pytest.mark.parametrize("path", ["/client", "/client/"])
def test_page_is_served_with_csp_and_no_cache(web, path):
    res = web.get(path)
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/html")
    assert res.headers["cache-control"] == "no-cache"
    csp = res.headers["content-security-policy"]
    # same-origin scripts/styles/fetch are all the page needs
    assert "script-src 'self'" in csp and "default-src 'self'" in csp and "connect-src 'self'" in csp
    assert "'unsafe-inline'" not in csp.split("script-src", 1)[1].split(";", 1)[0]
    assert res.headers["x-frame-options"] == "DENY"
    assert res.headers["x-content-type-options"] == "nosniff"


def test_page_needs_no_credential_and_has_no_inline_script(web):
    html = web.get("/client").text
    assert html.lstrip().lower().startswith("<!doctype html>")
    for body in re.findall(r"<script\b[^>]*>(.*?)</script>", html, flags=re.S | re.I):
        assert body.strip() == "", "inline <script> bodies are blocked by the CSP"
    scripts = re.findall(r'<script\b[^>]*\bsrc="([^"]+)"', html)
    assert scripts == ["/client/assets/client-i18n.js", "/client/assets/client.js"]
    assert 'href="/client/assets/client.css"' in html
    assert "/static/" not in html
    assert not re.search(r"\son[a-z]+\s*=", html, flags=re.I), "inline event handler attribute"
    assert "javascript:" not in html.lower()
    assert 'name="viewport"' in html


@pytest.mark.parametrize("name", ASSETS)
def test_assets_are_served_and_revalidated(web, name):
    res = web.get(f"/client/assets/{name}")
    assert res.status_code == 200
    assert res.headers["cache-control"] == "no-cache"
    assert res.text == (CLIENT_DIR / name).read_text(encoding="utf-8")


def test_assets_mount_serves_nothing_outside_the_client_directory(web):
    assert web.get("/client/assets/../dashboard.js").status_code in (400, 404)
    assert web.get("/client/assets/dashboard.js").status_code == 404
    assert web.get("/client/assets/%2e%2e/dashboard.js").status_code in (400, 404)


@pytest.mark.parametrize("name", ASSETS + ["index.html"])
def test_client_files_do_not_reach_into_engineering_code(name):
    text = (CLIENT_DIR / name).read_text(encoding="utf-8")
    code = _strip_comments(text) if name.endswith(".js") else text
    for forbidden in ("/static/", "/dashboard/api", "/status/", "WebSocket", "X-Dashboard-Key", "dashboard.js"):
        assert forbidden not in code, f"{name} references {forbidden}"


def test_client_js_escapes_rendered_data():
    js = _strip_comments((CLIENT_DIR / "client.js").read_text(encoding="utf-8"))
    assert "function esc(" in js
    assert "eval(" not in js and "new Function" not in js and "document.write" not in js
    # Every ${...} interpolation is escaped, URL-encoded, a pre-escaped *Html value
    # or the severity badge helper — never raw data.
    safe = re.compile(r"^(esc\(|sevBadge\(|encodeURIComponent\(|flag\(|valueHtml\(|\w+Html$)")
    unsafe = []
    for m in re.finditer(r"\$\{((?:[^{}]|\{[^{}]*\})*)\}", js):
        expr = m.group(1).strip()
        if not safe.match(expr):
            unsafe.append(expr)
    assert unsafe == []
    for token in ["${a.detection_name}", "${a.endpoint_name}", "${r.body}", "${r.author}",
                  "${a.ai_summary_excerpt}", "${flat.raw_alert_json}"]:
        assert token not in js, f"unescaped interpolation: {token}"
    # Recommendation text and the raw alert go through esc() and keep their line breaks via CSS.
    assert 'class="pre">${esc(r.body)}' in js
    assert "${esc(prettyJson(flat.raw_alert_json))}" in js
    assert "white-space:pre-wrap" in (CLIENT_DIR / "client.css").read_text(encoding="utf-8")


def test_client_js_uses_the_session_header_and_jst():
    js = (CLIENT_DIR / "client.js").read_text(encoding="utf-8")
    assert '"X-Client-Session"' in js
    assert 'sessionStorage' in js and "client_session" in js
    assert 'timeZone: "Asia/Tokyo"' in js
    assert "encodeURIComponent(" in js
    assert "console.log" not in js, "tokens must never reach the console"


# ------------------------------------------------------- layout for a non-technical reader

def _html() -> str:
    return (CLIENT_DIR / "index.html").read_text(encoding="utf-8")


def _tag(html: str, element_id: str) -> str:
    m = re.search(rf'<[a-z]+\b[^>]*\bid="{element_id}"[^>]*>', html)
    assert m, f"#{element_id} is missing"
    return m.group(0)


def test_overview_is_the_first_and_default_view():
    html = _html()
    tabs = re.findall(r'role="tab"[^>]*\bdata-tab="([a-z]+)"', html)
    assert tabs == ["overview", "alerts", "reports"]
    assert 'aria-selected="true"' in _tag(html, "tabOverview")
    assert " hidden" not in _tag(html, "panelOverview")
    for panel in ("panelAlerts", "panelReports"):
        assert " hidden" in _tag(html, panel)
    js = (CLIENT_DIR / "client.js").read_text(encoding="utf-8")
    # Anything that is not a known tab route lands on the overview.
    assert 'return "overview";' in js


def test_secondary_alert_controls_sit_behind_a_disclosure():
    html = _html()
    more = re.search(r'<details id="moreFilters"[^>]*>(.*?)</details>', html, flags=re.S)
    assert more, "the 'More options' disclosure is missing"
    assert "<details id=\"moreFilters\" open" not in html, "secondary options start collapsed"
    for control in ("fSort", "fSize", "clearFilters", "refreshBtn"):
        assert f'id="{control}"' in more.group(1), f"#{control} should be under More options"
    # Severity is chosen in one place (the count chips), not a second checkbox row.
    assert 'id="sevFilter"' not in html
    # Custom dates appear only when "Choose dates" is picked.
    assert " hidden" in _tag(html, "customDates")


def test_alert_detail_leads_with_plain_language_and_collapses_technical_fields():
    js = _strip_comments((CLIENT_DIR / "client.js").read_text(encoding="utf-8"))
    body = js[js.index("function renderDetail("):js.index("function onDetailClosed(")]
    page = body[body.index("body.innerHTML = `"):]           # the rendered order
    order = [page.index(k) for k in ('t("section_story")', 't("section_recs")', "${factsSectionHtml}",
                                     "${aiMoreSectionHtml}", 't("section_technical")')]
    assert order == sorted(order), "detail order: what happened, engineer advice, key facts, technical"
    assert '<details class="disclose"><summary>${esc(t("section_technical"))}' in body
    assert '<details class="disclose" open' not in body
    # Every field the server sends stays reachable: the technical section lists the rest.
    assert "!shown.has(k)" in body and "raw_alert_json" in body


def test_portal_ui_calls_only_the_existing_client_api():
    js = _strip_comments((CLIENT_DIR / "client.js").read_text(encoding="utf-8"))
    paths = set(re.findall(r'api(?:Fetch)?\("(/[^"?]*)', js))
    # /stats: the Home charts' aggregate endpoint (counts only; same scoping as /alerts).
    assert paths <= {"/auth/login", "/auth/logout", "/auth/me", "/alerts", "/alerts/", "/alerts/export",
                     "/export/fields", "/reports", "/reports/", "/stats"}, paths


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
@pytest.mark.parametrize("name", ["client.js", "client-i18n.js"])
def test_client_scripts_parse(name):
    subprocess.run(["node", "--check", str(CLIENT_DIR / name)], check=True, capture_output=True)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_english_wording_avoids_soc_jargon():
    script = (
        f"eval(require('fs').readFileSync({json.dumps(str(CLIENT_DIR / 'client-i18n.js'))},'utf8')"
        "+';console.log(JSON.stringify(CLIENT_I18N.en))');"
    )
    en = json.loads(subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True).stdout)
    for key, text in en.items():
        for word in ("endpoint", "detection", "telemetry", "IOC", "triage"):
            assert word.lower() not in text.lower(), f"{key}: {text!r} uses {word!r}"


# ------------------------------------------------------------------------ Home charts

def _js() -> str:
    return _strip_comments((CLIENT_DIR / "client.js").read_text(encoding="utf-8"))


def _fn(js: str, name: str) -> str:
    start = js.index(f"function {name}(")
    nxt = re.search(r"\n(?:async )?function \w+\(", js[start + 1:])
    return js[start:start + 1 + nxt.start()] if nxt else js[start:]


def test_home_period_picker_offers_7_30_90_days_and_drives_the_stats_call():
    html = _html()
    picker = re.search(r'<div id="homePeriod"[^>]*>(.*?)</div>', html, flags=re.S)
    assert picker, "the Home period picker is missing"
    assert re.findall(r'data-days="(\d+)"', picker.group(1)) == ["7", "30", "90"]
    # It sits above the status sentence and every chart, so one control scopes the page.
    assert html.index('id="homePeriod"') < html.index('id="ovStatus"') < html.index('id="ovChart"')
    js = _js()
    assert "const HOME_DAYS = [7, 30, 90];" in js
    load = _fn(js, "loadOverview")
    assert 'api("/stats?"' in load and "days: String(days)" in load


def test_charts_are_built_with_dom_apis_not_markup():
    """Device and threat names come from alerts (attacker-influenced): the chart, legend,
    tooltip, table and ranked lists never go through innerHTML. ECharts draws the marks
    to a canvas; every text layer around them (tooltips, legend, the donut's centre
    figure) is this page's own DOM, filled with textContent."""
    js = _js()
    for name in ("renderFigures", "renderLegend", "renderChart", "setChartActive", "renderStatsTable",
                 "renderRanked", "drawRanked", "renderSeverity", "renderStatsSkeleton", "tipRow", "placeTip"):
        body = _fn(js, name)
        assert "innerHTML" not in body and "insertAdjacentHTML" not in body, name
    assert "document.createTextNode(" in js
    builder = _fn(js, "el")
    assert "setAttribute(k, String(v))" in builder
    # ECharts' own HTML tooltip (which takes an HTML string) is never configured.
    assert "tooltip:" not in js and "formatter: (params)" not in js


def test_client_files_load_nothing_from_other_origins():
    for name in ASSETS + ["index.html"]:
        text = (CLIENT_DIR / name).read_text(encoding="utf-8")
        urls = set(re.findall(r"https?://[^\s\"')]+", text))
        assert urls <= {"http://www.w3.org/2000/svg"}, (name, urls)
    # The only script the page adds itself is the chart library vendored beside it
    # (same origin, under /client/assets: never /static, never a CDN), and only once
    # signed in: the login page does not load it.
    js = _js()
    assert set(re.findall(r'"(/[^"\s]*\.js)"', js)) == {"/client/assets/echarts.min.js"}
    assert (CLIENT_DIR / "echarts.min.js").is_file()
    assert "echarts" not in _html()
    assert "loadEcharts()" in _fn(js, "showApp") and "loadEcharts" not in _fn(js, "init")


def test_vendored_chart_library_is_served_from_the_client_assets(web):
    res = web.get("/client/assets/echarts.min.js")
    assert res.status_code == 200
    assert res.headers["cache-control"] == "no-cache"
    assert res.headers["content-type"].startswith(("text/javascript", "application/javascript"))


def test_every_chart_has_a_text_equivalent():
    html = _html()
    assert re.search(r'<details id="ovTableWrap"[^>]*>\s*<summary data-i18n="table_show"', html)
    assert 'id="ovChartLive"' in html and 'aria-live="polite"' in _tag(html, "ovChartLive")
    js = _js()
    chart = _fn(js, "renderChart")
    assert 'setAttribute("tabindex", "0")' in chart and 't("chart_aria"' in chart
    keys = _fn(js, "bindChart")
    for key in ("ArrowLeft", "ArrowRight", "Home", "End", "Enter", "Escape"):
        assert f'"{key}"' in keys


def test_severity_fills_are_reserved_for_severity():
    css = (CLIENT_DIR / "client.css").read_text(encoding="utf-8")
    for lvl in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        assert css.count(f"--sev-fill-{lvl}:") == 3, lvl          # dark base, OS light, explicit light
    # The ranked device/threat bars use a neutral ink, never a severity colour: the
    # --rank-fill token is defined per theme without a severity value, and the bar
    # chart reads that token and no severity token.
    assert css.count("--rank-fill:") == 3
    for value in re.findall(r"--rank-fill:([^;]+);", css):
        assert "sev-" not in value
    js = _js()
    assert 'v("--rank-fill"' in _fn(js, "chartTokens")
    draw = _fn(js, "drawRanked")
    assert "k.rank" in draw and "k.sev" not in draw
