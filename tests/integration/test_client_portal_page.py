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
    assert paths <= {"/auth/login", "/auth/logout", "/auth/me", "/alerts", "/alerts/", "/alerts/export",
                     "/export/fields", "/reports", "/reports/"}, paths


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
