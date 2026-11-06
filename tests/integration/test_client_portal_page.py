"""
The client portal web UI (static/client/*), served at /client with its assets
under /client/assets. These are static-file / header checks; the API behind the
page is covered by the other client tests.
"""
import re
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
