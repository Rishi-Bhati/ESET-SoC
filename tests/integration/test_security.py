"""
Security-focused coverage: ingest auth, dashboard key enforcement,
WebSocket origin/key checks, and XSS-safe rendering of hostile payloads.
"""
import pytest
from fastapi.testclient import TestClient
from src.config import settings

AUTH = {"Authorization": "Bearer test_token"}

DASHBOARD_ROUTES = [
    ("get", "/dashboard/api/jobs"),
    ("get", "/dashboard/api/alerts"),
    ("get", "/dashboard/api/emails"),
]


# --------------------------- ingest auth ---------------------------

@pytest.mark.parametrize("route", ["/webhook/eset", "/webhook/syslog"])
def test_ingest_requires_token(client: TestClient, route: str):
    assert client.post(route, json={}).status_code == 401
    assert client.post(route, headers={"Authorization": "Bearer wrong"}, json={}).status_code == 401
    assert client.post(route, headers={"Authorization": ""}, json={}).status_code == 401


def test_ingest_accepts_bare_and_bearer_token(client: TestClient):
    payload = {"alert_id": "auth-form-1", "occurred_at": "2026-01-01T00:00:00Z", "severity": "LOW"}
    assert client.post("/webhook/eset", headers={"Authorization": "test_token"}, json=payload).json()["status"] == "queued"

    payload2 = {"alert_id": "auth-form-2", "occurred_at": "2026-01-01T00:00:00Z", "severity": "LOW"}
    assert client.post("/webhook/eset", headers=AUTH, json=payload2).json()["status"] == "queued"


def test_near_miss_tokens_rejected(client: TestClient):
    for bad in ["test_toke", "test_tokenX", "TEST_TOKEN", "", "Bearer", "test token"]:
        res = client.post("/webhook/eset", headers={"Authorization": f"Bearer {bad}"}, json={})
        assert res.status_code == 401, f"token {bad!r} was accepted"


def test_surrounding_whitespace_is_tolerated(client: TestClient):
    """
    validate_eset_token strips the bearer value, so stray whitespace from the
    sender is accepted. Documented deliberately: it is lenient parsing, not a
    weakening — the exact secret is still required.
    """
    payload = {"alert_id": "auth-ws-1", "occurred_at": "2026-01-01T00:00:00Z", "severity": "LOW"}
    res = client.post("/webhook/eset", headers={"Authorization": "Bearer  test_token  "}, json=payload)
    assert res.json()["status"] == "queued"


# --------------------------- dashboard key ---------------------------

@pytest.mark.parametrize("method,route", DASHBOARD_ROUTES)
def test_dashboard_open_when_key_unset(client: TestClient, method: str, route: str):
    assert getattr(client, method)(route).status_code == 200


@pytest.mark.parametrize("method,route", DASHBOARD_ROUTES)
def test_dashboard_requires_key_when_configured(client: TestClient, monkeypatch, method: str, route: str):
    monkeypatch.setattr(settings, "dashboard_access_key", "s3cret-key")

    assert getattr(client, method)(route).status_code == 401
    assert getattr(client, method)(route, headers={"X-Dashboard-Key": "wrong"}).status_code == 401
    assert getattr(client, method)(route, headers={"X-Dashboard-Key": "s3cret-key"}).status_code == 200


def test_dashboard_retry_requires_key(client: TestClient, monkeypatch):
    res = client.post("/webhook/eset", headers=AUTH, json={
        "alert_id": "sec-retry-1", "occurred_at": "2026-01-01T00:00:00Z", "severity": "LOW"})
    cid = res.json()["correlation_id"]

    monkeypatch.setattr(settings, "dashboard_access_key", "s3cret-key")
    assert client.post(f"/dashboard/api/jobs/{cid}/retry").status_code == 401


# --------------------------- websocket ---------------------------

def test_ws_rejects_cross_origin(client: TestClient):
    with pytest.raises(Exception):
        with client.websocket_connect("/dashboard/api/ws", headers={"Origin": "http://evil.example"}):
            pass


def test_ws_allows_same_origin(client: TestClient):
    # TestClient's base host is "testserver"
    with client.websocket_connect("/dashboard/api/ws", headers={"Origin": "http://testserver"}) as ws:
        assert ws is not None


def test_ws_requires_key_when_configured(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "dashboard_access_key", "s3cret-key")
    with pytest.raises(Exception):
        with client.websocket_connect("/dashboard/api/ws"):
            pass
    with client.websocket_connect("/dashboard/api/ws?key=s3cret-key") as ws:
        assert ws is not None


# --------------------------- XSS ---------------------------

XSS = "<img src=x onerror=alert(1)>"


def test_hostile_payload_is_stored_and_served_without_executing(client: TestClient):
    """
    A malicious ingest payload must round-trip as data. The dashboard escapes it
    at render time, so the API returning the raw string is expected; what must NOT
    happen is the API serving it inside an HTML document.
    """
    res = client.post("/webhook/eset", headers=AUTH, json={
        "alert_id": "xss-1",
        "occurred_at": "2026-01-01T00:00:00Z",
        "severity": "HIGH",
        "detection_name": XSS,
        "endpoint_name": XSS,
        "raw_subject": XSS,
    })
    cid = res.json()["correlation_id"]

    detail = client.get(f"/dashboard/api/jobs/{cid}")
    # JSON response, not HTML — the browser will never parse this as markup
    assert detail.headers["content-type"].startswith("application/json")
    assert detail.json()["job"]["raw_payload"]["detection_name"] == XSS


def test_dashboard_escapes_all_rendered_data():
    """
    Guards the stored-XSS fix: every interpolation of ingested data into innerHTML
    must go through esc(). Catches a raw `${j.field}` slipping back in.
    """
    import os
    base = os.path.join(os.path.dirname(__file__), "..", "..", "static")
    sources = {}
    for name in ("dashboard.js", "dashboard-viz.js"):
        with open(os.path.join(base, name)) as f:
            sources[name] = f.read()

    assert "function esc(" in sources["dashboard.js"], "escaping helper is missing"

    unescaped = [
        "${j.detection_name}", "${j.endpoint_name}", "${j.source}", "${j.correlation_id}",
        "${m.subject}", "${m.body}", "${job.error}", "${a.detection_name}",
        "${a.object_uri}", "${a.file_hash}", "${r.risk_rationale}", "${e.message}",
        "${it.detection_name}", "${info.detail}",
    ]
    for name, src in sources.items():
        for token in unescaped:
            assert token not in src, f"unescaped interpolation in {name}: {token}"


def test_dashboard_badges_use_class_allowlist():
    """A hostile status string must not be able to break out of the class attribute."""
    import os
    path = os.path.join(os.path.dirname(__file__), "..", "..", "static", "dashboard.js")
    with open(path) as f:
        js = f.read()
    assert "BADGES.has(value)" in js, "badge CSS class is not restricted to an allowlist"
