"""
Cross-cutting HTTP hardening: security headers, same-origin enforcement on
dashboard mutations, auth-failure throttling, the production config guard,
and the access-log noise filter.
"""
import logging
import re

import pytest
from fastapi.testclient import TestClient

from src import main
from src.config import settings
from src.middleware import security
from src.utils.logging import QuietDashboardAccessFilter


# --------------------------- headers ---------------------------

def test_security_headers_on_page_and_api(client: TestClient):
    for path in ["/", "/dashboard/api/jobs", "/health"]:
        h = client.get(path).headers
        assert h["x-content-type-options"] == "nosniff", path
        assert h["x-frame-options"] == "DENY", path
        assert "frame-ancestors 'none'" in h["content-security-policy"], path
        # Plain-HTTP test client: HSTS is only sent over https
        assert "strict-transport-security" not in h, path
    assert client.get("/dashboard/api/jobs").headers["cache-control"] == "no-store"


def test_csp_allows_exactly_the_inline_theme_script(client: TestClient):
    html = client.get("/").text
    csp = client.get("/").headers["content-security-policy"]
    script_src = re.search(r"script-src ([^;]+)", csp).group(1)
    assert "'unsafe-inline'" not in script_src
    for h in security.inline_script_hashes(html):
        assert h in script_src


# --------------------------- same origin ---------------------------

def test_cross_origin_dashboard_mutation_is_rejected(client: TestClient):
    body = {"client_notification_emails": "a@example.com"}
    evil = client.put("/dashboard/api/settings/recipients", json=body,
                      headers={"Origin": "https://evil.example"})
    assert evil.status_code == 403
    same = client.put("/dashboard/api/settings/recipients", json=body,
                      headers={"Origin": "http://testserver"})
    assert same.status_code == 200
    # Non-browser clients send no Origin at all
    assert client.put("/dashboard/api/settings/recipients", json=body).status_code == 200


def test_cross_origin_check_does_not_touch_the_webhook(client: TestClient):
    res = client.post("/webhook/eset", json={"alert_id": "x"},
                      headers={"Origin": "https://elsewhere.example", "Authorization": "Bearer test_token"})
    assert res.status_code != 403


# --------------------------- throttling ---------------------------

def test_wrong_dashboard_keys_are_throttled(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "dashboard_access_key", "correct-horse-battery-staple")
    monkeypatch.setattr(security.auth_limiter, "max_failures", 3)
    for _ in range(3):
        assert client.get("/dashboard/api/jobs", headers={"X-Dashboard-Key": "guess"}).status_code == 401
    blocked = client.get("/dashboard/api/jobs", headers={"X-Dashboard-Key": "correct-horse-battery-staple"})
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) > 0


def test_missing_dashboard_key_is_not_counted_as_a_guess(client: TestClient, monkeypatch):
    """The dashboard probes once without a key on every page load."""
    monkeypatch.setattr(settings, "dashboard_access_key", "correct-horse-battery-staple")
    monkeypatch.setattr(security.auth_limiter, "max_failures", 3)
    for _ in range(10):
        assert client.get("/dashboard/api/jobs").status_code == 401
    ok = client.get("/dashboard/api/jobs", headers={"X-Dashboard-Key": "correct-horse-battery-staple"})
    assert ok.status_code == 200


def test_wrong_webhook_tokens_are_throttled(client: TestClient, monkeypatch):
    monkeypatch.setattr(security.auth_limiter, "max_failures", 3)
    for _ in range(3):
        assert client.post("/webhook/eset", json={}, headers={"Authorization": "Bearer nope"}).status_code == 401
    assert client.post("/webhook/eset", json={}, headers={"Authorization": "Bearer test_token"}).status_code == 429


def test_limiter_window_expires(monkeypatch):
    lim = security.AuthFailureLimiter(max_failures=2, window_seconds=10)
    now = [1000.0]
    monkeypatch.setattr(security.time, "monotonic", lambda: now[0])
    lim.record_failure("1.2.3.4"); lim.record_failure("1.2.3.4")
    assert lim.retry_after("1.2.3.4") > 0
    assert lim.retry_after("5.6.7.8") == 0
    now[0] += 11
    assert lim.retry_after("1.2.3.4") == 0


def test_limiter_memory_is_bounded():
    lim = security.AuthFailureLimiter(max_failures=5, window_seconds=60, max_tracked=100)
    for i in range(1000):
        lim.record_failure(f"10.0.{i // 256}.{i % 256}")
    assert len(lim._failures) <= 100


# --------------------------- production guard ---------------------------

def _prod(monkeypatch, **overrides):
    values = dict(app_env="production", dashboard_access_key="k" * 32,
                  eset_webhook_auth_token="t" * 32, ai_provider="openai",
                  openai_model="gpt-test", openai_api_key="", openai_api_key_secret_id="eset-soc-lite/prod/openai",
                  enable_api_docs=False, email_delivery_enabled=False)
    values.update(overrides)
    for k, v in values.items():
        monkeypatch.setattr(settings, k, v)


def test_production_guard_accepts_a_safe_config(monkeypatch):
    _prod(monkeypatch)
    main.check_production_config()


@pytest.mark.parametrize("overrides, fragment", [
    ({"dashboard_access_key": ""}, "DASHBOARD_ACCESS_KEY is blank"),
    ({"dashboard_access_key": "123456"}, "DASHBOARD_ACCESS_KEY is shorter"),
    ({"eset_webhook_auth_token": "test"}, "ESET_WEBHOOK_AUTH_TOKEN"),
    ({"openai_api_key_secret_id": ""}, "AI_PROVIDER=openai is missing"),
    ({"openai_model": ""}, "AI_PROVIDER=openai is missing"),
    ({"openai_api_key_secret_id": "", "openai_api_key": "your_openai_api_key_here"}, "OPENAI_API_KEY is a placeholder"),
    ({"ai_provider": "skynet"}, "AI_PROVIDER 'skynet'"),
    ({"enable_api_docs": True}, "ENABLE_API_DOCS"),
    ({"email_delivery_enabled": True, "email_api_url": "", "email_api_key": ""}, "EMAIL_DELIVERY_ENABLED"),
])
def test_production_guard_refuses_unsafe_config(monkeypatch, overrides, fragment):
    _prod(monkeypatch, **overrides)
    with pytest.raises(RuntimeError, match=fragment):
        main.check_production_config()


def test_guard_is_inactive_outside_production(monkeypatch):
    _prod(monkeypatch, app_env="development", dashboard_access_key="")
    main.check_production_config()


# --------------------------- access-log noise ---------------------------

def _access_record(method, path, status):
    return logging.LogRecord("uvicorn.access", logging.INFO, "", 0,
                             '%s - "%s %s HTTP/%s" %d', ("1.2.3.4:5", method, path, "1.1", status), None)


@pytest.mark.parametrize("method, path, status, kept", [
    ("GET", "/dashboard/api/logs?page=1", 200, False),
    ("GET", "/static/dashboard.js", 304, False),
    ("GET", "/health", 200, False),
    ("GET", "/", 200, False),
    ("GET", "/dashboard/api/jobs", 401, True),     # failures always kept
    ("POST", "/webhook/eset", 202, True),          # ingest always kept
    ("PUT", "/dashboard/api/settings/recipients", 200, True),
    ("GET", "/status/abc", 200, True),
])
def test_quiet_filter_keeps_what_matters(method, path, status, kept):
    assert QuietDashboardAccessFilter().filter(_access_record(method, path, status)) is kept


def test_unconfigured_webhook_token_refuses_everything(client, monkeypatch):
    monkeypatch.setattr(settings, "eset_webhook_auth_token", "")
    for header in ("Bearer ", "Bearer", ""):
        res = client.post("/webhook/eset", headers={"Authorization": header}, json={"alert_id": "x"})
        assert res.status_code == 401
