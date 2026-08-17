"""
Coverage for the dashboard's control surface: settings store, stats, logs,
AI content, and outbox mutation.
"""
import json
import os
import pytest
from fastapi.testclient import TestClient
from src.config import settings
from src.services import email_outbox
from src.storage import settings_store

AUTH = {"Authorization": "Bearer test_token"}


def _payload(alert_id: str, severity: str = "HIGH"):
    return {
        "alert_id": alert_id,
        "occurred_at": "2026-08-10T12:00:00Z",
        "severity": severity,
        "detection_name": "Win32/Test.Threat",
        "endpoint_name": "HOST-TEST-01",
        "threat_handled": False,
        "isolation_status": False,
    }


# --------------------------- settings ---------------------------

def test_settings_defaults_to_env(client: TestClient):
    body = client.get("/dashboard/api/settings").json()
    assert set(body["recipients"]) == {
        "client_notification_emails", "cthree_notification_emails",
        "internal_notification_emails", "engineer_notification_emails",
    }
    assert all(r["source"] == "env" for r in body["recipients"].values())
    assert "dedup_ttl_seconds" in body["runtime"]
    assert body["runtime"]["dashboard_protected"] is False


def test_update_recipients_persists_and_marks_source(client: TestClient):
    res = client.put("/dashboard/api/settings/recipients", json={
        "client_notification_emails": "a@example.com, b@example.com",
        "engineer_notification_emails": "eng@example.com",
    })
    assert res.status_code == 200
    assert set(res.json()["updated"]) == {"client_notification_emails", "engineer_notification_emails"}

    body = client.get("/dashboard/api/settings").json()["recipients"]
    assert body["client_notification_emails"]["value"] == "a@example.com, b@example.com"
    assert body["client_notification_emails"]["source"] == "dashboard"
    # Untouched keys still report the env default
    assert body["cthree_notification_emails"]["source"] == "env"


def test_update_recipients_rejects_empty_payload(client: TestClient):
    assert client.put("/dashboard/api/settings/recipients", json={}).status_code == 400


def test_update_recipients_ignores_unknown_keys(client: TestClient):
    res = client.put("/dashboard/api/settings/recipients", json={
        "client_notification_emails": "x@example.com",
        "sqlite_db_path": "/etc/passwd",     # must not be writable through this route
    })
    assert res.json()["updated"] == ["client_notification_emails"]
    assert settings.sqlite_db_path != "/etc/passwd"


@pytest.mark.asyncio
async def test_saved_recipients_drive_the_pipeline(client: TestClient):
    """The whole point of the settings UI: saved values must reach composed emails."""
    client.put("/dashboard/api/settings/recipients", json={
        "client_notification_emails": "dashboard-client@example.com",
        "cthree_notification_emails": "",
        "internal_notification_emails": "",
        "engineer_notification_emails": "",
    })

    res = client.post("/webhook/eset", headers=AUTH, json=_payload("ctrl-recipients-1"))
    cid = res.json()["correlation_id"]

    emails = [e for e in await email_outbox.list_emails() if e["correlation_id"] == cid]
    assert len(emails) == 1
    assert emails[0]["notification_type"] == "CLIENT_JA"
    assert emails[0]["to"] == ["dashboard-client@example.com"]


@pytest.mark.asyncio
async def test_dashboard_override_beats_env(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "client_notification_emails", "env@example.com")
    assert await settings_store.get_effective("client_notification_emails") == "env@example.com"

    await settings_store.set_setting("client_notification_emails", "override@example.com")
    assert await settings_store.get_effective("client_notification_emails") == "override@example.com"


# --------------------------- stats ---------------------------

def test_stats_shape_and_counts(client: TestClient):
    client.post("/webhook/eset", headers=AUTH, json=_payload("ctrl-stats-1", "CRITICAL"))
    client.post("/webhook/eset", headers=AUTH, json=_payload("ctrl-stats-2", "LOW"))

    s = client.get("/dashboard/api/stats?hours=24").json()
    assert s["totals"]["jobs"] == 2
    assert s["by_source"]["WEBHOOK"] == 2
    assert sum(s["by_status"].values()) == 2
    assert len(s["series"]) == 24
    assert sum(p["count"] for p in s["series"]) == 2
    # Risk comes from result files
    assert s["by_risk"].get("CRITICAL", 0) >= 1


def test_stats_window_is_clamped(client: TestClient):
    assert len(client.get("/dashboard/api/stats?hours=1").json()["series"]) == 1
    assert len(client.get("/dashboard/api/stats?hours=99999").json()["series"]) == 168


# --------------------------- logs ---------------------------

def test_logs_endpoint_parses_json_lines(client: TestClient, tmp_path, monkeypatch):
    from src.api import dashboard
    log = tmp_path / "app.log"
    log.write_text(
        json.dumps({"event": "job_created", "level": "info", "timestamp": "2026-08-17T10:00:00Z"}) + "\n"
        + json.dumps({"event": "pipeline_failed", "level": "error", "timestamp": "2026-08-17T10:00:01Z"}) + "\n"
        + "not json at all\n"
    )
    monkeypatch.setattr(dashboard, "LOG_PATH", str(log))

    all_lines = client.get("/dashboard/api/logs").json()["lines"]
    assert len(all_lines) == 2          # the non-JSON line is skipped

    errors = client.get("/dashboard/api/logs?level=error").json()["lines"]
    assert len(errors) == 1 and errors[0]["event"] == "pipeline_failed"

    found = client.get("/dashboard/api/logs?q=job_created").json()["lines"]
    assert len(found) == 1


def test_logs_missing_file_is_not_an_error(client: TestClient, monkeypatch):
    from src.api import dashboard
    monkeypatch.setattr(dashboard, "LOG_PATH", "/nonexistent/app.log")
    body = client.get("/dashboard/api/logs").json()
    assert body["lines"] == [] and "note" in body


# --------------------------- ai content ---------------------------

def test_ai_content_lists_generated_notifications(client: TestClient):
    client.post("/webhook/eset", headers=AUTH, json=_payload("ctrl-ai-1"))

    items = client.get("/dashboard/api/ai-content").json()["items"]
    assert len(items) >= 1
    it = items[0]
    assert it["detection_name"] == "Win32/Test.Threat"
    for key in ("client_notification_ja", "cthree_notification_ja",
                "internal_notification_ja", "engineer_notification_en"):
        assert key in it["ai_output"]


# --------------------------- outbox mutation ---------------------------

@pytest.mark.asyncio
async def test_delete_email_removes_from_outbox(client: TestClient):
    client.put("/dashboard/api/settings/recipients", json={
        "client_notification_emails": "c@example.com",
        "cthree_notification_emails": "",
        "internal_notification_emails": "",
        "engineer_notification_emails": "",
    })
    res = client.post("/webhook/eset", headers=AUTH, json=_payload("ctrl-del-1"))
    cid = res.json()["correlation_id"]

    emails = await email_outbox.list_emails()
    target = next(e for e in emails if e["correlation_id"] == cid)

    assert client.delete(f"/dashboard/api/emails/{target['email_id']}").status_code == 200
    remaining = {e["email_id"] for e in await email_outbox.list_emails()}
    assert target["email_id"] not in remaining


def test_delete_unknown_email_404(client: TestClient):
    assert client.delete("/dashboard/api/emails/nope").status_code == 404


# --------------------------- static assets ---------------------------

def test_dashboard_scripts_are_served(client: TestClient):
    for asset in ["/static/dashboard.js", "/static/dashboard-viz.js", "/static/dashboard.html"]:
        assert client.get(asset).status_code == 200, asset


def test_dashboard_js_escapes_rendered_data():
    """Guards the stored-XSS fix across the rebuilt frontend."""
    base = os.path.join(os.path.dirname(__file__), "..", "..", "static")
    js = open(os.path.join(base, "dashboard.js")).read()
    assert "function esc(" in js
    for token in ["${j.detection_name}", "${j.endpoint_name}", "${m.subject}",
                  "${job.error}", "${a.detection_name}", "${it.detection_name}"]:
        assert token not in js, f"unescaped interpolation: {token}"
