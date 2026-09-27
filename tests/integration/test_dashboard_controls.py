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


def test_settings_reports_security_posture_without_secrets(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "dashboard_access_key", "")
    body = client.get("/dashboard/api/settings").json()
    posture = {p["id"]: p["status"] for p in body["security"]}
    assert posture["dashboard_key"] == "bad"
    assert posture["https"] == "warn"          # TestClient speaks plain http
    assert "test_token" not in json.dumps(body)


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


async def test_every_stats_chart_uses_the_same_created_at_window(client, monkeypatch):
    import time
    from src.storage import job_store
    from src.api import dashboard
    from src.storage.database import db_session

    now = time.time()
    rows = [("recent", now - 600, "WEBHOOK", "HIGH"),
            ("older", now - 12 * 3600, "SYSLOG", "LOW"),
            ("future", now + 3600, "SYSLOG", "CRITICAL")]
    for cid, created, source, _risk in rows:
        await job_store.create_job(cid, source, {})
        async with db_session() as conn:
            await conn.execute("UPDATE jobs SET created_at=? WHERE correlation_id=?", (created, cid))
            await conn.commit()
    monkeypatch.setattr(dashboard, "_read_results", lambda limit: [
        {"correlation_id": cid, "risk_level": risk} for cid, _created, _source, risk in rows
    ])
    small = client.get("/dashboard/api/stats?hours=6").json()
    assert small["totals"]["jobs"] == sum(p["count"] for p in small["series"]) == 1
    assert small["by_risk"] == {"HIGH": 1}
    assert small["by_source"] == {"WEBHOOK": 1}
    assert small["by_status"] == {"PENDING": 1}
    large = client.get("/dashboard/api/stats?hours=24").json()
    assert large["totals"]["jobs"] == 2
    assert large["by_risk"] == {"HIGH": 1, "LOW": 1}


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


def _write_log(path, entries):
    path.write_text("".join(json.dumps(e) + "\n" for e in entries))


def test_logs_paginate_newest_first_by_default(client: TestClient, tmp_path, monkeypatch):
    from src.api import dashboard
    log = tmp_path / "app.log"
    _write_log(log, [{"event": "e", "level": "info", "i": i} for i in range(250)])
    monkeypatch.setattr(dashboard, "LOG_PATH", str(log))

    p1 = client.get("/dashboard/api/logs?page_size=100").json()
    assert (p1["total"], p1["pages"], p1["page"]) == (250, 3, 1)
    assert [e["i"] for e in p1["lines"]][:2] == [249, 248]
    p3 = client.get("/dashboard/api/logs?page_size=100&page=3").json()
    assert [e["i"] for e in p3["lines"]] == list(range(49, -1, -1))
    # Out-of-range pages clamp rather than returning an empty page
    assert client.get("/dashboard/api/logs?page_size=100&page=99").json()["page"] == 3

    oldest = client.get("/dashboard/api/logs?page_size=100&sort=asc").json()
    assert [e["i"] for e in oldest["lines"]][:2] == [0, 1]


def test_logs_ids_are_unique_and_stable_across_appends(client: TestClient, tmp_path, monkeypatch):
    """Rows are keyed by _id in the UI so an expanded row survives a refresh."""
    from src.api import dashboard
    log = tmp_path / "app.log"
    _write_log(log, [{"event": "same", "level": "info"} for _ in range(3)])
    monkeypatch.setattr(dashboard, "LOG_PATH", str(log))

    before = client.get("/dashboard/api/logs").json()["lines"]
    assert len({e["_id"] for e in before}) == 3
    with open(log, "a") as f:
        f.write(json.dumps({"event": "new", "level": "info"}) + "\n")
    after = client.get("/dashboard/api/logs").json()["lines"]
    assert after[0]["event"] == "new"
    assert [e["_id"] for e in after[1:]] == [e["_id"] for e in before]


def test_logs_multi_level_source_and_event_filters_with_facets(client: TestClient, tmp_path, monkeypatch):
    from src.api import dashboard
    log = tmp_path / "app.log"
    _write_log(log, [
        {"event": "ingest_duplicate_dropped", "level": "warning"},
        {"event": "pipeline_failed", "level": "error"},
        {"event": "job_created", "level": "info"},
        {"event": '127.0.0.1:5000 - "POST /webhook/eset HTTP/1.1" 202', "level": "info"},
        {"event": '127.0.0.1:5001 - "GET /health HTTP/1.1" 200'},   # legacy: no level
    ])
    monkeypatch.setattr(dashboard, "LOG_PATH", str(log))

    body = client.get("/dashboard/api/logs?level=warning,error").json()
    assert {e["event"] for e in body["lines"]} == {"ingest_duplicate_dropped", "pipeline_failed"}
    # Level facet ignores the level selection itself, so every option shows a count
    assert body["facets"]["levels"] == {"warning": 1, "error": 1, "info": 3}

    http = client.get("/dashboard/api/logs?source=http").json()
    assert http["total"] == 2
    webhook = next(e for e in http["lines"] if e["http_path"] == "/webhook/eset")
    assert (webhook["http_method"], webhook["http_status"]) == ("POST", "202")
    assert client.get("/dashboard/api/logs?source=app").json()["total"] == 3

    only = client.get("/dashboard/api/logs?event=job_created").json()
    assert only["total"] == 1
    assert ("job_created", 1) in [tuple(x) for x in only["facets"]["events"]]


def test_logs_since_minutes_filters_by_timestamp(client: TestClient, tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from src.api import dashboard
    fmt = "%Y-%m-%dT%H:%M:%S.%fZ"
    now = datetime.now(timezone.utc)
    log = tmp_path / "app.log"
    _write_log(log, [
        {"event": "old", "level": "info", "timestamp": (now - timedelta(hours=3)).strftime(fmt)},
        {"event": "recent", "level": "info", "timestamp": (now - timedelta(minutes=5)).strftime(fmt)},
        {"event": "untimed", "level": "info"},
    ])
    monkeypatch.setattr(dashboard, "LOG_PATH", str(log))

    assert [e["event"] for e in client.get("/dashboard/api/logs?since_minutes=60").json()["lines"]] == ["recent"]
    assert client.get("/dashboard/api/logs").json()["total"] == 3


def test_logs_page_size_is_capped_and_legacy_limit_still_works(client: TestClient, tmp_path, monkeypatch):
    from src.api import dashboard
    log = tmp_path / "app.log"
    _write_log(log, [{"event": "e", "level": "info"} for _ in range(700)])
    monkeypatch.setattr(dashboard, "LOG_PATH", str(log))

    assert len(client.get("/dashboard/api/logs?page_size=5000").json()["lines"]) == 500
    body = client.get("/dashboard/api/logs?limit=10").json()
    assert len(body["lines"]) == 10 and body["total_scanned"] == 700


def test_logs_cache_resets_when_file_is_replaced(client: TestClient, tmp_path, monkeypatch):
    from src.api import dashboard
    log = tmp_path / "app.log"
    _write_log(log, [{"event": "a", "level": "info"} for _ in range(5)])
    monkeypatch.setattr(dashboard, "LOG_PATH", str(log))
    assert client.get("/dashboard/api/logs").json()["total"] == 5

    _write_log(log, [{"event": "b", "level": "info"}])   # truncated + rewritten
    body = client.get("/dashboard/api/logs").json()
    assert body["total"] == 1 and body["lines"][0]["event"] == "b"


def test_logs_export_returns_every_match_as_ndjson(client: TestClient, tmp_path, monkeypatch):
    from src.api import dashboard
    log = tmp_path / "app.log"
    _write_log(log, [{"event": "e", "level": "warning" if i % 2 else "info", "i": i} for i in range(300)])
    monkeypatch.setattr(dashboard, "LOG_PATH", str(log))

    res = client.get("/dashboard/api/logs/export?level=warning")
    assert res.status_code == 200
    assert "attachment" in res.headers["content-disposition"]
    rows = [json.loads(line) for line in res.text.splitlines()]
    assert len(rows) == 150 and all(r["level"] == "warning" for r in rows)
    assert "_id" not in rows[0] and rows[0]["i"] == 299


def test_logs_missing_file_is_not_an_error(client: TestClient, monkeypatch):
    from src.api import dashboard
    monkeypatch.setattr(dashboard, "LOG_PATH", "/nonexistent/app.log")
    body = client.get("/dashboard/api/logs").json()
    assert body["lines"] == [] and "note" in body


def test_historical_logs_redact_credentials_before_display_or_search(client, tmp_path, monkeypatch):
    from src.api import dashboard
    log = tmp_path / "old.log"
    log.write_text(json.dumps({"event": "WebSocket /ws?%6bey=old-secret", "level": "info"}) + "\n[]\n")
    monkeypatch.setattr(dashboard, "LOG_PATH", str(log))
    result = client.get("/dashboard/api/logs").json()
    assert len(result["lines"]) == 1
    assert "old-secret" not in json.dumps(result)
    assert client.get("/dashboard/api/logs?q=old-secret").json()["lines"] == []


def test_alerts_index_carries_normalized_names_for_non_eset_shapes(client: TestClient):
    """A payload that names its fields differently has no detection_name in
    the raw body; the Alerts table needs the alias-resolved names."""
    res = client.post("/webhook/eset", headers=AUTH, json={
        "alert_id": "ctrl-shape-1", "threat": "Trojan.Generic", "hostname": "LAB-7", "risk": "high",
    })
    cid = res.json()["correlation_id"]
    alert = next(a for a in client.get("/dashboard/api/alerts").json()["alerts"] if a["correlation_id"] == cid)
    assert alert["endpoint_name"] == "LAB-7"


def test_alerts_backfills_names_for_older_index_records(client: TestClient):
    from src.api import dashboard
    cid = client.post("/webhook/eset", headers=AUTH, json=_payload("ctrl-backfill-1")).json()["correlation_id"]
    index = os.path.join(settings.output_dir, "index.json")
    records = json.load(open(index))
    for r in records:
        r.pop("detection_name", None); r.pop("endpoint_name", None)
    json.dump(records, open(index, "w"))
    dashboard._label_cache.clear()
    alert = next(a for a in client.get("/dashboard/api/alerts").json()["alerts"] if a["correlation_id"] == cid)
    assert (alert["detection_name"], alert["endpoint_name"]) == ("Win32/Test.Threat", "HOST-TEST-01")


# --------------------------- ai content ---------------------------

def test_ai_content_lists_generated_notifications(client: TestClient):
    client.post("/webhook/eset", headers=AUTH, json=_payload("ctrl-ai-1"))

    items = client.get("/dashboard/api/ai-content").json()["items"]
    assert len(items) >= 1
    it = items[0]
    assert it["detection_name"] == "Win32/Test.Threat"
    for key in ("risk_level", "alert_summary_ja", "risk_reason_ja", "client_notification_ja",
                "internal_summary_ja", "engineer_summary_en", "recommended_initial_actions_ja",
                "additional_confirmation_items_ja", "unknown_items", "backlog_comment_ja",
                "email_subject_ja", "email_body_ja"):
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


def test_dashboard_assets_must_be_revalidated(client: TestClient):
    """Without this a browser can keep running a stale dashboard.js against
    new HTML after an update."""
    for asset in ["/", "/static/dashboard.js", "/static/ui-select.js"]:
        assert client.get(asset).headers.get("cache-control") == "no-cache", asset


def test_dashboard_js_escapes_rendered_data():
    """Guards the stored-XSS fix across the rebuilt frontend."""
    base = os.path.join(os.path.dirname(__file__), "..", "..", "static")
    js = open(os.path.join(base, "dashboard.js"), encoding="utf-8").read()
    assert "function esc(" in js
    for token in ["${j.detection_name}", "${j.endpoint_name}", "${m.subject}",
                  "${job.error}", "${a.detection_name}", "${it.detection_name}"]:
        assert token not in js, f"unescaped interpolation: {token}"
