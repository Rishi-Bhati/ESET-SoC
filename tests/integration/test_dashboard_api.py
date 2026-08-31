"""
Endpoint coverage for the dashboard API, the root page, and the auth surface.
"""
import json
import os
import pytest
from fastapi.testclient import TestClient
from src.config import settings
from src.storage import job_store

AUTH = {"Authorization": "Bearer test_token"}


def _payload(alert_id: str, severity: str = "HIGH", **extra):
    base = {
        "alert_id": alert_id,
        "occurred_at": "2026-08-10T12:00:00Z",
        "severity": severity,
        "detection_name": "Win32/Test.Threat",
        "endpoint_name": "HOST-TEST-01",
        "threat_handled": False,
        "isolation_status": False,
    }
    base.update(extra)
    return base


# --------------------------- root & static ---------------------------

def test_root_serves_dashboard(client: TestClient):
    res = client.get("/")
    assert res.status_code == 200
    assert "ESET SOC Lite" in res.text
    assert "text/html" in res.headers["content-type"]


def test_static_assets_mounted(client: TestClient):
    res = client.get("/static/dashboard.html")
    assert res.status_code == 200


# --------------------------- health ---------------------------

def test_health_reports_all_subsystems(client: TestClient):
    res = client.get("/health")
    assert res.status_code == 200
    body = res.json()
    for key in ("status", "database", "output_directory", "gemini_api", "syslog_listener"):
        assert key in body
    assert body["database"]["status"] == "ok"
    assert body["output_directory"]["status"] == "ok"
    # Listeners are not started under TestClient (no lifespan), so they report down
    assert set(body["syslog_listener"]) == {"udp", "tcp"}


# --------------------------- jobs ---------------------------

def test_jobs_empty_then_populated(client: TestClient):
    assert client.get("/dashboard/api/jobs").json()["jobs"] == []

    res = client.post("/webhook/eset", headers=AUTH, json=_payload("dash-job-1"))
    cid = res.json()["correlation_id"]

    jobs = client.get("/dashboard/api/jobs").json()["jobs"]
    assert len(jobs) == 1
    assert jobs[0]["correlation_id"] == cid
    assert jobs[0]["source"] == "WEBHOOK"
    assert jobs[0]["raw_payload"]["detection_name"] == "Win32/Test.Threat"


def test_jobs_status_filter_and_pagination(client: TestClient):
    for i in range(3):
        client.post("/webhook/eset", headers=AUTH, json=_payload(f"dash-page-{i}"))

    all_jobs = client.get("/dashboard/api/jobs").json()["jobs"]
    assert len(all_jobs) == 3

    limited = client.get("/dashboard/api/jobs?limit=2").json()["jobs"]
    assert len(limited) == 2

    offset = client.get("/dashboard/api/jobs?limit=2&offset=2").json()["jobs"]
    assert len(offset) == 1

    success = client.get("/dashboard/api/jobs?status=SUCCESS").json()["jobs"]
    assert all(j["status"] == "SUCCESS" for j in success)

    nonexistent = client.get("/dashboard/api/jobs?status=NOPE").json()["jobs"]
    assert nonexistent == []


def test_jobs_limit_is_clamped(client: TestClient):
    # Absurd values must not blow up or bypass the cap
    assert client.get("/dashboard/api/jobs?limit=99999").status_code == 200
    assert client.get("/dashboard/api/jobs?limit=0&offset=-5").status_code == 200


def test_job_detail_includes_pipeline_result(client: TestClient):
    res = client.post("/webhook/eset", headers=AUTH, json=_payload("dash-detail-1"))
    cid = res.json()["correlation_id"]

    detail = client.get(f"/dashboard/api/jobs/{cid}").json()
    assert detail["job"]["correlation_id"] == cid
    # Pipeline runs synchronously under TestClient, so the result file exists
    assert detail["result"] is not None
    assert detail["result"]["normalized_alert"]["detection_name"] == "Win32/Test.Threat"
    assert detail["result"]["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")


def test_job_detail_404(client: TestClient):
    assert client.get("/dashboard/api/jobs/does-not-exist").status_code == 404


# --------------------------- alerts index ---------------------------

def test_alerts_index(client: TestClient):
    client.post("/webhook/eset", headers=AUTH, json=_payload("dash-index-1"))
    alerts = client.get("/dashboard/api/alerts").json()["alerts"]
    assert len(alerts) >= 1
    assert {"correlation_id", "risk_level", "status"} <= set(alerts[0])


# --------------------------- AI content ---------------------------

def test_ai_content_carries_the_alert_the_assessment_was_made_from(client: TestClient):
    """
    The view must be able to show the AI's assessment against the alert it was
    given. Returning ai_output alone leaves the reader with the drafted emails
    and no way to judge whether they are supported by what the alert said.
    """
    client.post("/webhook/eset", headers=AUTH, json=_payload("dash-ai-1"))
    items = client.get("/dashboard/api/ai-content").json()["items"]
    assert len(items) >= 1

    item = items[0]
    assert {
        "correlation_id", "processed_at", "pipeline_status",
        "risk_level", "risk_rationale",
        "detection_name", "endpoint_name",
        "alert", "threat_intel", "ai_output",
    } <= set(item)

    # The deterministic risk call and its reasoning travel with the AI output.
    assert item["risk_level"]
    assert item["risk_rationale"]

    # The normalized facts, not just the two summary fields.
    assert item["alert"]["detection_name"] == "Win32/Test.Threat"
    assert item["alert"]["endpoint_name"] == "HOST-TEST-01"


def test_ai_content_exposes_the_assessment_not_only_the_drafted_emails(client: TestClient):
    """The analytical fields the Analysis panel renders must actually be present."""
    client.post("/webhook/eset", headers=AUTH, json=_payload("dash-ai-2"))
    item = client.get("/dashboard/api/ai-content").json()["items"][0]

    engineer = item["ai_output"]["engineer_notification_en"]
    assert engineer["alert_summary"]
    assert engineer["assessment"]
    for field in ("confirmed_information", "unknown_information",
                  "investigation_items", "recommended_actions"):
        assert isinstance(engineer[field], list), field


def test_ai_content_requires_the_dashboard_key(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "dashboard_access_key", "sekret")
    assert client.get("/dashboard/api/ai-content").status_code == 401
    assert client.get(
        "/dashboard/api/ai-content", headers={"X-Dashboard-Key": "sekret"}
    ).status_code == 200


# --------------------------- emails ---------------------------

def test_emails_endpoint_shape(client: TestClient):
    body = client.get("/dashboard/api/emails").json()
    assert isinstance(body["emails"], list)


def test_emails_populated_when_recipients_configured(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "client_notification_emails", "client@example.com")
    monkeypatch.setattr(settings, "cthree_notification_emails", "cthree@example.com")
    monkeypatch.setattr(settings, "internal_notification_emails", "internal@example.com")
    monkeypatch.setattr(settings, "engineer_notification_emails", "eng@example.com")

    res = client.post("/webhook/eset", headers=AUTH, json=_payload("dash-email-1"))
    cid = res.json()["correlation_id"]

    emails = client.get("/dashboard/api/emails").json()["emails"]
    mine = [e for e in emails if e["correlation_id"] == cid]
    assert len(mine) == 4
    assert {e["notification_type"] for e in mine} == {"CLIENT_JA", "CTHREE_JA", "INTERNAL_JA", "ENGINEER_EN"}
    assert all(e["status"] == "PENDING" for e in mine)
    assert all(e["to"] for e in mine)
    assert all(e["body"] for e in mine)


# --------------------------- retry ---------------------------

def test_retry_rejects_non_failed_job(client: TestClient):
    res = client.post("/webhook/eset", headers=AUTH, json=_payload("dash-retry-1"))
    cid = res.json()["correlation_id"]
    # Job completed SUCCESS via the mocked AI, so retry must be refused
    retry = client.post(f"/dashboard/api/jobs/{cid}/retry")
    assert retry.status_code == 400
    assert "FAILED/PARTIAL" in retry.json()["detail"]


def test_retry_404_for_unknown_job(client: TestClient):
    assert client.post("/dashboard/api/jobs/nope/retry").status_code == 404


@pytest.mark.asyncio
async def test_retry_reruns_failed_job(client: TestClient):
    res = client.post("/webhook/eset", headers=AUTH, json=_payload("dash-retry-2"))
    cid = res.json()["correlation_id"]

    await job_store.update_job_status(cid, "FAILED", error="simulated failure")
    retry = client.post(f"/dashboard/api/jobs/{cid}/retry")
    assert retry.status_code == 200
    assert retry.json()["status"] == "retrying"

    job = await job_store.get_job(cid)
    assert job["status"] in ("PENDING", "PROCESSING", "SUCCESS", "PARTIAL")


# --------------------------- websocket ---------------------------

def test_websocket_streams_pipeline_events(client: TestClient):
    with client.websocket_connect("/dashboard/api/ws") as ws:
        client.post("/webhook/eset", headers=AUTH, json=_payload("dash-ws-1"))
        seen = set()
        for _ in range(40):
            msg = ws.receive_json()
            seen.add(msg["type"])
            assert "data" in msg
            if "alert_completed" in seen:
                break
        assert "job_status_changed" in seen
        assert "alert_completed" in seen
        assert "pipeline_stage" in seen


def test_websocket_streams_every_pipeline_stage(client: TestClient):
    """The flow graph depends on each stage reporting in order."""
    with client.websocket_connect("/dashboard/api/ws") as ws:
        client.post("/webhook/eset", headers=AUTH, json=_payload("dash-ws-stages"))
        stages: list[tuple[str, str]] = []
        for _ in range(60):
            msg = ws.receive_json()
            if msg["type"] == "pipeline_stage":
                stages.append((msg["data"]["stage"], msg["data"]["state"]))
            if msg["type"] == "alert_completed":
                break

        reached = {s for s, _ in stages}
        assert {"INGEST", "NORMALIZE", "RISK", "INTEL", "AI", "LINT", "OUTPUT"} <= reached
        assert ("RISK", "ok") in stages
        assert ("AI", "ok") in stages
        # Stages must arrive in pipeline order
        order = [s for s, st in stages if st == "ok"]
        assert order.index("NORMALIZE") < order.index("RISK") < order.index("INTEL") < order.index("AI")


# --------------------------- test endpoints must be gone ---------------------------

def test_synthetic_alert_endpoints_removed(client: TestClient):
    assert client.post("/dashboard/api/test-alert?severity=high").status_code == 404
    assert client.post("/dashboard/api/test-syslog").status_code == 404
