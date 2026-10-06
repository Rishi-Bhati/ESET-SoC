"""
An ESET alert carries only some fields, and only those may appear downstream:
in the normalized record, the AI prompt, the notification emails, the result
file and the dashboard API. Nothing the raw request did not contain may be
filled in as "UNKNOWN", "Unknown", "N/A", "false" or similar.

Runs the real webhook route and pipeline; only the AI network call is faked
(tests/ai_fakes.py).
"""
import json
import os

import pytest
from fastapi.testclient import TestClient

from src.config import settings
from src.storage import job_store
from ai_fakes import FakeProvider, prompt_data

AUTH = {"Authorization": "Bearer test_token"}

# A deliberately small alert: three fields, nothing about handling, isolation,
# the endpoint, the user or any indicator.
MINIMAL_PAYLOAD = {
    "detection_name": "Win32/Agent.MINIMAL",
    "severity": "HIGH",
    "occurred_at": "2026-10-01T09:00:00Z",
}
REPORTED = {"detection_name", "severity", "occurred_at"}
ABSENT = ("endpoint_name", "endpoint_type", "user_name", "os_name", "action_taken",
          "threat_handled", "isolation_status", "object_type", "object_uri",
          "file_hash", "url", "ip_address", "domain", "raw_subject", "raw_content")
PLACEHOLDERS = ("UNKNOWN", "Unknown", "unknown", "N/A", "不明")


@pytest.fixture
def recipients(monkeypatch):
    monkeypatch.setattr(settings, "client_notification_emails", "client@example.com")
    monkeypatch.setattr(settings, "cthree_notification_emails", "cthree@example.com")
    monkeypatch.setattr(settings, "internal_notification_emails", "internal@example.com")
    monkeypatch.setattr(settings, "engineer_notification_emails", "eng@example.com")


def _ingest(client: TestClient, payload: dict) -> tuple[str, dict]:
    res = client.post("/webhook/eset", headers=AUTH, json=payload)
    assert res.status_code == 200, res.text
    cid = res.json()["correlation_id"]
    return cid, client.get(f"/dashboard/api/jobs/{cid}").json()["result"]


def _emails(client: TestClient, cid: str) -> dict[str, dict]:
    return {e["notification_type"]: e for e in client.get("/dashboard/api/emails").json()["emails"]
            if e["correlation_id"] == cid}


def test_minimal_alert_carries_only_its_own_fields_end_to_end(client: TestClient, recipients):
    cid, result = _ingest(client, MINIMAL_PAYLOAD)
    assert result["pipeline_status"] == "SUCCESS"

    # Result file / dashboard API: only the reported fields (+ the ingest route).
    alert = result["normalized_alert"]
    assert set(alert) - {"raw_payload"} == REPORTED | {"source"}
    assert all(field not in alert for field in ABSENT)
    with open(os.path.join(settings.output_dir, f"{cid}.json"), encoding="utf-8") as f:
        persisted = json.load(f)["normalized_alert"]
    assert set(persisted) - {"raw_payload"} == REPORTED | {"source"}

    # The stored job (the pipeline's input, shown on the dashboard) has no
    # null-filled fields either; the original JSON is kept verbatim.
    job = client.get(f"/dashboard/api/jobs/{cid}").json()["job"]
    assert set(job["raw_payload"]) - {"raw_payload", "source"} == REPORTED
    assert job["raw_payload"]["raw_payload"] == MINIMAL_PAYLOAD

    # Risk scoring still works: a missing threat_handled is neutral, and the
    # rationale does not present it as an "unknown" field.
    assert result["risk_level"] == "HIGH"
    assert "unknown" not in result["risk_rationale"].lower()

    # AI prompt: only the reported fields, no "missing fields" list, and no
    # threat-intel block when the alert gave nothing to look up.
    request = FakeProvider.requests[-1]
    data = prompt_data(request)
    assert set(data["normalized_alert"]) == REPORTED | {"source"}
    assert "unknown_fields" not in data and "threat_intelligence" not in data
    for placeholder in PLACEHOLDERS:
        assert placeholder not in request.user_prompt, placeholder
    for field in ABSENT:
        assert field not in request.user_prompt, field

    # Emails: no row or section for anything the alert did not report.
    emails = _emails(client, cid)
    assert set(emails) == {"CLIENT_JA", "CTHREE_JA", "INTERNAL_JA", "ENGINEER_EN"}
    for email in emails.values():
        for placeholder in PLACEHOLDERS:
            assert placeholder not in email["body"], (email["notification_type"], placeholder)
            assert placeholder not in email["subject"], (email["notification_type"], placeholder)
        assert email["endpoint_name"] is None
    assert emails["ENGINEER_EN"]["subject"] == "[HIGH] Win32/Agent.MINIMAL"


def test_minimal_alert_fallback_email_lists_only_reported_facts(client: TestClient, recipients, ai_responder):
    ai_responder(lambda request: TimeoutError("no response"))
    cid, result = _ingest(client, MINIMAL_PAYLOAD)
    assert result["pipeline_status"] == "PARTIAL"

    emails = _emails(client, cid)
    assert set(emails) == {"INTERNAL_JA", "ENGINEER_EN"}
    engineer = emails["ENGINEER_EN"]["body"]
    facts = engineer.split("ALERT FACTS:\n", 1)[1].split("\n\n", 1)[0].splitlines()
    assert facts == [
        "- Detection: Win32/Agent.MINIMAL",
        "- Occurred at: 2026-10-01T09:00:00Z",
        "- ESET severity: HIGH",
    ]
    for email in emails.values():
        for placeholder in ("UNKNOWN", "Unknown", "N/A", "不明", "Threat handled", "Isolated"):
            assert placeholder not in email["body"], (email["notification_type"], placeholder)


def test_reported_false_is_kept_distinct_from_absent(client: TestClient, recipients):
    cid, result = _ingest(client, {**MINIMAL_PAYLOAD, "threat_handled": False})
    alert = result["normalized_alert"]
    assert alert["threat_handled"] == "false"
    assert "isolation_status" not in alert
    assert prompt_data(FakeProvider.requests[-1])["normalized_alert"]["threat_handled"] == "false"


@pytest.mark.asyncio
async def test_dashboard_drops_placeholders_from_result_files_written_before_the_fix(client: TestClient):
    # A result file in the old format: every field present, absent ones "UNKNOWN".
    cid = "legacy-unknown-fields"
    legacy_alert = {field: "UNKNOWN" for field in ABSENT + ("event_type", "alert_id", "detection_uuid", "target_uuid")}
    legacy_alert.update(source="WEBHOOK", detection_name="Win32/Legacy", severity="HIGH",
                        occurred_at="2026-01-01T00:00:00Z", raw_payload={"detection_name": "Win32/Legacy"})
    legacy = {
        "correlation_id": cid, "source": "WEBHOOK", "received_at": "2026-01-01T00:00:00Z",
        "processed_at": "2026-01-01T00:00:01Z", "pipeline_status": "SUCCESS",
        "normalized_alert": legacy_alert, "risk_level": "HIGH", "risk_rationale": "r",
        "ai_output": {"alert_summary_ja": "x"},
    }
    with open(os.path.join(settings.output_dir, f"{cid}.json"), "w", encoding="utf-8") as f:
        json.dump(legacy, f)
    with open(os.path.join(settings.output_dir, "index.json"), "w", encoding="utf-8") as f:
        json.dump([{"correlation_id": cid, "risk_level": "HIGH", "status": "SUCCESS"}], f)
    await job_store.create_job(cid, "WEBHOOK", {"detection_name": "Win32/Legacy"})

    alert = client.get(f"/dashboard/api/jobs/{cid}").json()["result"]["normalized_alert"]
    assert "UNKNOWN" not in json.dumps(alert)
    assert alert["detection_name"] == "Win32/Legacy" and alert["raw_payload"] == {"detection_name": "Win32/Legacy"}

    item = client.get("/dashboard/api/ai-content").json()["items"][0]
    assert "UNKNOWN" not in json.dumps(item["alert"])
    assert item["endpoint_name"] is None
