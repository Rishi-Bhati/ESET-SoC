import json
import pytest
from fastapi.testclient import TestClient
from src.config import settings
from src.storage import job_store

def test_webhook_unauthorized(client: TestClient):
    # Missing header
    response = client.post("/webhook/eset", json={})
    assert response.status_code == 401
    
    # Wrong token
    response = client.post(
        "/webhook/eset", 
        headers={"Authorization": "Bearer wrong_token"}, 
        json={}
    )
    assert response.status_code == 401

def test_webhook_success_and_status(client: TestClient):
    headers = {"Authorization": "Bearer test_token"}
    payload = {
        "alert_id": "test-webhook-alert-99",
        "occurred_at": "2026-08-10T12:00:00Z",
        "severity": "HIGH",
        "detection_name": "Test malware",
        "endpoint_name": "WORKSTATION-X"
    }
    
    # 1. Post to webhook
    response = client.post("/webhook/eset", headers=headers, json=payload)
    assert response.status_code == 200  # FastAPI defaults 200, returns queued status
    data = response.json()
    assert data["status"] == "queued"
    correlation_id = data["correlation_id"]
    assert correlation_id is not None
    
    # 2. Check job created in SQLite database
    # Since background tasks are run synchronously in test client, it might be SUCCESS or PROCESSING
    response_status = client.get(f"/status/{correlation_id}")
    assert response_status.status_code == 200
    status_data = response_status.json()
    assert status_data["correlation_id"] == correlation_id
    assert status_data["status"] in ("PENDING", "PROCESSING", "SUCCESS")
    
    # 3. Check duplicate submission
    response_dup = client.post("/webhook/eset", headers=headers, json=payload)
    assert response_dup.status_code == 200
    dup_data = response_dup.json()
    assert dup_data["status"] == "duplicate"


def test_webhook_rejects_oversized_payload(client: TestClient, monkeypatch):
    """MAX_INGEST_BODY_BYTES is enforced before the body is parsed (413, not 200)."""
    monkeypatch.setattr(settings, "max_ingest_body_bytes", 10)
    headers = {"Authorization": "Bearer test_token"}
    payload = {"alert_id": "too-big-for-the-limit", "occurred_at": "2026-01-01T00:00:00Z", "severity": "LOW"}

    response = client.post("/webhook/eset", headers=headers, json=payload)
    assert response.status_code == 413

    response = client.post("/webhook/syslog", headers=headers, json=payload)
    assert response.status_code == 413


def test_webhook_accepts_payload_within_default_limit(client: TestClient):
    """The default 1 MiB limit does not interfere with a normal-sized alert."""
    headers = {"Authorization": "Bearer test_token"}
    payload = {"alert_id": "normal-size-1", "occurred_at": "2026-01-01T00:00:00Z", "severity": "LOW"}
    response = client.post("/webhook/eset", headers=headers, json=payload)
    assert response.status_code == 200
    assert response.json()["status"] == "queued"


# ---------------------------------------------------------------------------
# Unencodable alert content
# ---------------------------------------------------------------------------

def test_scrub_unencodable_replaces_lone_surrogates():
    """
    json.loads accepts a lone surrogate, but anything durable (the SQLite bind
    in delivery_store, the compact-JSON body of an outbound email) raises
    UnicodeEncodeError on it. Scrubbing at ingest keeps such a payload from
    reaching a stage that persists it and then fails on it forever.
    """
    from src.api.webhook import scrub_unencodable

    scrubbed = scrub_unencodable({
        "threat_name": "Win32/\ud800Agent",
        "nested": {"path": "C:\\\\Users\\\\\ud800x\\\\bad.exe"},
        "list": ["ok", "bad\udfff"],
        "number": 42,
        "null": None,
    })

    # Everything now survives the encodings the pipeline actually performs.
    import json as _json
    _json.dumps(scrubbed, ensure_ascii=False).encode("utf-8")

    assert "\ud800" not in scrubbed["threat_name"]
    assert scrubbed["threat_name"].startswith("Win32/")
    assert scrubbed["number"] == 42
    assert scrubbed["null"] is None


def test_webhook_accepts_a_payload_carrying_a_lone_surrogate(client):
    """A crafted detection name must not 500 or wedge anything downstream."""
    body = '{"threat_name": "Win32/\\ud800Agent", "computer_name": "WKS-01", ' \
           '"severity": "HIGH", "threat_handled": true}'
    response = client.post(
        "/webhook/eset",
        content=body.encode("utf-8"),
        headers={"Authorization": "test_token", "Content-Type": "application/json"},
    )
    assert response.status_code in (200, 202), response.text
