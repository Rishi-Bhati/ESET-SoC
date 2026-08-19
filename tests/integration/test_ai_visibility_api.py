"""
End-to-end coverage for AI Visibility: real ingest -> real pipeline -> the real
GeminiAIService.generate() body (including instrumentation) -> the dashboard API
and WebSocket.

The autouse `mock_gemini` fixture in tests/conftest.py replaces
GeminiAIService.generate() ENTIRELY, which is exactly the method this feature
instruments — so it would never run under that mock. This module overrides that
fixture (same name, module scope, also autouse) to patch one level deeper instead:
GeminiAIService._call_gemini_with_retry(), which returns the raw SDK response object.
That means generate()'s real body — normalization of the prompt, redaction, trace
recording, the safety lint hookup — actually executes here, against a fake but
realistic SDK response, with no real network call.
"""
import pytest
from fastapi.testclient import TestClient
from src.config import settings
from src.models.ai_output import (
    AIOutput, ClientNotificationJa, CThreeNotificationJa, InternalNotificationJa, EngineerNotificationEn,
)

AUTH = {"Authorization": "Bearer test_token"}


def _payload(alert_id: str, **extra):
    base = {
        "alert_id": alert_id,
        "occurred_at": "2026-08-18T12:00:00Z",
        "severity": "HIGH",
        "detection_name": "Win32/Test.Threat",
        "endpoint_name": "HOST-TEST-01",
        "user_name": "jane.doe",
        "threat_handled": False,
        "isolation_status": False,
        "raw_content": "Detected. Internal note: password: hunter2live! must rotate.",
    }
    base.update(extra)
    return base


def _fake_ai_output(risk: str = "HIGH") -> AIOutput:
    return AIOutput(
        risk_level=risk,
        client_notification_ja=ClientNotificationJa(summary="s", current_status="c", required_confirmation="r"),
        cthree_notification_ja=CThreeNotificationJa(
            summary="s", assessment="a", front_office_notes="f", draft_client_response="d"),
        internal_notification_ja=InternalNotificationJa(
            summary="s", assessment="a", recommended_actions=["x"], draft_client_response="d"),
        engineer_notification_en=EngineerNotificationEn(
            alert_summary="s", assessment="a", confirmed_information=["c"], unknown_information=["u"],
            investigation_items=["i"], recommended_actions=["r"], draft_client_response="d",
        ),
    )


class _FakeUsage:
    def __init__(self):
        self.prompt_token_count = 123
        self.candidates_token_count = 45
        self.total_token_count = 168


class _FakeResponse:
    def __init__(self, text: str, with_usage: bool = True):
        self.text = text
        self.usage_metadata = _FakeUsage() if with_usage else None


@pytest.fixture(autouse=True)
def mock_gemini(monkeypatch):
    """Overrides the session-wide autouse mock for this module only — see module docstring."""
    from src.services.ai.gemini_service import GeminiAIService

    async def fake_call(self, prompt, generation_config):
        return _FakeResponse(_fake_ai_output().model_dump_json())

    monkeypatch.setattr(GeminiAIService, "_call_gemini_with_retry", fake_call)


# --------------------------- happy path ---------------------------

def test_successful_generation_produces_a_visible_trace(client: TestClient):
    res = client.post("/webhook/eset", headers=AUTH, json=_payload("aivis-1"))
    assert res.json()["status"] == "queued"

    traces = client.get("/dashboard/api/ai/traces").json()["traces"]
    assert len(traces) >= 1
    t = traces[0]
    assert t["provider"] == "google_gemini"
    assert t["model"] == "gemini-3.1-flash-lite"
    assert t["component"] == "pipeline.ai_generate"
    assert t["status"] == "SUCCESS"


def test_trace_detail_exposes_full_lifecycle(client: TestClient):
    client.post("/webhook/eset", headers=AUTH, json=_payload("aivis-2"))
    trace_id = client.get("/dashboard/api/ai/traces").json()["traces"][0]["trace_id"]

    detail = client.get(f"/dashboard/api/ai/traces/{trace_id}").json()["trace"]
    assert detail["objective"]
    assert detail["data_categories"], "input data must be categorized"
    assert detail["external_calls"], "the Gemini call itself must appear as an external contact"
    ext = detail["external_calls"][0]
    assert ext["service"] == "Google Generative AI (Gemini)"
    assert ext["domain"] == "generativelanguage.googleapis.com"
    assert ext["status"] == "OK"
    assert detail["output_redacted"] is not None
    assert detail["usage"] == {"prompt_tokens": 123, "output_tokens": 45, "total_tokens": 168}
    assert detail["decision_summary"]["task"]
    assert "chain-of-thought" in detail["decision_summary"]["note"]
    assert detail["tool_calls"] == []
    assert len(detail["events"]) >= 5  # started, context_collected, sensitive_data_scan, request_sent, ...
    assert detail["external_data_transfer"] is True


# --------------------------- sensitive data ---------------------------

def test_sensitive_input_is_detected_and_redacted_before_storage(client: TestClient):
    client.post("/webhook/eset", headers=AUTH, json=_payload("aivis-3"))
    trace_id = client.get("/dashboard/api/ai/traces").json()["traces"][0]["trace_id"]
    detail = client.get(f"/dashboard/api/ai/traces/{trace_id}").json()["trace"]

    raw_content = detail["input_redacted"]["normalized_alert"]["raw_content"]
    assert "hunter2live" not in raw_content
    assert "[REDACTED: SECRET]" in raw_content
    assert any(f["category"] == "GENERIC_SECRET_ASSIGNMENT" for f in detail["security_findings"])
    assert detail["risk"] == "SENSITIVE_DATA_DETECTED"

    overview = client.get("/dashboard/api/ai/overview").json()
    assert overview["security_alerts"] >= 1


# --------------------------- policy blocking (safety lint) ---------------------------

def test_lint_failure_blocks_the_trace_without_changing_pipeline_behavior(client: TestClient, monkeypatch):
    from src.services.ai.gemini_service import GeminiAIService

    async def fake_call(self, prompt, generation_config):
        blocked = _fake_ai_output()
        blocked.engineer_notification_en.assessment = "Infection confirmed on this host."
        return _FakeResponse(blocked.model_dump_json())

    monkeypatch.setattr(GeminiAIService, "_call_gemini_with_retry", fake_call)

    res = client.post("/webhook/eset", headers=AUTH, json=_payload("aivis-4"))
    cid = res.json()["correlation_id"]

    job = client.get(f"/dashboard/api/jobs/{cid}").json()["job"]
    assert job["status"] == "PARTIAL"   # existing pipeline behavior must be unchanged

    traces = client.get("/dashboard/api/ai/traces?status=BLOCKED").json()["traces"]
    mine = [t for t in traces if t["correlation_id"] == cid]
    assert len(mine) == 1
    assert mine[0]["risk"] == "BLOCKED"

    detail = client.get(f"/dashboard/api/ai/traces/{mine[0]['trace_id']}").json()["trace"]
    assert any(e["type"] == "policy_check" for e in detail["events"])
    assert any(f["category"] == "POLICY_VIOLATION" for f in detail["security_findings"])
    # the AI call itself succeeded — only the downstream policy check blocked the output
    assert detail["external_calls"][0]["status"] == "OK"


# --------------------------- provider failure ---------------------------

def test_provider_error_produces_error_trace_and_partial_job(client: TestClient, monkeypatch):
    from src.services.ai.gemini_service import GeminiAIService

    async def failing_call(self, prompt, generation_config):
        raise TimeoutError("Gemini did not respond in time")

    monkeypatch.setattr(GeminiAIService, "_call_gemini_with_retry", failing_call)

    res = client.post("/webhook/eset", headers=AUTH, json=_payload("aivis-5"))
    cid = res.json()["correlation_id"]

    job = client.get(f"/dashboard/api/jobs/{cid}").json()["job"]
    assert job["status"] == "PARTIAL"

    traces = client.get("/dashboard/api/ai/traces?status=ERROR").json()["traces"]
    mine = [t for t in traces if t["correlation_id"] == cid]
    assert len(mine) == 1
    assert mine[0]["risk"] == "ERROR"

    detail = client.get(f"/dashboard/api/ai/traces/{mine[0]['trace_id']}").json()["trace"]
    assert "Gemini did not respond" in detail["error"]
    assert detail["external_calls"][0]["status"] == "ERROR"


def test_empty_response_produces_error_trace(client: TestClient, monkeypatch):
    from src.services.ai.gemini_service import GeminiAIService

    async def empty_call(self, prompt, generation_config):
        raise ValueError("Gemini returned an empty response")

    monkeypatch.setattr(GeminiAIService, "_call_gemini_with_retry", empty_call)

    res = client.post("/webhook/eset", headers=AUTH, json=_payload("aivis-empty"))
    cid = res.json()["correlation_id"]
    job = client.get(f"/dashboard/api/jobs/{cid}").json()["job"]
    assert job["status"] == "PARTIAL"

    traces = client.get("/dashboard/api/ai/traces?status=ERROR").json()["traces"]
    assert any(t["correlation_id"] == cid for t in traces)


def test_malformed_response_produces_error_trace(client: TestClient, monkeypatch):
    from src.services.ai.gemini_service import GeminiAIService

    async def malformed_call(self, prompt, generation_config):
        return _FakeResponse("{not valid json at all")

    monkeypatch.setattr(GeminiAIService, "_call_gemini_with_retry", malformed_call)

    res = client.post("/webhook/eset", headers=AUTH, json=_payload("aivis-malformed"))
    cid = res.json()["correlation_id"]
    job = client.get(f"/dashboard/api/jobs/{cid}").json()["job"]
    assert job["status"] == "PARTIAL"

    traces = client.get("/dashboard/api/ai/traces?status=ERROR").json()["traces"]
    assert any(t["correlation_id"] == cid for t in traces)


# --------------------------- manual redaction ---------------------------

def test_manual_redaction_via_api_is_permanent(client: TestClient):
    client.post("/webhook/eset", headers=AUTH, json=_payload("aivis-6", user_name="john.smith"))
    trace_id = client.get("/dashboard/api/ai/traces").json()["traces"][0]["trace_id"]
    detail = client.get(f"/dashboard/api/ai/traces/{trace_id}").json()["trace"]

    text = detail["input_redacted"]["normalized_alert"]["endpoint_name"]
    res = client.post(f"/dashboard/api/ai/traces/{trace_id}/redact", json={
        "field_path": "input_redacted.normalized_alert.endpoint_name", "start": 0, "end": len(text),
    })
    assert res.status_code == 200
    assert "[REDACTED]" in res.json()["trace"]["input_redacted"]["normalized_alert"]["endpoint_name"]

    refetched = client.get(f"/dashboard/api/ai/traces/{trace_id}").json()["trace"]
    assert text not in str(refetched)  # the original value cannot be recovered from the API
    assert any(r["field_path"] == "input_redacted.normalized_alert.endpoint_name"
               for r in refetched["manual_redactions"])
    assert any(f["method"] == "manual" for f in refetched["security_findings"])


def test_manual_redaction_rejects_invalid_range(client: TestClient):
    client.post("/webhook/eset", headers=AUTH, json=_payload("aivis-7"))
    trace_id = client.get("/dashboard/api/ai/traces").json()["traces"][0]["trace_id"]

    res = client.post(f"/dashboard/api/ai/traces/{trace_id}/redact", json={
        "field_path": "input_redacted.normalized_alert.endpoint_name", "start": 0, "end": 99999,
    })
    assert res.status_code == 400


def test_redact_unknown_trace_returns_400(client: TestClient):
    res = client.post("/dashboard/api/ai/traces/does-not-exist/redact", json={
        "field_path": "a.b", "start": 0, "end": 1,
    })
    assert res.status_code == 400


# --------------------------- misc surface ---------------------------

def test_ai_overview_shape(client: TestClient):
    body = client.get("/dashboard/api/ai/overview").json()
    for key in ("active_requests", "requests_today", "total_traces", "security_alerts",
                "external_calls_today", "providers", "by_risk"):
        assert key in body


def test_ai_trace_detail_404_for_unknown_id(client: TestClient):
    assert client.get("/dashboard/api/ai/traces/does-not-exist").status_code == 404


def test_dashboard_key_protects_ai_routes(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "dashboard_access_key", "s3cret-key")
    assert client.get("/dashboard/api/ai/overview").status_code == 401
    assert client.get("/dashboard/api/ai/traces").status_code == 401
    assert client.get("/dashboard/api/ai/overview", headers={"X-Dashboard-Key": "s3cret-key"}).status_code == 200


# --------------------------- websocket ---------------------------

def test_websocket_streams_ai_trace_events(client: TestClient):
    with client.websocket_connect("/dashboard/api/ws") as ws:
        client.post("/webhook/eset", headers=AUTH, json=_payload("aivis-ws-1"))
        seen_types = set()
        for _ in range(60):
            msg = ws.receive_json()
            seen_types.add(msg["type"])
            if "ai_trace_completed" in seen_types:
                break
        assert "ai_trace_started" in seen_types
        assert "ai_trace_event" in seen_types
        assert "ai_trace_completed" in seen_types


# --------------------------- existing functionality is unaffected ---------------------------

def test_ai_content_and_email_composition_still_work_alongside_tracing(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "client_notification_emails", "client@example.com")
    monkeypatch.setattr(settings, "cthree_notification_emails", "")
    monkeypatch.setattr(settings, "internal_notification_emails", "")
    monkeypatch.setattr(settings, "engineer_notification_emails", "")

    res = client.post("/webhook/eset", headers=AUTH, json=_payload("aivis-8"))
    cid = res.json()["correlation_id"]

    ai_content = client.get("/dashboard/api/ai-content").json()["items"]
    assert any(i["correlation_id"] == cid for i in ai_content)

    emails = client.get("/dashboard/api/emails").json()["emails"]
    assert any(e["correlation_id"] == cid for e in emails)
