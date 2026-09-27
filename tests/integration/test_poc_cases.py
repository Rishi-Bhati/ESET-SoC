"""
The client's PoC test cases, end to end through the real pipeline (only the AI
network call is faked):

  LOW       handled low-risk detection
  MEDIUM    unclear or partially handled alert
  HIGH      malware detection not fully handled
  CRITICAL  ransomware-like behavior / multiple endpoints affected

plus the failure behavior the client specified: the AI never decides or
changes the risk level, and an AI failure still records the alert and tells
our team that the AI summary could not be generated.

Fixtures: tests/fixtures/poc_cases/*.json. To run the same cases against the
real OpenAI API, see scripts/run_poc_cases.py.
"""
import json
import os

import pytest
from fastapi.testclient import TestClient

from src.config import settings
from src.services.ai.base import AIOutputRejected, ProviderResponse
from ai_fakes import FakeProvider, prompt_data, sample_output

AUTH = {"Authorization": "Bearer test_token"}
CASES_DIR = os.path.join(os.path.dirname(__file__), "..", "fixtures", "poc_cases")


def load_case(name: str) -> dict:
    with open(os.path.join(CASES_DIR, f"{name}.json"), encoding="utf-8") as f:
        payload = json.load(f)
    # "_poc_case" documents the fixture; it is not part of an ESET payload.
    return {k: v for k, v in payload.items() if not k.startswith("_")}


def run(client: TestClient, payload: dict) -> dict:
    res = client.post("/webhook/eset", headers=AUTH, json=payload)
    assert res.status_code == 200, res.text
    cid = res.json()["correlation_id"]
    body = client.get(f"/dashboard/api/jobs/{cid}").json()
    return {"job": body["job"], "result": body["result"], "cid": cid}


@pytest.fixture
def recipients(monkeypatch):
    monkeypatch.setattr(settings, "client_notification_emails", "client@example.com")
    monkeypatch.setattr(settings, "cthree_notification_emails", "cthree@example.com")
    monkeypatch.setattr(settings, "internal_notification_emails", "internal@example.com")
    monkeypatch.setattr(settings, "engineer_notification_emails", "eng@example.com")


@pytest.mark.parametrize("case, expected_level, deciding_rule", [
    ("low_handled_detection", "LOW", "severity_low_handled"),
    ("medium_partially_handled", "MEDIUM", "severity_medium_unhandled"),
    ("high_malware_not_handled", "HIGH", "severity_high_unhandled"),
    ("critical_ransomware_behavior", "CRITICAL", "ransomware_indicator"),
    ("critical_multiple_endpoints", "CRITICAL", "multiple_endpoints_reported"),
])
def test_poc_case_risk_level_is_decided_by_rules(client: TestClient, case, expected_level, deciding_rule):
    out = run(client, load_case(case))
    result = out["result"]

    assert out["job"]["status"] == "SUCCESS"
    assert result["risk_level"] == expected_level
    assert deciding_rule in [f["rule"] for f in result["risk_factors"] if f["effect"] in ("base", "raised")]

    # The AI received the level as an input and could only echo it back.
    request = FakeProvider.requests[-1]
    assert prompt_data(request)["predefined_risk"]["level"] == expected_level
    assert request.json_schema["properties"]["risk_level"]["enum"] == [expected_level]
    assert result["ai_output"]["risk_level"] == expected_level

    # Audit record: normalized alert, risk, AI request ID, AI output.
    assert result["normalized_alert"]["alert_id"] == load_case(case)["alert_id"]
    assert result["ai_run"]["request_id"] == "req_mock_0001"
    assert result["ai_run"]["prompt_version"]


def test_same_detection_on_several_endpoints_escalates_to_critical(client: TestClient):
    base = load_case("medium_partially_handled")
    levels = []
    for i, host in enumerate(("MAC-PC-101", "MAC-PC-102", "MAC-PC-103")):
        levels.append(run(client, {**base, "alert_id": f"spread-{i}", "endpoint_name": host})["result"]["risk_level"])
    assert levels == ["MEDIUM", "MEDIUM", "CRITICAL"]


def test_successful_alert_notifies_all_four_audiences(client: TestClient, recipients):
    out = run(client, load_case("high_malware_not_handled"))
    kinds = {n["notification_type"]: n for n in out["result"]["notifications"]}
    assert set(kinds) == {"CLIENT_JA", "CTHREE_JA", "INTERNAL_JA", "ENGINEER_EN"}
    assert all(n["kind"] == "ai_generated" for n in kinds.values())

    emails = {e["notification_type"]: e for e in client.get("/dashboard/api/emails").json()["emails"]
              if e["correlation_id"] == out["cid"]}
    assert emails["CLIENT_JA"]["subject"].startswith("【HIGH】")


def test_ai_failure_still_records_the_alert_and_notifies_the_team(client: TestClient, recipients, ai_responder):
    ai_responder(lambda request: TimeoutError("no response"))
    out = run(client, load_case("critical_ransomware_behavior"))
    result = out["result"]

    assert out["job"]["status"] == "PARTIAL"
    assert result["risk_level"] == "CRITICAL", "the rule-based decision survives an AI outage"
    assert result["ai_output"] is None
    assert result["ai_run"]["status"] == "FAILED"
    assert result["ai_run"]["error_type"] == "Timeout"
    assert result["ai_run"]["attempts"] == settings.ai_max_attempts, "bounded retries were used"

    kinds = {n["notification_type"]: n for n in result["notifications"]}
    assert set(kinds) == {"INTERNAL_JA", "ENGINEER_EN"}, "nothing goes to the client without the AI draft"
    assert all(n["kind"] == "ai_fallback" for n in kinds.values())
    emails = [e for e in client.get("/dashboard/api/emails").json()["emails"] if e["correlation_id"] == out["cid"]]
    assert all("[AI要約生成失敗]" in e["subject"] for e in emails)


def test_misconfigured_provider_is_handled_like_any_other_ai_failure(client: TestClient, recipients, monkeypatch):
    from src.services.ai import factory as ai_factory
    from src.services.ai.base import AIConfigurationError

    def broken():
        raise AIConfigurationError("OPENAI_MODEL is not set")
    monkeypatch.setattr(ai_factory, "get_ai_provider", broken)
    out = run(client, load_case("low_handled_detection"))
    assert out["job"]["status"] == "PARTIAL"
    assert out["result"]["ai_run"]["error_type"] == "ConfigurationError"
    assert {n["notification_type"] for n in out["result"]["notifications"]} == {"INTERNAL_JA", "ENGINEER_EN"}


def test_output_with_a_changed_risk_level_is_blocked(client: TestClient, recipients, ai_responder):
    # A provider without strict schema support could return another level; the
    # validator must catch it even though the schema pin normally prevents it.
    ai_responder(lambda request: ProviderResponse(text=sample_output("LOW").model_dump_json(), request_id="req_x"))
    out = run(client, load_case("high_malware_not_handled"))
    result = out["result"]
    assert out["job"]["status"] == "PARTIAL"
    assert result["risk_level"] == "HIGH"
    assert result["ai_output"] is None
    assert result["ai_run"]["status"] == "BLOCKED"
    assert any("risk_level_modified" in i for i in result["ai_run"]["validation_issues"])
    assert {n["kind"] for n in result["notifications"]} == {"ai_fallback"}


def test_output_claiming_the_environment_is_safe_is_blocked(client: TestClient, ai_responder):
    ai_responder(lambda request: ProviderResponse(
        text=sample_output("LOW", client_notification_ja="駆除が完了し、環境は安全です。").model_dump_json()))
    out = run(client, load_case("low_handled_detection"))
    assert out["job"]["status"] == "PARTIAL"
    assert "prohibited_phrase: 環境は安全です" in out["result"]["ai_run"]["validation_issues"]


def test_truncated_output_is_a_recorded_failure(client: TestClient, ai_responder):
    ai_responder(lambda request: AIOutputRejected("Output was cut off at AI_MAX_OUTPUT_TOKENS=16000"))
    out = run(client, load_case("medium_partially_handled"))
    assert out["job"]["status"] == "PARTIAL"
    assert out["result"]["ai_run"]["attempts"] == 1, "a truncated answer is not retried"


def test_simulated_threat_intel_never_changes_the_risk_level(client: TestClient, monkeypatch):
    # The mock marks any indicator containing "malicious" as MALICIOUS.
    payload = {**load_case("medium_partially_handled"), "url": "http://malicious.example/x.js"}
    monkeypatch.setattr(settings, "use_mock_threat_intel", True)
    out = run(client, {**payload, "alert_id": "ti-mock"})
    assert out["result"]["threat_intel"]["virustotal"]["status"] == "MALICIOUS"
    assert out["result"]["risk_level"] == "MEDIUM"


def test_real_threat_intel_raises_the_risk_level(client: TestClient, monkeypatch):
    from src.models.threat_intel import ThreatIntelResult, VirusTotalResult
    from src.pipeline import orchestrator

    async def real_lookup(alert):
        return ThreatIntelResult(virustotal=VirusTotalResult(status="MALICIOUS", positives=40, total=70))
    monkeypatch.setattr(settings, "use_mock_threat_intel", False)
    monkeypatch.setattr(orchestrator, "gather_threat_intel", real_lookup)
    out = run(client, {**load_case("medium_partially_handled"), "alert_id": "ti-real"})
    assert out["result"]["risk_level"] == "HIGH"
    assert "threat_intel_malicious" in [f["rule"] for f in out["result"]["risk_factors"]]
