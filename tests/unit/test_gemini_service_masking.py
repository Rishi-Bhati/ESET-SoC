"""
Verifies two things the mocked `mock_gemini` autouse fixture (see conftest.py)
cannot exercise, because it replaces GeminiAIService.generate() wholesale:

1. Pre-AI masking (src/services/ai/prompt_masking.py) is actually applied to the
   text sent to the model, not just implemented and unused.
2. The system prompt actually contains the untrusted-input / prompt-injection
   framing added alongside the masking work.

Both tests call the real GeminiAIService.generate() with only the outbound network
call (_call_gemini_with_retry) replaced, so everything in between — masking,
prompt assembly, schema validation, AI Visibility tracing — runs for real.
"""
from src.models.ai_output import (
    AIOutput, ClientNotificationJa, CThreeNotificationJa,
    InternalNotificationJa, EngineerNotificationEn,
)
from src.models.normalized_alert import NormalizedAlert
from src.models.threat_intel import AbuseIPDBResult, ThreatIntelResult, VirusTotalResult
from src.prompts.system_prompts import SYSTEM_PROMPT
from src.services.ai.gemini_service import GeminiAIService

# conftest.py's autouse `mock_gemini` fixture replaces GeminiAIService.generate
# wholesale for every test in the suite (so no test accidentally calls the real
# Gemini API). Captured here, at module-import time — before that fixture ever
# runs — so these tests can restore the real implementation and exercise the
# actual masking/prompt-assembly logic instead of the mock.
_REAL_GENERATE = GeminiAIService.generate


def _sample_alert(**overrides) -> NormalizedAlert:
    data = dict(
        source="ESET_PROTECT_CLOUD",
        event_type="Threat Detection",
        alert_id="alert-mask-1",
        detection_uuid="UNKNOWN",
        target_uuid="UNKNOWN",
        occurred_at="2026-01-01T00:00:00Z",
        severity="HIGH",
        detection_name="Win32/TrojanDownloader.Agent.YHV",
        endpoint_name="FINANCE-PC-09",
        endpoint_type="Server",
        user_name="charlie.brown",
        os_name="Windows Server 2022",
        action_taken="Connection terminated",
        threat_handled="false",
        isolation_status="false",
        object_type="Process",
        object_uri=r"C:\Users\charlie.brown\AppData\Local\Temp\evil.exe",
        file_hash="UNKNOWN",
        url="UNKNOWN",
        ip_address="UNKNOWN",
        domain="UNKNOWN",
        raw_subject="Alert",
        raw_content="content",
    )
    data.update(overrides)
    return NormalizedAlert(**data)


def _fake_ai_output(risk_level: str) -> AIOutput:
    return AIOutput(
        risk_level=risk_level,
        client_notification_ja=ClientNotificationJa(summary="s", current_status="c", required_confirmation="r"),
        cthree_notification_ja=CThreeNotificationJa(
            summary="s", assessment="a", front_office_notes="f", draft_client_response="d",
        ),
        internal_notification_ja=InternalNotificationJa(
            summary="s", assessment="a", recommended_actions=[], draft_client_response="d",
        ),
        engineer_notification_en=EngineerNotificationEn(
            alert_summary="s", assessment="a", confirmed_information=[], unknown_information=[],
            investigation_items=[], recommended_actions=[], draft_client_response="d",
        ),
    )


class _FakeGeminiResponse:
    def __init__(self, text: str) -> None:
        self.text = text
        self.usage_metadata = None


async def test_gemini_prompt_masks_user_name_and_username_path_segment(monkeypatch):
    monkeypatch.setattr(GeminiAIService, "generate", _REAL_GENERATE)

    captured: dict = {}

    async def fake_call(self, prompt, generation_config):
        captured["prompt"] = prompt
        return _FakeGeminiResponse(_fake_ai_output("HIGH").model_dump_json())

    monkeypatch.setattr(GeminiAIService, "_call_gemini_with_retry", fake_call)

    service = GeminiAIService()
    intel = ThreatIntelResult(virustotal=VirusTotalResult(status="UNKNOWN"), abuseipdb=AbuseIPDBResult(status="UNKNOWN"))
    alert = _sample_alert()

    await service.generate(alert, "HIGH", intel)

    prompt = captured["prompt"]
    assert "charlie.brown" not in prompt, "raw user_name must not reach the AI prompt"
    assert "evil.exe" in prompt, "filename (the useful triage signal) must be preserved"
    assert "FINANCE-PC-09" in prompt, "endpoint_name is needed for triage and must remain unmasked"


async def test_gemini_prompt_masking_can_be_disabled_via_config(monkeypatch):
    monkeypatch.setattr(GeminiAIService, "generate", _REAL_GENERATE)

    from src.config import settings
    monkeypatch.setattr(settings, "ai_masking_enabled", False)

    captured: dict = {}

    async def fake_call(self, prompt, generation_config):
        captured["prompt"] = prompt
        return _FakeGeminiResponse(_fake_ai_output("HIGH").model_dump_json())

    monkeypatch.setattr(GeminiAIService, "_call_gemini_with_retry", fake_call)

    service = GeminiAIService()
    intel = ThreatIntelResult(virustotal=VirusTotalResult(status="UNKNOWN"), abuseipdb=AbuseIPDBResult(status="UNKNOWN"))
    alert = _sample_alert()

    await service.generate(alert, "HIGH", intel)

    assert "charlie.brown" in captured["prompt"]


def test_system_prompt_frames_alert_content_as_untrusted_data():
    lowered = SYSTEM_PROMPT.lower()
    assert "untrusted" in lowered
    assert "instruction" in lowered
    # Must name at least the highest-risk attacker-controlled fields explicitly.
    for field in ("detection_name", "raw_content", "raw_subject"):
        assert field in SYSTEM_PROMPT
