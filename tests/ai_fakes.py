"""
Test doubles for the AI layer.

FakeProvider is a real BaseAIProvider subclass: only the network call
(`_invoke`) is replaced, so prompt assembly, masking, the pinned schema,
retries, Pydantic parsing and AI Visibility tracing all run for real in every
pipeline test. Tests change what the "model" returns by setting
`FakeProvider.responder` (see conftest.py's `ai_responder` fixture).
"""
import json
from typing import Any, Callable

from src.models.ai_output import AIOutput
from src.services.ai.base import BaseAIProvider, ProviderRequest, ProviderResponse


def sample_output(risk_level: str = "HIGH", detection: str = "Win32/Test.Threat", **overrides: Any) -> AIOutput:
    data = dict(
        risk_level=risk_level,
        alert_summary_ja=f"[MOCK] {detection} が検知されました。",
        risk_reason_ja=f"ルールエンジンにより {risk_level} と判定されました。",
        client_notification_ja=f"[MOCK] {detection} の検知についてご連絡いたします。",
        internal_summary_ja=f"[MOCK] 内部向け要約: {detection}",
        engineer_summary_en=f"[MOCK] Technical summary for {detection}.",
        recommended_initial_actions_ja=["ESET PROTECT で検知内容を確認する"],
        additional_confirmation_items_ja=["端末利用者への状況確認"],
        unknown_items=["action_taken: Needs confirmation"],
        backlog_comment_ja=f"【{risk_level}】{detection} を検知。確認中。",
        email_subject_ja=f"【{risk_level}】セキュリティアラートのご報告",
        email_body_ja="お世話になっております。セキュリティアラートについてご報告いたします。",
    )
    data.update(overrides)
    return AIOutput(**data)


def prompt_data(request: ProviderRequest) -> dict[str, Any]:
    """The JSON the provider was sent, parsed back out of the fenced user prompt."""
    body = request.user_prompt.split("<<<BEGIN_UNTRUSTED_ALERT_DATA>>>\n", 1)[1]
    return json.loads(body.split("\n<<<END_UNTRUSTED_ALERT_DATA>>>", 1)[0])


def default_responder(request: ProviderRequest) -> ProviderResponse:
    risk = request.json_schema["properties"]["risk_level"]["enum"][0]
    detection = prompt_data(request)["normalized_alert"].get("detection_name", "Win32/Test.Threat")
    return ProviderResponse(
        text=sample_output(risk, detection).model_dump_json(),
        request_id="req_mock_0001", response_id="chatcmpl-mock-0001", served_model="mock-model-2026",
        usage={"prompt_tokens": 123, "output_tokens": 45, "total_tokens": 168}, finish_reason="stop",
    )


class FakeProvider(BaseAIProvider):
    provider_name = "mock"
    service_label = "Mock AI"
    api_domain = "mock.invalid"
    responder: Callable[[ProviderRequest], Any] = staticmethod(default_responder)
    requests: list[ProviderRequest] = []

    def __init__(self) -> None:
        super().__init__(model="mock-model")

    async def _invoke(self, request: ProviderRequest) -> ProviderResponse:
        FakeProvider.requests.append(request)
        result = type(self).responder(request)
        if isinstance(result, BaseException):
            raise result
        return result
