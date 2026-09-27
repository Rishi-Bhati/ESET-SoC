"""
OpenAIProvider against a fake SDK client: the request it builds, what it
records, which failures it retries, and that no credential leaks into errors.
"""
from types import SimpleNamespace

import httpx
import openai
import pytest

from src.config import settings
from src.models.normalized_alert import NormalizedAlert
from src.models.threat_intel import ThreatIntelResult
from src.services import secrets
from src.services.ai import openai_provider
from src.services.ai.base import AIConfigurationError, AIGenerationError
from src.services.ai.openai_provider import AzureOpenAIProvider, OpenAIProvider
from ai_fakes import sample_output

FAKE_KEY = "sk-proj-THISISAFAKEKEYFORTESTS_abcdefghijklmnop1234"


def _completion(text: str, finish_reason: str = "stop", refusal=None):
    completion = SimpleNamespace(
        id="chatcmpl-abc123", model="gpt-test-2026-01-01",
        choices=[SimpleNamespace(finish_reason=finish_reason,
                                 message=SimpleNamespace(content=text, refusal=refusal))],
        usage=SimpleNamespace(prompt_tokens=900, completion_tokens=700, total_tokens=1600,
                              completion_tokens_details=SimpleNamespace(reasoning_tokens=128)),
    )
    completion._request_id = "req_0123456789"
    return completion


def _status_error(cls, status: int, message: str, code: str | None = None):
    request = httpx.Request("POST", "https://api.openai.com/v1/chat/completions")
    response = httpx.Response(status, request=request, headers={"x-request-id": "req_err_42"})
    return cls(message, response=response, body={"code": code, "message": message} if code else None)


class FakeClient:
    """Stands in for openai.AsyncOpenAI. `script` is consumed one item per call:
    an exception instance is raised, anything else is returned."""

    def __init__(self, script):
        self.script = list(script)
        self.calls: list[dict] = []
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))
        self.models = SimpleNamespace(retrieve=self._retrieve)

    async def _create(self, **kwargs):
        self.calls.append(kwargs)
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    async def _retrieve(self, model):
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


@pytest.fixture(autouse=True)
def openai_settings(monkeypatch):
    monkeypatch.setattr(settings, "ai_provider", "openai")
    monkeypatch.setattr(settings, "openai_model", "gpt-test")
    monkeypatch.setattr(settings, "openai_api_key", FAKE_KEY)
    monkeypatch.setattr(settings, "openai_api_key_secret_id", "")
    monkeypatch.setattr(settings, "openai_temperature", "")
    monkeypatch.setattr(settings, "openai_reasoning_effort", "")
    monkeypatch.setattr(settings, "ai_max_attempts", 3)
    openai_provider._clients.clear()
    secrets.clear_cache()
    yield
    openai_provider._clients.clear()
    secrets.clear_cache()


@pytest.fixture
def fake_client(monkeypatch):
    holder = {}

    def install(script):
        client = FakeClient(script)
        built_with = []

        def new_client(self, api_key):
            built_with.append(api_key)
            return client
        monkeypatch.setattr(OpenAIProvider, "_new_client", new_client)
        holder["client"], holder["keys"] = client, built_with
        return client
    install.holder = holder
    return install


async def _generate(risk="HIGH"):
    alert = NormalizedAlert(severity=risk, detection_name="Win32/Test.A", endpoint_name="PC-1", user_name="taro")
    return await OpenAIProvider().generate(alert, risk, ThreatIntelResult(), risk_rationale="because")


async def test_request_uses_strict_schema_with_pinned_risk_and_no_storage(fake_client):
    client = fake_client([_completion(sample_output("HIGH").model_dump_json())])
    await _generate("HIGH")

    kwargs = client.calls[0]
    assert kwargs["model"] == "gpt-test"
    assert kwargs["store"] is False
    assert kwargs["max_completion_tokens"] == settings.ai_max_output_tokens
    fmt = kwargs["response_format"]
    assert fmt["type"] == "json_schema" and fmt["json_schema"]["strict"] is True
    assert fmt["json_schema"]["schema"]["properties"]["risk_level"]["enum"] == ["HIGH"]
    assert [m["role"] for m in kwargs["messages"]] == ["system", "user"]
    # Not sent unless configured: several current models reject a non-default temperature.
    assert "temperature" not in kwargs and "reasoning_effort" not in kwargs
    assert "taro" not in kwargs["messages"][1]["content"], "user name must be masked"


async def test_optional_tuning_is_sent_when_configured(fake_client, monkeypatch):
    monkeypatch.setattr(settings, "openai_temperature", "0.2")
    monkeypatch.setattr(settings, "openai_reasoning_effort", "low")
    client = fake_client([_completion(sample_output("HIGH").model_dump_json())])
    await _generate("HIGH")
    assert client.calls[0]["temperature"] == 0.2
    assert client.calls[0]["reasoning_effort"] == "low"


async def test_success_records_request_ids_and_usage_for_audit(fake_client):
    fake_client([_completion(sample_output("MEDIUM").model_dump_json())])
    result = await _generate("MEDIUM")
    meta = result.metadata
    assert result.output.risk_level == "MEDIUM"
    assert meta.status == "SUCCESS" and meta.provider == "openai" and meta.model == "gpt-test"
    assert meta.request_id == "req_0123456789"
    assert meta.response_id == "chatcmpl-abc123"
    assert meta.served_model == "gpt-test-2026-01-01"
    assert meta.usage["reasoning_tokens"] == 128
    assert meta.attempts == 1


async def test_transient_errors_are_retried_a_bounded_number_of_times(fake_client):
    client = fake_client([
        _status_error(openai.RateLimitError, 429, "slow down", code="rate_limit_exceeded"),
        _status_error(openai.InternalServerError, 500, "oops"),
        _completion(sample_output("HIGH").model_dump_json()),
    ])
    result = await _generate("HIGH")
    assert result.metadata.attempts == 3
    assert len(client.calls) == 3


async def test_retries_stop_at_ai_max_attempts(fake_client, monkeypatch):
    monkeypatch.setattr(settings, "ai_max_attempts", 2)
    client = fake_client([_status_error(openai.InternalServerError, 503, "down")] * 5)
    with pytest.raises(AIGenerationError) as exc_info:
        await _generate()
    assert len(client.calls) == 2
    meta = exc_info.value.metadata
    assert meta.status == "FAILED" and meta.attempts == 2
    assert meta.request_id == "req_err_42"


async def test_attempts_are_hard_capped_even_if_misconfigured(fake_client, monkeypatch):
    monkeypatch.setattr(settings, "ai_max_attempts", 1000)
    client = fake_client([_status_error(openai.InternalServerError, 503, "down")] * 20)
    with pytest.raises(AIGenerationError):
        await _generate()
    assert len(client.calls) == 5


@pytest.mark.parametrize("error", [
    _status_error(openai.BadRequestError, 400, "Unsupported parameter: 'temperature'"),
    _status_error(openai.NotFoundError, 404, "model not found"),
    _status_error(openai.RateLimitError, 429, "You exceeded your current quota", code="insufficient_quota"),
])
async def test_permanent_errors_are_not_retried(fake_client, error):
    client = fake_client([error, _completion(sample_output("HIGH").model_dump_json())])
    with pytest.raises(AIGenerationError):
        await _generate()
    assert len(client.calls) == 1


async def test_auth_error_never_leaks_the_key(fake_client):
    leaky = _status_error(openai.AuthenticationError, 401,
                          f"Incorrect API key provided: {FAKE_KEY[:12]}****{FAKE_KEY[-4:]}", code="invalid_api_key")
    fake_client([leaky])
    with pytest.raises(AIGenerationError) as exc_info:
        await _generate()
    meta = exc_info.value.metadata
    dumped = meta.model_dump_json() + str(exc_info.value)
    assert "sk-" not in dumped and FAKE_KEY[-4:] not in dumped
    assert meta.error_type == "AuthenticationError"
    assert "HTTP 401 (invalid_api_key)" in meta.error


async def test_rotated_secrets_manager_key_is_reread_once_after_401(fake_client, monkeypatch):
    monkeypatch.setattr(settings, "openai_api_key", "")
    monkeypatch.setattr(settings, "openai_api_key_secret_id", "eset-soc-lite/poc/openai-api-key")
    reads = iter(["sk-old-key-000000000000000000", "sk-new-key-111111111111111111"])
    monkeypatch.setattr(secrets, "fetch_secret_string", lambda secret_id: next(reads))
    fake_client([
        _status_error(openai.AuthenticationError, 401, "bad key", code="invalid_api_key"),
        _completion(sample_output("HIGH").model_dump_json()),
    ])
    result = await _generate()
    assert result.metadata.status == "SUCCESS"
    assert fake_client.holder["keys"] == ["sk-old-key-000000000000000000", "sk-new-key-111111111111111111"]


async def test_truncated_output_fails_without_retry(fake_client):
    client = fake_client([_completion('{"risk_level": "HIGH", "alert_sum', finish_reason="length")] * 3)
    with pytest.raises(AIGenerationError) as exc_info:
        await _generate()
    assert len(client.calls) == 1
    assert "AI_MAX_OUTPUT_TOKENS" in exc_info.value.metadata.error


async def test_refusal_is_a_failure(fake_client):
    fake_client([_completion(None, refusal="I can't help with that")])
    with pytest.raises(AIGenerationError) as exc_info:
        await _generate()
    assert exc_info.value.metadata.error_type == "OutputRejected"


async def test_schema_mismatch_is_a_failure_with_field_locations(fake_client):
    fake_client([_completion('{"risk_level": "HIGH"}')])
    with pytest.raises(AIGenerationError) as exc_info:
        await _generate()
    meta = exc_info.value.metadata
    assert meta.error_type == "SchemaValidationError"
    assert "alert_summary_ja" in meta.error


def test_missing_model_is_a_configuration_error(monkeypatch):
    monkeypatch.setattr(settings, "openai_model", "")
    with pytest.raises(AIConfigurationError, match="OPENAI_MODEL"):
        OpenAIProvider()


async def test_missing_key_is_a_configuration_failure_not_a_crash(monkeypatch):
    monkeypatch.setattr(settings, "openai_api_key", "")
    with pytest.raises(AIGenerationError) as exc_info:
        await _generate()
    assert exc_info.value.metadata.error_type == "ConfigurationError"
    assert "OPENAI_API_KEY" in exc_info.value.metadata.error


async def test_connection_check_retrieves_the_model_without_generating(fake_client):
    model = SimpleNamespace(id="gpt-test")
    model._request_id = "req_models_1"
    client = fake_client([model])
    check = await OpenAIProvider().check_connection()
    assert check.ok and check.request_id == "req_models_1"
    assert client.calls == []  # no completion was requested


async def test_connection_check_reports_a_bad_key_without_echoing_it(fake_client):
    fake_client([_status_error(openai.AuthenticationError, 401, f"Incorrect API key provided: {FAKE_KEY}",
                               code="invalid_api_key")])
    check = await OpenAIProvider().check_connection()
    assert not check.ok
    assert "sk-" not in check.detail and "401" in check.detail


def test_azure_uses_deployment_name_and_its_own_endpoint(monkeypatch):
    monkeypatch.setattr(settings, "azure_openai_endpoint", "https://soc-lite.openai.azure.com/")
    monkeypatch.setattr(settings, "azure_openai_deployment", "soc-lite-gpt")
    monkeypatch.setattr(settings, "azure_openai_api_key", "azure-test-key")
    provider = AzureOpenAIProvider()
    assert provider.model == "soc-lite-gpt"
    assert provider.api_domain == "soc-lite.openai.azure.com"
    assert provider.describe()["key_source"] == "environment"
