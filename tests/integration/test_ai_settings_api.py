"""
The dashboard shows the AI configuration read-only and can test the connection,
but never exposes or accepts the API key.
"""
import pytest
from fastapi.testclient import TestClient
from src.api import dashboard
from src.config import settings
from src.services.ai.base import ConnectionCheck

KEY = "sk-proj-DASHBOARDMUSTNEVERSHOWTHIS_0123456789abcdef"


@pytest.fixture(autouse=True)
def openai_config(monkeypatch):
    monkeypatch.setattr(settings, "ai_provider", "openai")
    monkeypatch.setattr(settings, "openai_model", "gpt-test")
    monkeypatch.setattr(settings, "openai_api_key", KEY)
    monkeypatch.setattr(settings, "openai_api_key_secret_id", "")
    monkeypatch.setattr(dashboard, "_last_ai_test", 0.0)


def test_settings_describe_the_ai_provider_without_the_key(client: TestClient):
    body = client.get("/dashboard/api/settings").json()
    ai = body["ai"]
    assert ai["provider"] == "openai" and ai["model"] == "gpt-test"
    assert ai["configured"] is True and ai["editable"] is False
    assert ai["key_source"] == "environment" and ai["key_reference"] == "OPENAI_API_KEY"
    assert KEY not in str(body) and KEY[-6:] not in str(body)
    assert {"id": "ai_key_store", "status": "warn"} in body["security"]


def test_secrets_manager_source_is_reported_by_name(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "openai_api_key_secret_id",
                        "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:eset-soc-lite/prod/openai-AbCd")
    body = client.get("/dashboard/api/settings").json()
    assert body["ai"]["key_source"] == "aws_secrets_manager"
    assert body["ai"]["key_reference"] == "eset-soc-lite/prod/openai-AbCd"
    assert {"id": "ai_key_store", "status": "ok"} in body["security"]


def test_there_is_no_route_that_accepts_an_api_key(client: TestClient):
    for method in ("put", "post", "patch"):
        res = getattr(client, method)("/dashboard/api/settings/ai", json={"openai_api_key": "sk-x"})
        assert res.status_code in (404, 405)


def test_connection_test_reports_result_and_request_id(client: TestClient, monkeypatch):
    from src.services.ai import factory
    from ai_fakes import FakeProvider

    async def check(self):
        return ConnectionCheck(ok=True, detail="Model 'mock-model' is available", latency_ms=12.0, request_id="req_t")
    monkeypatch.setattr(FakeProvider, "check_connection", check)
    body = client.post("/dashboard/api/settings/ai/test").json()
    assert body == {"ok": True, "detail": "Model 'mock-model' is available", "latency_ms": 12.0,
                    "request_id": "req_t", "provider": "mock", "model": "mock-model"}


def test_connection_test_is_rate_limited(client: TestClient):
    assert client.post("/dashboard/api/settings/ai/test").status_code == 200
    assert client.post("/dashboard/api/settings/ai/test").status_code == 429


def test_connection_test_requires_the_dashboard_key(client: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "dashboard_access_key", "k" * 20)
    assert client.post("/dashboard/api/settings/ai/test").status_code == 401
