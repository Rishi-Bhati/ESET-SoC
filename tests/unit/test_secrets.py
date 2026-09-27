import json
import pytest
from src.config import settings
from src.services import secrets


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    secrets.clear_cache()
    monkeypatch.setattr(settings, "secret_cache_ttl_seconds", 300)
    yield
    secrets.clear_cache()


async def test_environment_value_is_used_without_a_secret_id():
    assert await secrets.resolve_secret("OPENAI_API_KEY", "sk-env", "") == "sk-env"


async def test_missing_everywhere_is_a_clear_error_without_values():
    with pytest.raises(secrets.SecretUnavailableError, match="OPENAI_API_KEY is not configured"):
        await secrets.resolve_secret("OPENAI_API_KEY", "", "")


async def test_secret_id_wins_over_environment_and_is_cached(monkeypatch):
    calls = []
    monkeypatch.setattr(secrets, "fetch_secret_string", lambda sid: calls.append(sid) or "sk-from-sm")
    for _ in range(3):
        assert await secrets.resolve_secret("OPENAI_API_KEY", "sk-env", "eset/poc/openai") == "sk-from-sm"
    assert calls == ["eset/poc/openai"]


async def test_invalidate_forces_a_reread(monkeypatch):
    values = iter(["sk-1", "sk-2"])
    monkeypatch.setattr(secrets, "fetch_secret_string", lambda sid: next(values))
    assert await secrets.resolve_secret("OPENAI_API_KEY", "", "s") == "sk-1"
    assert secrets.invalidate("s") is True
    assert await secrets.resolve_secret("OPENAI_API_KEY", "", "s") == "sk-2"
    assert secrets.invalidate("") is False, "an env-var key cannot be re-read"


@pytest.mark.parametrize("secret_string, expected", [
    ("sk-plain", "sk-plain"),
    (json.dumps({"OPENAI_API_KEY": "sk-named", "OTHER": "x"}), "sk-named"),
    (json.dumps({"api_key": "sk-generic"}), "sk-generic"),
    (json.dumps({"whatever": "sk-only"}), "sk-only"),
])
async def test_secret_string_formats(monkeypatch, secret_string, expected):
    monkeypatch.setattr(secrets, "fetch_secret_string", lambda sid: secret_string)
    assert await secrets.resolve_secret("OPENAI_API_KEY", "", "s") == expected


def test_region_comes_from_the_arn_when_not_configured(monkeypatch):
    monkeypatch.setattr(settings, "aws_region", "")
    arn = "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:eset-soc-lite/prod/openai-AbCdEf"
    assert secrets._region_for(arn) == "ap-northeast-1"
    assert secrets._region_for("eset-soc-lite/prod/openai") is None


def test_fetch_errors_name_the_secret_but_not_any_value(monkeypatch):
    class Boom(Exception):
        response = {"Error": {"Code": "AccessDeniedException", "Message": "secret value sk-should-not-appear"}}

    class Client:
        def get_secret_value(self, SecretId):
            raise Boom("sk-should-not-appear")

    monkeypatch.setattr(secrets, "_get_client", lambda region: Client())
    with pytest.raises(secrets.SecretUnavailableError) as exc_info:
        secrets.fetch_secret_string("eset/poc/openai")
    message = str(exc_info.value)
    assert "eset/poc/openai" in message and "AccessDeniedException" in message
    assert "sk-should-not-appear" not in message


def test_describe_source_never_carries_the_value():
    arn = "arn:aws:secretsmanager:ap-northeast-1:123456789012:secret:eset-soc-lite/prod/openai-AbCdEf"
    assert secrets.describe_source("OPENAI_API_KEY", "sk-env", arn) == secrets.SecretSource(
        "aws_secrets_manager", "eset-soc-lite/prod/openai-AbCdEf")
    assert secrets.describe_source("OPENAI_API_KEY", "sk-env", "").kind == "environment"
    assert secrets.describe_source("OPENAI_API_KEY", "", "").kind == "missing"


def test_app_secrets_overlay_only_allowlisted_credentials(monkeypatch):
    monkeypatch.setattr(settings, "app_secrets_secret_id", "eset-soc-lite/poc/app")
    monkeypatch.setattr(settings, "dashboard_access_key", "")
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(secrets, "fetch_secret_string", lambda sid: json.dumps({
        "DASHBOARD_ACCESS_KEY": "k" * 32, "APP_ENV": "development",
    }))
    assert secrets.apply_app_secrets() == ["DASHBOARD_ACCESS_KEY"]
    assert settings.dashboard_access_key == "k" * 32
    assert settings.app_env == "production", "configuration keys are not taken from the secret"


def test_app_secrets_disabled_without_a_secret_id(monkeypatch):
    monkeypatch.setattr(settings, "app_secrets_secret_id", "")
    assert secrets.apply_app_secrets() == []
