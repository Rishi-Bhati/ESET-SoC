"""
Provider selection. AI_PROVIDER picks the implementation; each provider reads
its own model name and credentials from settings.

Adding a provider (e.g. Amazon Bedrock / Claude) is one class implementing
BaseAIProvider._invoke() plus one entry in _PROVIDERS — prompt, masking,
schema, retries, validation, tracing and audit records are shared.
"""
from typing import Callable
from src.config import settings
from src.services.ai.base import AIConfigurationError, BaseAIProvider


def _openai() -> BaseAIProvider:
    from src.services.ai.openai_provider import OpenAIProvider
    return OpenAIProvider()


def _azure_openai() -> BaseAIProvider:
    from src.services.ai.openai_provider import AzureOpenAIProvider
    return AzureOpenAIProvider()


def _gemini() -> BaseAIProvider:
    from src.services.ai.gemini_service import GeminiAIService
    return GeminiAIService()


_PROVIDERS: dict[str, Callable[[], BaseAIProvider]] = {
    "openai": _openai,
    "azure_openai": _azure_openai,
    "gemini": _gemini,
}

# provider: (model setting, key setting, key secret-id setting). Used for status
# displays and startup checks, without constructing the provider.
PROVIDER_SETTINGS = {
    "openai": ("openai_model", "openai_api_key", "openai_api_key_secret_id"),
    "azure_openai": ("azure_openai_deployment", "azure_openai_api_key", "azure_openai_api_key_secret_id"),
    "gemini": ("gemini_model", "gemini_api_key", "gemini_api_key_secret_id"),
}
MODEL_SETTING = {name: attrs[0] for name, attrs in PROVIDER_SETTINGS.items()}


def supported_providers() -> list[str]:
    return sorted(_PROVIDERS)


def configured_provider_name() -> str:
    return settings.ai_provider.strip().lower()


def get_ai_provider() -> BaseAIProvider:
    """A provider instance for the configured AI_PROVIDER. Raises
    AIConfigurationError when the provider is unknown or misconfigured."""
    name = configured_provider_name()
    factory = _PROVIDERS.get(name)
    if factory is None:
        raise AIConfigurationError(
            f"Unknown AI_PROVIDER '{settings.ai_provider}' (supported: {', '.join(supported_providers())})"
        )
    return factory()


def ai_provider_configured() -> bool:
    """A model name and a key source (env value or Secrets Manager ID) are set for
    the configured provider. Does not prove the key works — the dashboard's
    connection test does that."""
    required = PROVIDER_SETTINGS.get(configured_provider_name())
    if required is None:
        return False
    model_attr, key_attr, secret_attr = required
    return bool(getattr(settings, model_attr)) and bool(getattr(settings, key_attr) or getattr(settings, secret_attr))
