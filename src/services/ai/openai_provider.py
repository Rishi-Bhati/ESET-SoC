"""
OpenAI API provider (primary for the PoC), and Azure OpenAI on the same code path.

Uses Chat Completions with structured outputs (`response_format` = json_schema,
`strict: true`), which Azure OpenAI also supports — so switching vendor is a
configuration change, not a code change.

Request settings chosen for this workload:
  * `store=False` — the completion is not retained for OpenAI's stored-
    completions / evals features. (API data retention for abuse monitoring is
    governed by the organization's OpenAI data controls, not by this flag.)
  * SDK `max_retries=0` — retries are done once, visibly, by BaseAIProvider,
    so every attempt shows up in the trace and the total stays bounded.
  * temperature / reasoning_effort are only sent when configured: several
    current models reject a non-default temperature outright.

The API key is resolved per call through src/services/secrets.py (Secrets
Manager or environment) and only ever handed to the SDK client. After a 401
the cached secret is dropped and the call retried once with a fresh read, so a
key rotated in Secrets Manager is picked up without a restart.
"""
from __future__ import annotations

import hashlib
import time
from typing import Any
from urllib.parse import urlparse

import structlog

from src.config import settings
from src.services import secrets
from src.services.ai.base import (
    AIConfigurationError, AIOutputRejected, BaseAIProvider, ConnectionCheck, ProviderRequest, ProviderResponse,
)

logger = structlog.get_logger(__name__)

try:
    import openai
except ImportError:  # pragma: no cover - openai is in requirements.txt
    openai = None  # type: ignore[assignment]

# One SDK client per (provider, credential fingerprint, endpoint): reused across
# alerts for connection pooling, rebuilt when the key rotates.
_clients: dict[str, Any] = {}


def _fingerprint(*parts: str) -> str:
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()[:16]


def _usage(completion: Any) -> dict[str, Any] | None:
    usage = getattr(completion, "usage", None)
    if usage is None:
        return None
    details = getattr(usage, "completion_tokens_details", None)
    return {
        "prompt_tokens": getattr(usage, "prompt_tokens", None),
        "output_tokens": getattr(usage, "completion_tokens", None),
        "total_tokens": getattr(usage, "total_tokens", None),
        "reasoning_tokens": getattr(details, "reasoning_tokens", None) if details else None,
    }


class OpenAIProvider(BaseAIProvider):
    provider_name = "openai"
    service_label = "OpenAI API"
    api_domain = "api.openai.com"
    key_env_name = "OPENAI_API_KEY"

    def __init__(self) -> None:
        if openai is None:
            raise AIConfigurationError("The 'openai' package is not installed")
        super().__init__(model=self._configured_model())
        if not self.model:
            raise AIConfigurationError(f"{self._model_setting_name()} is not set")
        if settings.openai_base_url and self.provider_name == "openai":
            self.api_domain = urlparse(settings.openai_base_url).hostname or self.api_domain

    # -------------------------------------------------------------- config

    def _configured_model(self) -> str:
        return settings.openai_model.strip()

    def _model_setting_name(self) -> str:
        return "OPENAI_MODEL"

    def _key_config(self) -> tuple[str, str]:
        return settings.openai_api_key, settings.openai_api_key_secret_id

    def key_source(self) -> secrets.SecretSource:
        env_value, secret_id = self._key_config()
        return secrets.describe_source(self.key_env_name, env_value, secret_id)

    def describe(self) -> dict[str, Any]:
        info = super().describe()
        info["key_source"] = self.key_source().kind
        info["key_reference"] = self.key_source().reference
        if settings.openai_project_id:
            info["project_id"] = settings.openai_project_id
        return info

    def _new_client(self, api_key: str) -> Any:
        return openai.AsyncOpenAI(
            api_key=api_key,
            organization=settings.openai_organization_id or None,
            project=settings.openai_project_id or None,
            base_url=settings.openai_base_url or None,
            timeout=float(settings.ai_timeout_seconds),
            max_retries=0,
        )

    async def _client(self) -> Any:
        env_value, secret_id = self._key_config()
        try:
            api_key = await secrets.resolve_secret(self.key_env_name, env_value, secret_id)
        except secrets.SecretUnavailableError as exc:
            raise AIConfigurationError(str(exc)) from None
        cache_key = f"{self.provider_name}:{_fingerprint(api_key, settings.openai_base_url, settings.azure_openai_endpoint)}"
        client = _clients.get(cache_key)
        if client is None:
            # Drop clients built for a previous key of this provider.
            for key in [k for k in _clients if k.startswith(f"{self.provider_name}:")]:
                _clients.pop(key, None)
            client = self._new_client(api_key)
            _clients[cache_key] = client
        return client

    # -------------------------------------------------------------- calls

    def _request_kwargs(self, request: ProviderRequest) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": request.system_prompt},
                {"role": "user", "content": request.user_prompt},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {"name": request.schema_name, "schema": request.json_schema, "strict": True},
            },
            "max_completion_tokens": request.max_output_tokens,
            "store": False,
        }
        if settings.openai_temperature.strip():
            kwargs["temperature"] = float(settings.openai_temperature)
        if settings.openai_reasoning_effort.strip():
            kwargs["reasoning_effort"] = settings.openai_reasoning_effort.strip()
        return kwargs

    async def _create(self, request: ProviderRequest) -> Any:
        client = await self._client()
        return await client.chat.completions.create(**self._request_kwargs(request))

    async def _invoke(self, request: ProviderRequest) -> ProviderResponse:
        try:
            completion = await self._create(request)
        except openai.AuthenticationError:
            # What a rotated key looks like. Only worth one re-read when the key
            # comes from Secrets Manager; an env-var key cannot have changed.
            _, secret_id = self._key_config()
            if not secrets.invalidate(secret_id):
                raise
            logger.warning("ai_auth_failed_rereading_secret", provider=self.provider_name)
            completion = await self._create(request)

        choice = completion.choices[0]
        message = choice.message
        if getattr(message, "refusal", None):
            raise AIOutputRejected("The model refused to produce the notification")
        if choice.finish_reason == "length":
            raise AIOutputRejected(
                f"Output was cut off at AI_MAX_OUTPUT_TOKENS={request.max_output_tokens}"
            )
        if choice.finish_reason == "content_filter":
            raise AIOutputRejected("Output was blocked by the provider's content filter")
        if not message.content:
            raise AIOutputRejected("The model returned an empty response")

        return ProviderResponse(
            text=message.content,
            request_id=getattr(completion, "_request_id", None),
            response_id=getattr(completion, "id", None),
            served_model=getattr(completion, "model", None),
            usage=_usage(completion),
            finish_reason=choice.finish_reason,
        )

    # -------------------------------------------------------------- errors

    def _is_retryable(self, exc: BaseException) -> bool:
        if super()._is_retryable(exc):
            return True
        if isinstance(exc, (openai.APITimeoutError, openai.APIConnectionError, openai.InternalServerError)):
            return True
        if isinstance(exc, openai.RateLimitError):
            # Out of credit is not going to fix itself in ten seconds.
            return getattr(exc, "code", None) != "insufficient_quota"
        if isinstance(exc, openai.APIStatusError):
            return exc.status_code in (408, 409) or exc.status_code >= 500
        return False

    def _describe_error(self, exc: BaseException) -> tuple[str, str, str | None]:
        if isinstance(exc, AIConfigurationError):
            return "ConfigurationError", str(exc), None
        if isinstance(exc, AIOutputRejected):
            return "OutputRejected", str(exc), None
        if openai is not None and isinstance(exc, openai.APIStatusError):
            code = getattr(exc, "code", None)
            request_id = getattr(exc, "request_id", None)
            summary = f"HTTP {exc.status_code}" + (f" ({code})" if code else "")
            hints = {
                401: "the API key was rejected — check the key in the secret store",
                403: "the key's project/organization is not allowed to use this model or endpoint",
                404: f"model '{self.model}' was not found or is not available to this project",
                429: "rate limit or quota exceeded",
            }
            hint = hints.get(exc.status_code)
            if exc.status_code in (400, 422):
                # Request-shape errors are the useful ones to read ("unsupported
                # parameter: temperature") and never echo the key. Redacted anyway.
                from src.services.ai.redaction import redact_value
                message, _ = redact_value(str(getattr(exc, "message", ""))[:240], "error")
                hint = str(message)
            return type(exc).__name__, f"{summary}: {hint}" if hint else summary, request_id
        if openai is not None and isinstance(exc, openai.APITimeoutError):
            return "Timeout", f"No response within {settings.ai_timeout_seconds}s", None
        if openai is not None and isinstance(exc, openai.APIConnectionError):
            return "ConnectionError", f"Could not connect to {self.api_domain}", None
        return super()._describe_error(exc)

    async def check_connection(self) -> ConnectionCheck:
        """Retrieves the configured model: proves the key works and the project
        can use the model, without generating (or paying for) any tokens."""
        started = time.monotonic()
        try:
            client = await self._client()
            model = await client.models.retrieve(self.model)
            return ConnectionCheck(
                ok=True, detail=f"Model '{getattr(model, 'id', self.model)}' is available to this key",
                latency_ms=round((time.monotonic() - started) * 1000, 1),
                request_id=getattr(model, "_request_id", None),
            )
        except Exception as exc:
            error_type, message, request_id = self._describe_error(exc)
            return ConnectionCheck(ok=False, detail=f"{error_type}: {message}",
                                   latency_ms=round((time.monotonic() - started) * 1000, 1),
                                   request_id=request_id)


class AzureOpenAIProvider(OpenAIProvider):
    """Azure OpenAI Service. The deployment name stands in for the model name."""
    provider_name = "azure_openai"
    service_label = "Azure OpenAI Service"
    key_env_name = "AZURE_OPENAI_API_KEY"

    def __init__(self) -> None:
        if not settings.azure_openai_endpoint:
            raise AIConfigurationError("AZURE_OPENAI_ENDPOINT is not set")
        super().__init__()
        self.api_domain = urlparse(settings.azure_openai_endpoint).hostname or settings.azure_openai_endpoint

    def _configured_model(self) -> str:
        return settings.azure_openai_deployment.strip()

    def _model_setting_name(self) -> str:
        return "AZURE_OPENAI_DEPLOYMENT"

    def _key_config(self) -> tuple[str, str]:
        return settings.azure_openai_api_key, settings.azure_openai_api_key_secret_id

    def _new_client(self, api_key: str) -> Any:
        return openai.AsyncAzureOpenAI(
            api_key=api_key,
            azure_endpoint=settings.azure_openai_endpoint,
            api_version=settings.azure_openai_api_version,
            timeout=float(settings.ai_timeout_seconds),
            max_retries=0,
        )

    def describe(self) -> dict[str, Any]:
        info = super().describe()
        info.pop("project_id", None)
        info["api_version"] = settings.azure_openai_api_version
        return info
