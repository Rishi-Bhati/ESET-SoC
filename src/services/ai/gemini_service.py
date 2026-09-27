"""
Google Gemini provider — the platform's original AI integration, kept as an
alternative behind AI_PROVIDER=gemini.

Uses the (deprecated upstream) google-generativeai SDK, imported lazily so a
deployment that uses OpenAI does not need it installed. Gemini's structured
output takes an OpenAPI-subset schema; see schema_builder.build_gemini_schema
for why it is built by hand rather than passed as a Pydantic class.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

from src.config import settings
from src.models.ai_output import AIOutput
from src.services import secrets
from src.services.ai.base import (
    AIConfigurationError, AIOutputRejected, BaseAIProvider, ConnectionCheck, ProviderRequest, ProviderResponse,
)
from src.services.ai.schema_builder import build_gemini_schema


def _import_genai() -> Any:
    try:
        import google.generativeai as genai  # noqa: WPS433 - optional dependency
    except ImportError:
        raise AIConfigurationError(
            "AI_PROVIDER=gemini needs the google-generativeai package (pip install google-generativeai)"
        ) from None
    return genai


def _usage(response: Any) -> dict[str, Any] | None:
    usage = getattr(response, "usage_metadata", None)
    if usage is None:
        return None
    return {
        "prompt_tokens": getattr(usage, "prompt_token_count", None),
        "output_tokens": getattr(usage, "candidates_token_count", None),
        "total_tokens": getattr(usage, "total_token_count", None),
    }


class GeminiAIService(BaseAIProvider):
    provider_name = "google_gemini"
    service_label = "Google Generative AI (Gemini)"
    api_domain = "generativelanguage.googleapis.com"

    def __init__(self) -> None:
        super().__init__(model=settings.gemini_model)
        self._genai = _import_genai()

    def describe(self) -> dict[str, Any]:
        info = super().describe()
        source = secrets.describe_source("GEMINI_API_KEY", settings.gemini_api_key, settings.gemini_api_key_secret_id)
        info["key_source"], info["key_reference"] = source.kind, source.reference
        return info

    async def _configure(self) -> None:
        try:
            key = await secrets.resolve_secret(
                "GEMINI_API_KEY", settings.gemini_api_key, settings.gemini_api_key_secret_id,
            )
        except secrets.SecretUnavailableError as exc:
            raise AIConfigurationError(str(exc)) from None
        self._genai.configure(api_key=key)

    async def _invoke(self, request: ProviderRequest) -> ProviderResponse:
        await self._configure()
        genai = self._genai
        # Gemini reads the pinned risk level from its own schema dialect.
        pinned = request.json_schema["properties"]["risk_level"]["enum"]
        model = genai.GenerativeModel(self.model, system_instruction=request.system_prompt)
        config = genai.types.GenerationConfig(
            response_mime_type="application/json",
            response_schema=build_gemini_schema(AIOutput, pin={"risk_level": pinned}),
            temperature=0.1,
            max_output_tokens=request.max_output_tokens,
        )
        # Blocking SDK call, run off the event loop. BaseAIProvider bounds it with
        # AI_TIMEOUT_SECONDS (the thread itself cannot be cancelled, but the
        # pipeline stops waiting for it).
        response = await asyncio.get_running_loop().run_in_executor(
            None, lambda: model.generate_content(contents=[request.user_prompt], generation_config=config),
        )
        text = getattr(response, "text", "")
        if not text:
            raise AIOutputRejected("Gemini returned an empty response")
        return ProviderResponse(text=text, served_model=self.model, usage=_usage(response))

    def _describe_error(self, exc: BaseException) -> tuple[str, str, str | None]:
        if isinstance(exc, (AIConfigurationError, AIOutputRejected)):
            return type(exc).__name__, str(exc), None
        code = getattr(exc, "code", None)
        if code is not None and type(exc).__module__.startswith("google."):
            # google.api_core exceptions: the class and HTTP code are enough, and
            # the message can include request URLs carrying the key.
            return type(exc).__name__, f"HTTP {code}", None
        return super()._describe_error(exc)

    def _is_retryable(self, exc: BaseException) -> bool:
        if super()._is_retryable(exc):
            return True
        code = getattr(exc, "code", None)
        try:
            return int(code) in (408, 429) or int(code) >= 500
        except (TypeError, ValueError):
            return False

    async def check_connection(self) -> ConnectionCheck:
        started = time.monotonic()
        try:
            await self._configure()
            model_name = self.model if self.model.startswith("models/") else f"models/{self.model}"
            info = await asyncio.get_running_loop().run_in_executor(None, lambda: self._genai.get_model(model_name))
            return ConnectionCheck(ok=True, detail=f"Model '{getattr(info, 'name', model_name)}' is available",
                                   latency_ms=round((time.monotonic() - started) * 1000, 1))
        except Exception as exc:
            error_type, message, _ = self._describe_error(exc)
            return ConnectionCheck(ok=False, detail=f"{error_type}: {message}",
                                   latency_ms=round((time.monotonic() - started) * 1000, 1))
