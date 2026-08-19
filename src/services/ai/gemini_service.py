import asyncio
import json
from typing import Any
import google.generativeai as genai
import structlog
from src.config import settings
from src.services.ai.base import BaseAIProvider
from src.models.normalized_alert import NormalizedAlert
from src.models.threat_intel import ThreatIntelResult
from src.models.ai_output import AIOutput
from src.prompts.system_prompts import SYSTEM_PROMPT, PROMPT_VERSION
from src.services.ai.schema_builder import build_gemini_schema
from src.services.ai import trace_recorder
from src.utils.correlation import get_correlation_id
from src.utils.retry import get_retry_log, reset_retry_log, retry_api_call

logger = structlog.get_logger(__name__)

PROVIDER_NAME = "google_gemini"
MODEL_NAME = "gemini-3.1-flash-lite"
# The endpoint the google-generativeai SDK talks to. Shown in the AI Visibility
# dashboard's "External Contacts" section so an operator can see exactly which
# third party this alert's data was sent to.
API_DOMAIN = "generativelanguage.googleapis.com"

# Honest, explicit notes about what this specific integration does and does not send,
# surfaced verbatim in the AI Visibility trace detail (Data Flow section) — see
# src/services/ai/trace_recorder.py for how they're attached to a trace.
CONTEXT_NOTES = [
    "raw_payload (the original, unmodified ESET payload) is deliberately excluded from "
    "the prompt — only normalized_alert fields are sent (see normalizer.py).",
    "No conversation history is sent — each request is a stateless, single-turn "
    "structured-generation call with no memory of prior alerts.",
    "No files or documents are uploaded to the model.",
    "No function/tool calling is used by the model. VirusTotal and AbuseIPDB results "
    "were already fetched by the pipeline before this call and are included as static "
    "context in the prompt — the model itself never contacts either service.",
]


def _extract_usage(response: Any) -> dict[str, Any] | None:
    """Best-effort token-usage extraction. Returns None rather than fabricating numbers
    if the SDK response does not expose usage_metadata."""
    usage = getattr(response, "usage_metadata", None)
    if usage is None:
        return None
    try:
        return {
            "prompt_tokens": getattr(usage, "prompt_token_count", None),
            "output_tokens": getattr(usage, "candidates_token_count", None),
            "total_tokens": getattr(usage, "total_token_count", None),
        }
    except Exception:
        return None


class GeminiAIService(BaseAIProvider):
    """
    Implementation of AIProvider using Google's Gemini 2.0 Flash model.
    Utilizes Gemini's native Structured Output capabilities.

    Every call to generate() produces one AI Visibility trace (see
    src/services/ai/trace_recorder.py) covering the input sent, the model
    configuration, the external contact with Google's API, the response received,
    and any sensitive data detected along the way. Instrumentation failures never
    affect the outcome of generate() itself — see trace_recorder.py's module docstring.
    """

    def __init__(self) -> None:
        # Configure the Google AI Generative client using provided API key
        genai.configure(api_key=settings.gemini_api_key)
        # Using gemini-3.1-flash-lite for high speed, low latency, and cost-effectiveness
        self.model = genai.GenerativeModel(MODEL_NAME)

    @retry_api_call(max_attempts=3, min_delay=1.0, max_delay=10.0)
    async def _call_gemini_with_retry(
        self,
        prompt: str,
        generation_config: genai.types.GenerationConfig
    ) -> Any:
        """
        Executes the blocking model content generation in a separate executor thread.
        Decorated with exponential backoff retries. Returns the full SDK response
        object (not just .text) so callers can also read usage_metadata.
        """
        loop = asyncio.get_running_loop()

        # Run blocking SDK call in threadpool
        response = await loop.run_in_executor(
            None,
            lambda: self.model.generate_content(
                contents=[SYSTEM_PROMPT, prompt],
                generation_config=generation_config
            )
        )

        if not response.text:
            raise ValueError("Gemini returned an empty response")

        return response

    async def generate(
        self,
        alert: NormalizedAlert,
        risk_level: str,
        threat_intel: ThreatIntelResult
    ) -> AIOutput:
        """
        Sends the alert, risk calculation, and threat intelligence verdicts to Gemini
        and parses the returned structured JSON into an AIOutput Pydantic instance.
        """
        logger.info("gemini_generation_start", risk_level=risk_level)

        correlation_id = get_correlation_id() or "unknown"
        trace = await trace_recorder.start_trace(
            correlation_id=correlation_id,
            component="pipeline.ai_generate",
            action="generate_bilingual_notifications",
            provider=PROVIDER_NAME,
            model=MODEL_NAME,
            objective=(
                f"Generate 4 bilingual SOC notifications (client/C-Three/internal JA, "
                f"engineer EN) for a {risk_level}-risk alert, without inventing facts "
                f"not present in the input."
            ),
        )

        # Exclude raw_payload from data sent to prompt to keep context clean
        prompt_data = {
            "normalized_alert": alert.model_dump(exclude={"raw_payload"}),
            "calculated_risk_level": risk_level,
            "threat_intelligence": threat_intel.model_dump()
        }

        await trace_recorder.record_input(
            trace,
            data_categories=trace_recorder.build_alert_data_categories(alert, risk_level, threat_intel),
            raw_input=prompt_data,
            context_notes=CONTEXT_NOTES,
        )

        # Serialized input context
        prompt = (
            f"Normalized Alert and Threat Intelligence Context:\n"
            f"{json.dumps(prompt_data, indent=2)}\n\n"
            f"Please generate the Japanese and English notifications as specified by the system prompt."
        )

        # Enforce strict compliance via an explicit Gemini schema. We do NOT pass the
        # Pydantic class directly: the SDK's converter drops every `required` array,
        # which lets the model return a near-empty object (see schema_builder docstring).
        schema = build_gemini_schema(AIOutput)
        generation_config = genai.types.GenerationConfig(
            response_mime_type="application/json",
            response_schema=schema,
            temperature=0.1,  # Keep temperature low for high determinism and schema fidelity
            max_output_tokens=8192,  # 4 bilingual notifications; Japanese is token-dense
        )
        await trace_recorder.record_config(trace, {
            "temperature": 0.1,
            "max_output_tokens": 8192,
            "response_mime_type": "application/json",
            "response_schema_required_fields": list(schema.get("required", [])),
            "system_instructions_version": PROMPT_VERSION,
            "system_instructions_text": SYSTEM_PROMPT.strip(),
        })

        ext_call = await trace_recorder.record_external_call_start(
            trace, service="Google Generative AI (Gemini)", domain=API_DOMAIN,
            purpose="Generate structured bilingual SOC notification content",
            initiated_by="ai_provider_request",
            data_sent_category="Normalized alert fields, deterministic risk level, "
                                "pre-fetched threat-intel verdicts",
        )
        await trace_recorder.record_event(trace, "request_sent", "Request sent to model",
                                           detail=f"{PROVIDER_NAME}/{MODEL_NAME}")

        reset_retry_log()
        try:
            response = await self._call_gemini_with_retry(prompt, generation_config)
            for entry in get_retry_log():
                await trace_recorder.record_retry(
                    trace, entry["attempt"], entry["next_delay"] or 0.0, entry["error"],
                )

            raw_response = response.text

            # Parse and validate the response against the schema
            ai_output = AIOutput.model_validate_json(raw_response)
            logger.info("gemini_generation_success")

            await trace_recorder.record_external_call_end(
                trace, ext_call, status="OK",
                data_returned_category="Structured JSON: 4 bilingual notification objects",
            )
            await trace_recorder.record_output(
                trace, ai_output.model_dump(), usage=_extract_usage(response),
            )

            if ai_output.risk_level != risk_level:
                await trace_recorder.record_event(
                    trace, "consistency_check", "Risk-level consistency check",
                    detail=(
                        f"Model echoed risk_level={ai_output.risk_level}, but the deterministic "
                        f"risk engine computed {risk_level}. Only the risk engine's value is used "
                        f"downstream (src/services/risk_engine.py) — the model's own risk_level "
                        f"field is informational only."
                    ),
                )

            await trace_recorder.build_decision_summary(
                trace,
                task="Translate/summarize a security alert into 4 audience-specific notifications",
                context_used=[dc.field for dc in trace.data_categories] if trace else [],
                decision=f"Produced 4 notifications; model-reported risk_level={ai_output.risk_level}",
                confidence="Not provided — the Gemini structured-output API used here does not "
                           "return a confidence/uncertainty score for the response.",
                policy_checks=["schema_required_fields_enforced (see schema_builder.py)"],
            )

            await trace_recorder.complete_trace(
                trace, status="SUCCESS",
                risk="SENSITIVE_DATA_DETECTED" if (trace and trace.security_findings) else "SAFE",
            )
            return ai_output

        except Exception as e:
            logger.error("gemini_generation_failed", error=str(e))
            for entry in get_retry_log():
                await trace_recorder.record_retry(
                    trace, entry["attempt"], entry["next_delay"] or 0.0, entry["error"],
                )
            await trace_recorder.record_external_call_end(trace, ext_call, status="ERROR")
            await trace_recorder.complete_trace(trace, status="ERROR", risk="ERROR", error=str(e)[:500])
            raise e
        finally:
            reset_retry_log()
