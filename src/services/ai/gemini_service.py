import asyncio
import json
import google.generativeai as genai
import structlog
from src.config import settings
from src.services.ai.base import BaseAIProvider
from src.models.normalized_alert import NormalizedAlert
from src.models.threat_intel import ThreatIntelResult
from src.models.ai_output import AIOutput
from src.prompts.system_prompts import SYSTEM_PROMPT
from src.services.ai.schema_builder import build_gemini_schema
from src.utils.retry import retry_api_call

logger = structlog.get_logger(__name__)

class GeminiAIService(BaseAIProvider):
    """
    Implementation of AIProvider using Google's Gemini 2.0 Flash model.
    Utilizes Gemini's native Structured Output capabilities.
    """
    
    def __init__(self) -> None:
        # Configure the Google AI Generative client using provided API key
        genai.configure(api_key=settings.gemini_api_key)
        # Using gemini-3.1-flash-lite for high speed, low latency, and cost-effectiveness
        self.model = genai.GenerativeModel("gemini-3.1-flash-lite")
        
    @retry_api_call(max_attempts=3, min_delay=1.0, max_delay=10.0)
    async def _call_gemini_with_retry(
        self,
        prompt: str,
        generation_config: genai.types.GenerationConfig
    ) -> str:
        """
        Executes the blocking model content generation in a separate executor thread.
        Decorated with exponential backoff retries.
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
            
        return response.text

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
        
        # Exclude raw_payload from data sent to prompt to keep context clean
        prompt_data = {
            "normalized_alert": alert.model_dump(exclude={"raw_payload"}),
            "calculated_risk_level": risk_level,
            "threat_intelligence": threat_intel.model_dump()
        }
        
        # Serialized input context
        prompt = (
            f"Normalized Alert and Threat Intelligence Context:\n"
            f"{json.dumps(prompt_data, indent=2)}\n\n"
            f"Please generate the Japanese and English notifications as specified by the system prompt."
        )
        
        # Enforce strict compliance via an explicit Gemini schema. We do NOT pass the
        # Pydantic class directly: the SDK's converter drops every `required` array,
        # which lets the model return a near-empty object (see schema_builder docstring).
        generation_config = genai.types.GenerationConfig(
            response_mime_type="application/json",
            response_schema=build_gemini_schema(AIOutput),
            temperature=0.1,  # Keep temperature low for high determinism and schema fidelity
            max_output_tokens=8192,  # 4 bilingual notifications; Japanese is token-dense
        )
        
        try:
            raw_response = await self._call_gemini_with_retry(prompt, generation_config)
            
            # Parse and validate the response against the schema
            ai_output = AIOutput.model_validate_json(raw_response)
            logger.info("gemini_generation_success")
            return ai_output
            
        except Exception as e:
            logger.error("gemini_generation_failed", error=str(e))
            raise e
