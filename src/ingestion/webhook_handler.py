from typing import Any
import structlog
from src.ingestion.base import BaseIngestionHandler
from src.models.raw_payload import EsetRawPayload

logger = structlog.get_logger(__name__)

class WebhookIngestionHandler(BaseIngestionHandler):
    """
    Handler for parsing and validating webhook JSON payloads from ESET.
    """
    
    def parse(self, raw_data: Any) -> EsetRawPayload:
        """
        Parses raw dict payload from HTTP request.
        """
        if not isinstance(raw_data, dict):
            logger.error("webhook_invalid_payload_type", type=type(raw_data).__name__)
            raise ValueError("Webhook payload must be a JSON object (dict)")
            
        # Ensure raw_payload is set to the full payload for auditing
        data = dict(raw_data)
        if "raw_payload" not in data or not data["raw_payload"]:
            data["raw_payload"] = raw_data
            
        # If source is missing, default it
        if not data.get("source"):
            data["source"] = "ESET_PROTECT_CLOUD_WEBHOOK"
            
        try:
            return EsetRawPayload(**data)
        except Exception as e:
            logger.error("webhook_parse_error", error=str(e))
            raise ValueError(f"Failed to parse webhook JSON to EsetRawPayload: {e}")
