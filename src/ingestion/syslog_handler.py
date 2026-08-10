import json
from typing import Any
import structlog
from src.ingestion.base import BaseIngestionHandler
from src.models.raw_payload import EsetRawPayload

logger = structlog.get_logger(__name__)

class SyslogIngestionHandler(BaseIngestionHandler):
    """
    Handler for parsing and mapping Syslog-exported JSON events from ESET PROTECT.
    Syslog events might use slightly different keys from the webhook payload.
    """
    
    def parse(self, raw_data: Any) -> EsetRawPayload:
        """
        Parses raw syslog payload (dict or raw JSON string).
        """
        if isinstance(raw_data, str):
            try:
                raw_data = json.loads(raw_data)
            except Exception as e:
                logger.error("syslog_invalid_json_string", error=str(e))
                raise ValueError("Syslog payload string must be valid JSON")
                
        if not isinstance(raw_data, dict):
            logger.error("syslog_invalid_payload_type", type=type(raw_data).__name__)
            raise ValueError("Syslog payload must be a JSON object (dict)")
            
        # Map common ESET Syslog JSON keys to EsetRawPayload structure
        mapped = {
            "source": "ESET_PROTECT_CLOUD_SYSLOG",
            "event_type": raw_data.get("event_type") or raw_data.get("log_type") or raw_data.get("event"),
            "alert_id": raw_data.get("alert_id") or raw_data.get("id"),
            "detection_uuid": raw_data.get("detection_uuid") or raw_data.get("uuid") or raw_data.get("detection_id"),
            "target_uuid": raw_data.get("target_uuid") or raw_data.get("computer_uuid") or raw_data.get("endpoint_id"),
            "occurred_at": raw_data.get("occurred_at") or raw_data.get("occurred") or raw_data.get("time") or raw_data.get("occured"),
            "severity": raw_data.get("severity"),
            "detection_name": raw_data.get("detection_name") or raw_data.get("threat_name") or raw_data.get("name"),
            "endpoint_name": raw_data.get("endpoint_name") or raw_data.get("computer_name") or raw_data.get("hostname"),
            "endpoint_type": raw_data.get("endpoint_type"),
            "user_name": raw_data.get("user_name") or raw_data.get("username"),
            "os_name": raw_data.get("os_name") or raw_data.get("os"),
            "action_taken": raw_data.get("action_taken") or raw_data.get("action"),
            "threat_handled": raw_data.get("threat_handled") or raw_data.get("handled"),
            "isolation_status": raw_data.get("isolation_status"),
            "object_type": raw_data.get("object_type"),
            "object_uri": raw_data.get("object_uri") or raw_data.get("object"),
            "file_hash": raw_data.get("file_hash") or raw_data.get("hash") or raw_data.get("sha256"),
            "url": raw_data.get("url"),
            "ip_address": raw_data.get("ip_address") or raw_data.get("ip") or raw_data.get("ipv4"),
            "domain": raw_data.get("domain"),
            "raw_subject": raw_data.get("raw_subject") or raw_data.get("subject"),
            "raw_content": raw_data.get("raw_content") or raw_data.get("content"),
            "raw_payload": raw_data
        }
        
        # Remove keys with None values to let default values take effect
        filtered = {k: v for k, v in mapped.items() if v is not None}
        
        try:
            return EsetRawPayload(**filtered)
        except Exception as e:
            logger.error("syslog_parse_error", error=str(e))
            raise ValueError(f"Failed to parse syslog JSON to EsetRawPayload: {e}")
