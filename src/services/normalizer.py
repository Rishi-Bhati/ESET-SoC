import structlog
from src.models.raw_payload import EsetRawPayload
from src.models.normalized_alert import NormalizedAlert

logger = structlog.get_logger(__name__)

def normalize(raw: EsetRawPayload, source: str) -> NormalizedAlert:
    """
    Normalizes an EsetRawPayload into a strict NormalizedAlert.
    Ensures missing values are explicitly represented as 'UNKNOWN' string,
    standardizes boolean-like properties, and logs any missing fields.
    """
    logger.debug("normalizer_start", raw_source=raw.source, input_source=source)
    
    data = {}
    
    # Simple direct mappings with 'UNKNOWN' fallback
    data["source"] = source or raw.source or "UNKNOWN"
    data["event_type"] = raw.event_type or "UNKNOWN"
    data["alert_id"] = raw.alert_id or "UNKNOWN"
    data["detection_uuid"] = raw.detection_uuid or "UNKNOWN"
    data["target_uuid"] = raw.target_uuid or "UNKNOWN"
    data["occurred_at"] = raw.occurred_at or "UNKNOWN"
    data["severity"] = raw.severity or "UNKNOWN"
    data["detection_name"] = raw.detection_name or "UNKNOWN"
    data["endpoint_name"] = raw.endpoint_name or "UNKNOWN"
    data["endpoint_type"] = raw.endpoint_type or "UNKNOWN"
    data["user_name"] = raw.user_name or "UNKNOWN"
    data["os_name"] = raw.os_name or "UNKNOWN"
    data["action_taken"] = raw.action_taken or "UNKNOWN"
    
    # Standardize threat_handled (cast boolean to string "true"/"false")
    if isinstance(raw.threat_handled, bool):
        data["threat_handled"] = "true" if raw.threat_handled else "false"
    elif isinstance(raw.threat_handled, str):
        data["threat_handled"] = raw.threat_handled.strip().lower()
    else:
        data["threat_handled"] = "UNKNOWN"
        
    # Standardize isolation_status (cast boolean to string "true"/"false")
    if isinstance(raw.isolation_status, bool):
        data["isolation_status"] = "true" if raw.isolation_status else "false"
    elif isinstance(raw.isolation_status, str):
        data["isolation_status"] = raw.isolation_status.strip().lower()
    else:
        data["isolation_status"] = "UNKNOWN"
        
    data["object_type"] = raw.object_type or "UNKNOWN"
    data["object_uri"] = raw.object_uri or "UNKNOWN"
    data["file_hash"] = raw.file_hash or "UNKNOWN"
    data["url"] = raw.url or "UNKNOWN"
    data["ip_address"] = raw.ip_address or "UNKNOWN"
    data["domain"] = raw.domain or "UNKNOWN"
    data["raw_subject"] = raw.raw_subject or "UNKNOWN"
    data["raw_content"] = raw.raw_content or "UNKNOWN"
    
    # Preserve full raw structure for debugging/auditing
    data["raw_payload"] = raw.raw_payload or {}
    
    # Audit logging for missing critical fields (warning but non-blocking)
    missing_fields = [k for k, v in data.items() if v == "UNKNOWN" and k != "source"]
    if missing_fields:
        logger.debug("normalizer_unknown_fields", fields=missing_fields)
        
    return NormalizedAlert(**data)
