from typing import Any
from pydantic import BaseModel, Field

class NormalizedAlert(BaseModel):
    """
    Strict internal contract representing a standardized alert.
    All missing fields are explicitly normalized to 'UNKNOWN'.
    """
    source: str = Field(default="UNKNOWN")
    event_type: str = Field(default="UNKNOWN")
    alert_id: str = Field(default="UNKNOWN")
    detection_uuid: str = Field(default="UNKNOWN")
    target_uuid: str = Field(default="UNKNOWN")
    occurred_at: str = Field(default="UNKNOWN")
    severity: str = Field(default="UNKNOWN")
    detection_name: str = Field(default="UNKNOWN")
    endpoint_name: str = Field(default="UNKNOWN")
    endpoint_type: str = Field(default="UNKNOWN")
    user_name: str = Field(default="UNKNOWN")
    os_name: str = Field(default="UNKNOWN")
    action_taken: str = Field(default="UNKNOWN")
    threat_handled: str = Field(default="UNKNOWN")
    isolation_status: str = Field(default="UNKNOWN")
    object_type: str = Field(default="UNKNOWN")
    object_uri: str = Field(default="UNKNOWN")
    file_hash: str = Field(default="UNKNOWN")
    url: str = Field(default="UNKNOWN")
    ip_address: str = Field(default="UNKNOWN")
    domain: str = Field(default="UNKNOWN")
    raw_subject: str = Field(default="UNKNOWN")
    raw_content: str = Field(default="UNKNOWN")
    raw_payload: dict[str, Any] = Field(default_factory=dict)
