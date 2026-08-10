from typing import Any
from pydantic import BaseModel, Field

class EsetRawPayload(BaseModel):
    """
    Represents the raw, unnormalized payload coming from ESET PROTECT Cloud
    via Webhooks or Syslog JSON. Fields are extremely lenient (optional)
    to handle variable payloads.
    """
    source: str | None = Field(default=None)
    event_type: str | None = Field(default=None)
    alert_id: str | None = Field(default=None)
    detection_uuid: str | None = Field(default=None)
    target_uuid: str | None = Field(default=None)
    occurred_at: str | None = Field(default=None)
    severity: str | None = Field(default=None)
    detection_name: str | None = Field(default=None)
    endpoint_name: str | None = Field(default=None)
    endpoint_type: str | None = Field(default=None)
    user_name: str | None = Field(default=None)
    os_name: str | None = Field(default=None)
    action_taken: str | None = Field(default=None)
    threat_handled: str | bool | None = Field(default=None)
    isolation_status: str | bool | None = Field(default=None)
    object_type: str | None = Field(default=None)
    object_uri: str | None = Field(default=None)
    file_hash: str | None = Field(default=None)
    url: str | None = Field(default=None)
    ip_address: str | None = Field(default=None)
    domain: str | None = Field(default=None)
    raw_subject: str | None = Field(default=None)
    raw_content: str | None = Field(default=None)
    raw_payload: dict[str, Any] = Field(default_factory=dict)

    # Allow extra fields to be parsed into model without error
    model_config = {
        "extra": "allow"
    }
