from typing import Any
from pydantic import BaseModel, Field, SerializerFunctionWrapHandler, model_serializer

class NormalizedAlert(BaseModel):
    """
    Strict internal contract representing a standardized alert.

    A field is set only when the submitted alert actually carried it (under
    ESET's own key or a recognized alias — see src/services/normalizer.py).
    Anything the sender did not send stays None, and None fields are left out
    when the alert is serialized: the persisted result file, the dashboard API
    and the AI prompt never show a placeholder for a field that was not in
    the raw request. `present_fields()` is the one way to ask what was sent.
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
    # "true" / "false" (or the sender's own wording) only when reported. A
    # missing value is not "false": nothing says the threat was left unhandled.
    threat_handled: str | None = Field(default=None)
    isolation_status: str | None = Field(default=None)
    object_type: str | None = Field(default=None)
    object_uri: str | None = Field(default=None)
    file_hash: str | None = Field(default=None)
    url: str | None = Field(default=None)
    ip_address: str | None = Field(default=None)
    domain: str | None = Field(default=None)
    raw_subject: str | None = Field(default=None)
    raw_content: str | None = Field(default=None)
    raw_payload: dict[str, Any] = Field(default_factory=dict)

    @model_serializer(mode="wrap")
    def _omit_absent_fields(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        """Absent fields are omitted, never written out as null or a placeholder."""
        return {key: value for key, value in handler(self).items() if value is not None}

    def present_fields(self) -> dict[str, str]:
        """The alert fields that were actually reported, in declaration order
        (raw_payload excluded)."""
        return {
            name: value for name, value in self
            if name != "raw_payload" and isinstance(value, str) and value.strip()
        }
