from pydantic import BaseModel, Field


class EmailMessage(BaseModel):
    """
    A single outbound notification email staged for later delivery.
    Written to the pending-emails outbox (see src/services/email_outbox.py) —
    a stepping stone toward the separate Email Service integration.
    """
    email_id: str
    correlation_id: str
    notification_type: str  # CLIENT_JA, CTHREE_JA, INTERNAL_JA, ENGINEER_EN
    to: list[str]
    subject: str
    body: str
    risk_level: str
    endpoint_name: str
    detection_name: str
    created_at: str
    status: str = Field(default="PENDING")  # forward-compat with real sending later
