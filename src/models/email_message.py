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
    body: str  # plain text — what the dashboard shows
    # The formatted version handed to the mail service (src/services/email_layout.py).
    # None for messages queued before HTML emails existed; those go out as `body`.
    html: str | None = None
    risk_level: str
    # None when the alert did not report it (never a placeholder).
    endpoint_name: str | None = None
    detection_name: str | None = None
    created_at: str
    status: str = Field(default="PENDING")  # forward-compat with real sending later
