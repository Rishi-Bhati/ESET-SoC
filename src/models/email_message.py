from pydantic import BaseModel, Field


class EmailAttachment(BaseModel):
    """A file sent with an email. Content is base64 so the message stays JSON-serialisable
    in outbox.json."""
    filename: str
    content_type: str
    content_base64: str
    size_bytes: int


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
    # Files to attach (e.g. the weekly report workbook). Absent in outbox files
    # written before attachments existed, which still load with an empty list.
    attachments: list[EmailAttachment] = Field(default_factory=list)
    # Overrides the idempotency key sent to the mail service. Normally unset: the
    # provider derives a stable key from email_id + recipients (see
    # EsetMailProvider.idempotency_key_for), which is the same on every retry of
    # the same logical email.
    idempotency_key: str | None = None
