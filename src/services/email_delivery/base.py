"""
Provider-agnostic contract for actually delivering an email.

The pipeline only ever talks to this interface, so swapping ESET Mail for SES,
SendGrid or an SMTP relay is a new subclass plus one config value — nothing in
the orchestrator, dispatcher or outbox changes.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from src.models.email_message import EmailMessage


@dataclass
class DeliveryResult:
    """Outcome of a single delivery attempt."""
    success: bool
    remote_id: str | None = None     # provider-side id, for cross-referencing
    error: str | None = None
    status_code: int | None = None
    retryable: bool = True           # False for permanent errors (bad auth, bad payload)

    @classmethod
    def ok(cls, remote_id: str | None, status_code: int | None = None) -> "DeliveryResult":
        return cls(success=True, remote_id=remote_id, status_code=status_code)

    @classmethod
    def fail(cls, error: str, status_code: int | None = None, retryable: bool = True) -> "DeliveryResult":
        return cls(success=False, error=error, status_code=status_code, retryable=retryable)


class EmailDeliveryProvider(ABC):
    """A transport capable of sending one EmailMessage."""

    name: str = "base"

    @abstractmethod
    async def send(self, message: EmailMessage) -> DeliveryResult:
        """Deliver a single message. Must not raise — return a failed DeliveryResult instead."""

    @abstractmethod
    def is_configured(self) -> tuple[bool, str]:
        """(ready, reason). Lets the dashboard explain *why* delivery is off."""
