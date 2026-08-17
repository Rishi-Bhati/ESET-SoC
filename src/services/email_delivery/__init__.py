"""
Email delivery providers.

`get_provider()` is the only thing the rest of the codebase imports, so adding a
transport means registering it here — no other module changes.
"""
import structlog
from src.config import settings
from src.services.email_delivery.base import DeliveryResult, EmailDeliveryProvider
from src.services.email_delivery.eset_mail import EsetMailProvider

logger = structlog.get_logger(__name__)

_PROVIDERS: dict[str, type[EmailDeliveryProvider]] = {
    EsetMailProvider.name: EsetMailProvider,
}


def get_provider(name: str | None = None) -> EmailDeliveryProvider:
    key = (name or settings.email_provider or "eset_mail").strip().lower()
    provider_cls = _PROVIDERS.get(key)
    if provider_cls is None:
        logger.warning("email_provider_unknown", requested=key, known=list(_PROVIDERS))
        provider_cls = EsetMailProvider
    return provider_cls()


__all__ = ["get_provider", "EmailDeliveryProvider", "DeliveryResult", "EsetMailProvider"]
