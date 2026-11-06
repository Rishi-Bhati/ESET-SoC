"""
DEFERRED FEATURE: emails the client when an engineer adds a recommendation.
Not wired up yet — the client wants it later. The recipient list is
settings_store.get_effective_with_fallback("recommendation_notification_emails",
"client_notification_emails").
"""
from typing import Any


async def notify_recommendation_added(recommendation: dict[str, Any]) -> dict[str, Any]:
    """
    Queues a notification email for a new recommendation (record from
    storage/recommendation_store.py) and stores its id via
    recommendation_store.set_notification_email_id. Returns
    {"queued": bool, "email_id": str | None, "reason": str | None}.
    """
    raise NotImplementedError
