"""
Hands queued emails off to the mail service.

Division of responsibility — the ESET Mail worker owns the send queue: it
persists each accepted email in D1, retries failures, recovers messages stuck
mid-send, and dispatches over SMTP on its own cron. None of that is duplicated
here. This module's only job is to get each composed email *accepted* (HTTP 202)
exactly once, and to retry when the handoff itself fails.

Lifecycle of one email in this platform:

    composed -> outbox.json (+ delivery record PENDING)
        -> handoff attempt
             202 accepted        -> removed from outbox, recorded ACCEPTED + remote_id
             transport / 5xx     -> stays in outbox, retried by the sweeper
             bad request / auth  -> removed from outbox, recorded FAILED
             attempts exhausted  -> removed from outbox, recorded FAILED

After ACCEPTED the message belongs to the mail service; its delivery outcome is
visible there under the stored `remote_id`.
"""
import asyncio
from typing import Any
import structlog
from src.config import settings
from src.models.email_message import EmailMessage
from src.services import email_outbox
from src.services.email_delivery import get_provider
from src.storage import delivery_store
from src.utils import events

logger = structlog.get_logger(__name__)

# Serialises handoff runs so the sweeper, the pipeline trigger and a dashboard
# click can never hand the same queued email off twice.
_dispatch_lock = asyncio.Lock()


def delivery_status() -> dict[str, Any]:
    """Whether handoff is on and correctly configured — surfaced in the dashboard."""
    provider = get_provider()
    ready, reason = provider.is_configured()
    return {
        "enabled": settings.email_delivery_enabled,
        "provider": provider.name,
        "configured": ready,
        "reason": reason,
        "endpoint": settings.email_api_url,
        "security_mode": settings.email_security_mode,
        "max_attempts": settings.email_max_attempts,
        "dispatch_interval_seconds": settings.email_dispatch_interval_seconds,
        # Blank when the mail service is left to apply its own default/priority
        # order across its configured senders.
        "sender_routing": getattr(provider, "sender_routing", dict)(),
    }


async def dispatch_pending(limit: int = 50) -> dict[str, Any]:
    """
    Attempts handoff of everything currently queued. Returns a summary; never
    raises, so a mail-service outage cannot disturb the ingestion pipeline.
    """
    if not settings.email_delivery_enabled:
        return {"skipped": "delivery disabled", "accepted": 0, "failed": 0, "pending": 0}

    provider = get_provider()
    ready, reason = provider.is_configured()
    if not ready:
        logger.warning("email_dispatch_not_configured", reason=reason)
        return {"skipped": reason, "accepted": 0, "failed": 0, "pending": 0}

    async with _dispatch_lock:
        queued = await email_outbox.list_emails()
        if not queued:
            return {"accepted": 0, "failed": 0, "pending": 0}

        accepted = failed = 0
        for raw in queued[:limit]:
            try:
                message = EmailMessage(**raw)
            except Exception as e:
                # An unparseable entry would block the queue forever — drop it.
                logger.error("email_outbox_entry_invalid", error=str(e), entry=str(raw)[:200])
                await email_outbox.record_dead_letter(raw, f"unparseable outbox entry: {e}")
                await email_outbox.remove_email(raw.get("email_id", ""))
                failed += 1
                continue

            try:
                outcome = await _hand_off(provider, message)
            except Exception as e:
                # A provider is contractually forbidden from raising here
                # (see base.EmailDeliveryProvider.send). If one ever does, the
                # sweep must still drain the rest of the queue rather than
                # aborting and re-hitting the same entry on every later run.
                logger.error(
                    "email_handoff_raised",
                    email_id=message.email_id, error=str(e),
                )
                await email_outbox.record_dead_letter(raw, f"handoff raised: {e}")
                await email_outbox.remove_email(message.email_id)
                await delivery_store.record_attempt(
                    message.email_id, delivery_store.FAILED, error=str(e)
                )
                failed += 1
                continue

            if outcome == "accepted":
                accepted += 1
            elif outcome == "failed":
                failed += 1

        remaining = len(await email_outbox.list_emails())
        if accepted or failed:
            logger.info(
                "email_dispatch_complete",
                accepted=accepted, failed=failed, pending=remaining,
            )
        return {"accepted": accepted, "failed": failed, "pending": remaining}


async def _hand_off(provider: Any, message: EmailMessage) -> str:
    """Hands one message to the mail service and reconciles outbox + record."""
    await events.emit("email_sending", {"email_id": message.email_id})

    result = await provider.send(message)

    if result.success:
        await email_outbox.remove_email(message.email_id)
        await delivery_store.record_attempt(
            message.email_id, delivery_store.ACCEPTED, remote_id=result.remote_id
        )
        await events.emit("email_accepted", {
            "email_id": message.email_id,
            "correlation_id": message.correlation_id,
            "notification_type": message.notification_type,
            "to": message.to,
            "subject": message.subject,
            "remote_id": result.remote_id,
        })
        await events.emit_stage(
            message.correlation_id, "SEND", "ok",
            detail=f"{message.notification_type} accepted (#{result.remote_id})",
        )
        return "accepted"

    attempts = await delivery_store.get_attempts(message.email_id) + 1
    exhausted = attempts >= settings.email_max_attempts
    permanent = not result.retryable

    if permanent or exhausted:
        # File it before dropping it: giving up on a notification must not make
        # it disappear, least of all a CRITICAL one.
        await email_outbox.record_dead_letter(message.model_dump(), result.error)
        await email_outbox.remove_email(message.email_id)
        await delivery_store.record_attempt(
            message.email_id, delivery_store.FAILED, error=result.error
        )
        await events.emit("email_failed", {
            "email_id": message.email_id,
            "correlation_id": message.correlation_id,
            "error": result.error,
            "attempts": attempts,
            "permanent": permanent,
        })
        await events.emit_stage(
            message.correlation_id, "SEND", "failed",
            detail=(result.error or "handoff failed")[:120],
        )
        logger.error(
            "email_handoff_gave_up",
            email_id=message.email_id, attempts=attempts,
            permanent=permanent, error=result.error,
        )
        return "failed"

    # Retryable: leave it queued for the next sweep
    await delivery_store.record_attempt(
        message.email_id, delivery_store.PENDING, error=result.error
    )
    logger.warning(
        "email_handoff_will_retry",
        email_id=message.email_id, attempts=attempts, error=result.error,
    )
    return "retry"


async def dispatch_soon(delay: float = 0.0) -> None:
    """Fire-and-forget handoff used by the pipeline once emails are queued."""
    try:
        if delay:
            await asyncio.sleep(delay)
        await dispatch_pending()
    except Exception as e:
        logger.error("email_dispatch_task_failed", error=str(e))


async def run_dispatch_loop() -> None:
    """
    Periodic sweeper for emails that could not be handed off — a mail-service
    outage, a transient network failure, or messages composed while delivery was
    switched off. Successfully accepted emails are already gone from the outbox,
    so this never re-sends them.
    """
    interval = max(10, settings.email_dispatch_interval_seconds)
    logger.info("email_dispatch_loop_started", interval_seconds=interval)
    while True:
        try:
            await asyncio.sleep(interval)
            await dispatch_pending()
        except asyncio.CancelledError:
            logger.info("email_dispatch_loop_stopped")
            raise
        except Exception as e:
            logger.error("email_dispatch_loop_error", error=str(e))
