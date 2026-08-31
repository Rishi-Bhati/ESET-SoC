import os
import tempfile
import json
import asyncio
from datetime import datetime, timezone
from typing import Any
import structlog
from src.models.email_message import EmailMessage
from src.storage import delivery_store
from src.utils import events

logger = structlog.get_logger(__name__)

OUTBOX_DIR = "output/emails"
OUTBOX_PATH = os.path.join(OUTBOX_DIR, "outbox.json")
# Emails that will never be handed off. Giving up on a notification is not the
# same as it never having existed: a CRITICAL alert that could not be delivered
# has to remain recoverable and visible, not be dropped on the floor.
DEAD_LETTER_PATH = os.path.join(OUTBOX_DIR, "dead_letter.json")

# Lock to synchronize concurrent read-modify-write cycles on outbox.json
_outbox_lock = asyncio.Lock()


def _read_outbox() -> list[dict[str, Any]]:
    if not os.path.exists(OUTBOX_PATH):
        return []
    try:
        with open(OUTBOX_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("outbox_read_failed_reinitializing", error=str(e))
        return []


def _write_outbox(records: list[dict[str, Any]]) -> None:
    os.makedirs(OUTBOX_DIR, exist_ok=True)
    temp_fd, temp_path = tempfile.mkstemp(dir=OUTBOX_DIR, prefix="outbox_", suffix=".tmp")
    try:
        with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=2)
        os.replace(temp_path, OUTBOX_PATH)
    except Exception:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise


async def add_emails(messages: list[EmailMessage]) -> None:
    """
    Appends newly-composed emails to the pending outbox. The outbox file holds
    only pending entries — once real sending is wired in, delivered emails are
    removed via remove_email() rather than marked in place.
    """
    if not messages:
        return

    async with _outbox_lock:
        records = _read_outbox()
        records.extend(m.model_dump() for m in messages)
        _write_outbox(records)

    logger.info("outbox_emails_added", count=len(messages))

    for message in messages:
        # Register the delivery record before announcing it, so the dashboard
        # never sees a queued email that has no history row behind it.
        #
        # Guarded per message: these entries are already durable in the outbox,
        # so letting one failure abort the loop would leave every message behind
        # it queued but invisible — no delivery record and no dashboard event.
        try:
            await delivery_store.record_pending(message)
            await events.emit("email_queued", message.model_dump())
        except Exception as e:
            logger.error(
                "outbox_email_registration_failed",
                email_id=message.email_id, error=str(e),
            )


async def remove_email(email_id: str) -> None:
    """
    Removes a single email from the pending outbox (e.g. once actually sent by
    the future Email Service integration). Unused today, kept ready for that.
    """
    async with _outbox_lock:
        records = _read_outbox()
        remaining = [r for r in records if r.get("email_id") != email_id]
        if len(remaining) != len(records):
            _write_outbox(remaining)
            logger.info("outbox_email_removed", email_id=email_id)


async def list_emails() -> list[dict[str, Any]]:
    """Returns all currently-pending emails, for the dashboard outbox panel."""
    async with _outbox_lock:
        return _read_outbox()


def _read_dead_letter() -> list[dict[str, Any]]:
    if not os.path.exists(DEAD_LETTER_PATH):
        return []
    try:
        with open(DEAD_LETTER_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logger.warning("dead_letter_read_failed_reinitializing", error=str(e))
        return []


async def record_dead_letter(record: dict[str, Any], error: str | None) -> None:
    """
    Files an email that handoff has permanently given up on, with the reason.

    Called immediately before the entry leaves the outbox, so the notification
    survives the failure in a form an operator can inspect and replay by hand.
    Never raises: failing to file a dead letter must not also abort the sweep.
    """
    try:
        entry = dict(record)
        entry["failed_at"] = datetime.now(timezone.utc).isoformat()
        entry["error"] = error
        async with _outbox_lock:
            records = _read_dead_letter()
            records.append(entry)
            os.makedirs(OUTBOX_DIR, exist_ok=True)
            temp_fd, temp_path = tempfile.mkstemp(dir=OUTBOX_DIR, prefix="dead_", suffix=".tmp")
            try:
                with os.fdopen(temp_fd, "w", encoding="utf-8") as f:
                    json.dump(records, f, indent=2)
                os.replace(temp_path, DEAD_LETTER_PATH)
            except Exception:
                if os.path.exists(temp_path):
                    os.remove(temp_path)
                raise
        logger.warning(
            "email_dead_lettered",
            email_id=entry.get("email_id"), error=error,
        )
    except Exception as e:
        logger.error("dead_letter_write_failed", error=str(e))


async def list_dead_letters() -> list[dict[str, Any]]:
    """Returns permanently-failed emails, for the dashboard."""
    async with _outbox_lock:
        return _read_dead_letter()
