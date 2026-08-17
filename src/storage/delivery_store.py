"""
Handoff history for outbound notification emails.

The ESET Mail worker owns the actual send queue — retries, stuck-message
recovery and SMTP dispatch all happen there. This platform's responsibility ends
once the worker returns 202 and takes ownership, so the states recorded here are
about *handoff*, not final delivery:

    PENDING   still in outbox.json, not yet accepted by the mail service
    ACCEPTED  handed off successfully; `remote_id` is the worker's queue id
    FAILED    we could not hand it off and gave up

Final delivery outcome (sent / bounced) lives in the mail service's own
dashboard, keyed by `remote_id`.
"""
import json
import time
from typing import Any
import structlog
from src.storage.database import db_session

logger = structlog.get_logger(__name__)

PENDING, ACCEPTED, FAILED = "PENDING", "ACCEPTED", "FAILED"


async def record_pending(message: Any) -> None:
    """Registers a freshly composed email. Idempotent on email_id."""
    now = time.time()
    async with db_session() as conn:
        await conn.execute(
            """
            INSERT INTO email_deliveries
                (email_id, correlation_id, notification_type, recipients, subject,
                 status, attempts, remote_id, error, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 0, NULL, NULL, ?, ?)
            ON CONFLICT(email_id) DO NOTHING
            """,
            (message.email_id, message.correlation_id, message.notification_type,
             json.dumps(message.to), message.subject, PENDING, now, now),
        )
        await conn.commit()


async def record_attempt(
    email_id: str,
    status: str,
    error: str | None = None,
    remote_id: str | None = None,
) -> None:
    """Records the outcome of one handoff attempt, incrementing the counter."""
    now = time.time()
    async with db_session() as conn:
        await conn.execute(
            """
            UPDATE email_deliveries
            SET status = ?, error = ?, remote_id = COALESCE(?, remote_id),
                attempts = attempts + 1, updated_at = ?
            WHERE email_id = ?
            """,
            (status, error, remote_id, now, email_id),
        )
        await conn.commit()
    logger.info("email_delivery_recorded", email_id=email_id, status=status)


async def get_delivery(email_id: str) -> dict[str, Any] | None:
    async with db_session() as conn:
        async with conn.execute(
            """
            SELECT email_id, correlation_id, notification_type, recipients, subject,
                   status, attempts, remote_id, error, created_at, updated_at
            FROM email_deliveries WHERE email_id = ?
            """,
            (email_id,),
        ) as cursor:
            row = await cursor.fetchone()
            return _row(row) if row else None


async def list_deliveries(limit: int = 100, status: str | None = None) -> list[dict[str, Any]]:
    query = """
        SELECT email_id, correlation_id, notification_type, recipients, subject,
               status, attempts, remote_id, error, created_at, updated_at
        FROM email_deliveries
    """
    params: list[Any] = []
    if status:
        query += " WHERE status = ?"
        params.append(status)
    query += " ORDER BY updated_at DESC LIMIT ?"
    params.append(limit)

    out = []
    async with db_session() as conn:
        async with conn.execute(query, params) as cursor:
            async for row in cursor:
                out.append(_row(row))
    return out


async def counts_by_status() -> dict[str, int]:
    out = {PENDING: 0, ACCEPTED: 0, FAILED: 0}
    async with db_session() as conn:
        async with conn.execute(
            "SELECT status, COUNT(*) FROM email_deliveries GROUP BY status"
        ) as cursor:
            async for status, count in cursor:
                out[status] = count
    return out


async def get_attempts(email_id: str) -> int:
    record = await get_delivery(email_id)
    return record["attempts"] if record else 0


def _row(row: Any) -> dict[str, Any]:
    try:
        recipients = json.loads(row[3])
    except Exception:
        recipients = []
    return {
        "email_id": row[0],
        "correlation_id": row[1],
        "notification_type": row[2],
        "recipients": recipients,
        "subject": row[4],
        "status": row[5],
        "attempts": row[6],
        "remote_id": row[7],
        "error": row[8],
        "created_at": row[9],
        "updated_at": row[10],
    }
