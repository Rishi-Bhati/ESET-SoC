"""
Engineer recommendations attached to an alert and shown to the client in the
portal. A recommendation is never edited or deleted: an engineer who got it wrong
retracts it (with a reason), and the original text stays in the audit trail.
Clients only ever see active (non-retracted) ones.

Record shape (a plain dict):
    id, correlation_id, body, author, created_at,
    retracted_at, retracted_by, retract_reason  (None while active),
    notification_email_id                        (None until a notification is queued)
"""
import time
import uuid
from typing import Any
import structlog
from src.storage.database import db_session

logger = structlog.get_logger(__name__)

MAX_BODY_LENGTH = 4000
MAX_AUTHOR_LENGTH = 200
MAX_REASON_LENGTH = 1000

_COLUMNS = (
    "id, correlation_id, body, author, created_at, retracted_at, retracted_by, "
    "retract_reason, notification_email_id"
)


def _row(row: Any) -> dict[str, Any]:
    return {
        "id": row[0],
        "correlation_id": row[1],
        "body": row[2],
        "author": row[3],
        "created_at": row[4],
        "retracted_at": row[5],
        "retracted_by": row[6],
        "retract_reason": row[7],
        "notification_email_id": row[8],
    }


def _new_id() -> str:
    return "rec_" + uuid.uuid4().hex[:16]


async def create(correlation_id: str, body: str, author: str) -> dict[str, Any]:
    """Adds a recommendation to an alert. Raises ValueError on blank/oversized
    text or a blank author/correlation_id. Does not check the alert exists —
    that is the caller's job (the API layer)."""
    body = (body or "").strip()
    author = (author or "").strip()
    correlation_id = (correlation_id or "").strip()
    if not correlation_id:
        raise ValueError("correlation_id is required")
    if not body:
        raise ValueError("Recommendation text is required")
    if len(body) > MAX_BODY_LENGTH:
        raise ValueError(f"Recommendation text must be at most {MAX_BODY_LENGTH} characters")
    if not author:
        raise ValueError("author is required")
    if len(author) > MAX_AUTHOR_LENGTH:
        raise ValueError(f"author must be at most {MAX_AUTHOR_LENGTH} characters")

    rec_id = _new_id()
    now = time.time()
    async with db_session() as conn:
        await conn.execute(
            "INSERT INTO alert_recommendations (id, correlation_id, body, author, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (rec_id, correlation_id, body, author, now),
        )
        await conn.commit()
    logger.info("recommendation_created", id=rec_id, correlation_id=correlation_id, author=author)
    return {
        "id": rec_id, "correlation_id": correlation_id, "body": body, "author": author,
        "created_at": now, "retracted_at": None, "retracted_by": None,
        "retract_reason": None, "notification_email_id": None,
    }


async def get(rec_id: str) -> dict[str, Any] | None:
    """One recommendation (retracted or not), or None."""
    async with db_session() as conn:
        async with conn.execute(
            f"SELECT {_COLUMNS} FROM alert_recommendations WHERE id = ?", (rec_id,)
        ) as cursor:
            row = await cursor.fetchone()
    return _row(row) if row else None


async def list_for_alert(correlation_id: str, include_retracted: bool = False) -> list[dict[str, Any]]:
    """An alert's recommendations, oldest first. Active only unless include_retracted."""
    query = f"SELECT {_COLUMNS} FROM alert_recommendations WHERE correlation_id = ?"
    if not include_retracted:
        query += " AND retracted_at IS NULL"
    query += " ORDER BY created_at ASC, id ASC"
    async with db_session() as conn:
        async with conn.execute(query, (correlation_id,)) as cursor:
            return [_row(r) async for r in cursor]


# SQLite's default bound-variable limit is 999 on older builds; stay well under it.
_CHUNK = 500


def _chunks(items: list[str]) -> list[list[str]]:
    return [items[i:i + _CHUNK] for i in range(0, len(items), _CHUNK)]


async def list_for_alerts(correlation_ids: list[str]) -> dict[str, list[dict[str, Any]]]:
    """Active recommendations for many alerts at once, oldest first. Every requested
    id is a key in the result (an empty list when it has none)."""
    ids = list(dict.fromkeys(correlation_ids))
    result: dict[str, list[dict[str, Any]]] = {cid: [] for cid in ids}
    if not ids:
        return result
    async with db_session() as conn:
        for chunk in _chunks(ids):
            marks = ",".join("?" * len(chunk))
            async with conn.execute(
                f"SELECT {_COLUMNS} FROM alert_recommendations "
                f"WHERE correlation_id IN ({marks}) AND retracted_at IS NULL "
                "ORDER BY created_at ASC, id ASC",
                chunk,
            ) as cursor:
                async for r in cursor:
                    result[r[1]].append(_row(r))
    return result


async def counts(correlation_ids: list[str]) -> dict[str, int]:
    """Number of ACTIVE recommendations per alert. Every requested id is a key
    (0 when none)."""
    ids = list(dict.fromkeys(correlation_ids))
    result: dict[str, int] = {cid: 0 for cid in ids}
    if not ids:
        return result
    async with db_session() as conn:
        for chunk in _chunks(ids):
            marks = ",".join("?" * len(chunk))
            async with conn.execute(
                "SELECT correlation_id, COUNT(*) FROM alert_recommendations "
                f"WHERE correlation_id IN ({marks}) AND retracted_at IS NULL "
                "GROUP BY correlation_id",
                chunk,
            ) as cursor:
                async for cid, n in cursor:
                    result[cid] = n
    return result


async def retract(rec_id: str, by: str, reason: str) -> dict[str, Any] | None:
    """
    Withdraws a recommendation; it disappears from the client's view but stays on
    record. Returns the updated record, or None if the id does not exist.
    Idempotent: retracting an already-retracted one returns it unchanged (the
    first retraction's author/reason are kept). Raises ValueError on a blank `by`.
    """
    by = (by or "").strip()
    reason = (reason or "").strip()
    if not by:
        raise ValueError("retracted_by is required")
    if len(reason) > MAX_REASON_LENGTH:
        raise ValueError(f"Reason must be at most {MAX_REASON_LENGTH} characters")
    now = time.time()
    async with db_session() as conn:
        await conn.execute(
            "UPDATE alert_recommendations SET retracted_at = ?, retracted_by = ?, retract_reason = ? "
            "WHERE id = ? AND retracted_at IS NULL",
            (now, by, reason or None, rec_id),
        )
        await conn.commit()
    rec = await get(rec_id)
    if rec and rec["retracted_by"] == by and rec["retracted_at"] == now:
        logger.info("recommendation_retracted", id=rec_id, by=by)
    return rec


async def list_all(include_retracted: bool = True) -> list[dict[str, Any]]:
    """Every recommendation on record, in one query, ordered by alert then oldest
    first. Retracted ones included by default — this is the engineering export's
    audit view (src/services/alert_export.py); never hand it to a client."""
    query = f"SELECT {_COLUMNS} FROM alert_recommendations"
    if not include_retracted:
        query += " WHERE retracted_at IS NULL"
    query += " ORDER BY correlation_id ASC, created_at ASC, id ASC"
    async with db_session() as conn:
        async with conn.execute(query) as cursor:
            return [_row(r) async for r in cursor]


async def set_notification_email_id(rec_id: str, email_id: str) -> None:
    """Records which queued email notified the client about this recommendation."""
    async with db_session() as conn:
        await conn.execute(
            "UPDATE alert_recommendations SET notification_email_id = ? WHERE id = ?",
            (email_id, rec_id),
        )
        await conn.commit()
