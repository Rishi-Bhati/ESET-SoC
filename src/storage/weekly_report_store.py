"""
Weekly report runs (table weekly_reports), one row per period_key (e.g. "2026-W45",
the ISO week reported on). period_key is the idempotency key: claim() is atomic, so
a restart, a second instance or a manual click cannot produce two reports for the same week.

Row (dict): period_key, period_start, period_end (epoch floats), status, trigger
("scheduled" | "manual" | "baseline"), claimed_at, completed_at, email_id,
recipients (list[str]), counts (dict, parsed from counts_json, without "findings"),
findings (list[dict], stored in counts_json under "findings"), file_path,
file_sha256, attachment_included (bool), resend_count, attempts, error.
"""
import json
import time
from typing import Any
import structlog
from src.storage.database import db_session

logger = structlog.get_logger(__name__)

# status values
CLAIMED = "CLAIMED"              # a runner owns the period and is generating
GENERATED = "GENERATED"          # workbook archived + counts stored; email not enabled
QUEUED = "QUEUED"                # ... and the report email was put in the outbox
SENT = "SENT"                    # kept for compatibility (email handed off); not written today
NO_RECIPIENTS = "NO_RECIPIENTS"  # generated, email enabled but no recipients configured
FAILED = "FAILED"                # generation or queueing failed; may be re-claimed
SKIPPED = "SKIPPED"              # deliberately not produced (e.g. the baseline on first enable)
STATUSES: tuple[str, ...] = (CLAIMED, GENERATED, QUEUED, SENT, NO_RECIPIENTS, FAILED, SKIPPED)

# Statuses that end a run (stamp completed_at).
TERMINAL: frozenset[str] = frozenset({GENERATED, QUEUED, SENT, NO_RECIPIENTS, FAILED, SKIPPED})

# A CLAIMED row older than this is considered abandoned (crashed runner) and can be re-claimed.
STALE_CLAIM_SECONDS = 15 * 60

_COLUMNS = (
    "period_key, period_start, period_end, status, trigger, claimed_at, completed_at, "
    "email_id, recipients, counts_json, file_path, file_sha256, attachment_included, "
    "resend_count, attempts, error"
)


def _loads(text: Any, default: Any) -> Any:
    if not text:
        return default
    try:
        value = json.loads(text)
    except (TypeError, ValueError):
        return default
    return value if isinstance(value, type(default)) else default


def _row(r: Any) -> dict[str, Any]:
    counts = _loads(r[9], {})
    findings = counts.pop("findings", [])
    return {
        "period_key": r[0], "period_start": r[1], "period_end": r[2], "status": r[3],
        "trigger": r[4], "claimed_at": r[5], "completed_at": r[6], "email_id": r[7],
        "recipients": _loads(r[8], []), "counts": counts,
        "findings": findings if isinstance(findings, list) else [],
        "file_path": r[10], "file_sha256": r[11], "attachment_included": bool(r[12]),
        "resend_count": r[13] or 0, "attempts": r[14] or 0, "error": r[15],
    }


async def claim(
    period_key: str, period_start: float, period_end: float, trigger: str,
    *, now: float | None = None, max_attempts: int | None = None,
) -> bool:
    """
    Atomically takes ownership of a period. True = this caller must produce the
    report; False = already finished (GENERATED/QUEUED/SKIPPED/...), or actively
    CLAIMED by someone else. A FAILED row or a stale CLAIMED row is re-claimed
    (attempts += 1). `max_attempts` (scheduler) leaves a FAILED row alone once it
    has been tried that many times; a manual run passes None (no limit).
    """
    now = time.time() if now is None else now
    async with db_session() as conn:
        cursor = await conn.execute(
            """
            INSERT INTO weekly_reports
                (period_key, period_start, period_end, status, trigger, claimed_at, attempts)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(period_key) DO NOTHING
            """,
            (period_key, period_start, period_end, CLAIMED, trigger, now),
        )
        if cursor.rowcount == 1:
            await conn.commit()
            return True
        limit = max_attempts if max_attempts is not None else 2**31
        cursor = await conn.execute(
            """
            UPDATE weekly_reports
            SET status = ?, trigger = ?, claimed_at = ?, completed_at = NULL,
                attempts = attempts + 1, error = NULL
            WHERE period_key = ?
              AND ((status = ? AND attempts < ?) OR (status = ? AND claimed_at < ?))
            """,
            (CLAIMED, trigger, now, period_key, FAILED, limit, CLAIMED, now - STALE_CLAIM_SECONDS),
        )
        await conn.commit()
        return cursor.rowcount == 1


async def reclaim_for_regenerate(period_key: str, trigger: str, *, now: float | None = None) -> bool:
    """
    Takes ownership of an already-finished period to regenerate it (manual
    "regenerate"). False when the row does not exist or a fresh CLAIMED run owns it.
    """
    now = time.time() if now is None else now
    async with db_session() as conn:
        cursor = await conn.execute(
            """
            UPDATE weekly_reports
            SET status = ?, trigger = ?, claimed_at = ?, completed_at = NULL,
                attempts = attempts + 1, error = NULL
            WHERE period_key = ? AND (status != ? OR claimed_at < ?)
            """,
            (CLAIMED, trigger, now, period_key, CLAIMED, now - STALE_CLAIM_SECONDS),
        )
        await conn.commit()
        return cursor.rowcount == 1


async def record_skipped(
    period_key: str, period_start: float, period_end: float, trigger: str, reason: str,
) -> bool:
    """Inserts a SKIPPED row unless the period already has one. True if inserted."""
    now = time.time()
    async with db_session() as conn:
        cursor = await conn.execute(
            """
            INSERT INTO weekly_reports
                (period_key, period_start, period_end, status, trigger, claimed_at,
                 completed_at, attempts, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?)
            ON CONFLICT(period_key) DO NOTHING
            """,
            (period_key, period_start, period_end, SKIPPED, trigger, now, now, reason),
        )
        await conn.commit()
        return cursor.rowcount == 1


async def count() -> int:
    """Number of rows (0 = the report has never run or been baselined)."""
    async with db_session() as conn:
        async with conn.execute("SELECT COUNT(*) FROM weekly_reports") as cursor:
            return (await cursor.fetchone())[0]


async def get(period_key: str) -> dict[str, Any] | None:
    """One run, or None."""
    async with db_session() as conn:
        async with conn.execute(
            f"SELECT {_COLUMNS} FROM weekly_reports WHERE period_key = ?", (period_key,)
        ) as cursor:
            row = await cursor.fetchone()
    return _row(row) if row else None


async def list_reports(limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
    """Runs, newest period first."""
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    async with db_session() as conn:
        async with conn.execute(
            f"SELECT {_COLUMNS} FROM weekly_reports "
            "ORDER BY period_start DESC, period_key DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ) as cursor:
            return [_row(r) async for r in cursor]


async def update_status(
    period_key: str,
    status: str,
    *,
    email_id: str | None = None,
    recipients: list[str] | None = None,
    counts: dict[str, Any] | None = None,
    findings: list[dict[str, Any]] | None = None,
    file_path: str | None = None,
    file_sha256: str | None = None,
    attachment_included: bool | None = None,
    error: str | None = None,
    clear_file: bool = False,
) -> None:
    """Sets the status and any provided fields (None = leave unchanged). Terminal
    statuses (everything but CLAIMED) also stamp completed_at. `findings` is stored
    inside counts_json under "findings" (replacing any previous list when given).
    clear_file=True blanks file_path/file_sha256 (a regenerated period with no file)."""
    if status not in STATUSES:
        raise ValueError(f"unknown weekly report status: {status!r}")
    sets = ["status = ?"]
    params: list[Any] = [status]
    if status in TERMINAL:
        sets.append("completed_at = ?")
        params.append(time.time())
    if email_id is not None:
        sets.append("email_id = ?")
        params.append(email_id)
    if recipients is not None:
        sets.append("recipients = ?")
        params.append(json.dumps(list(recipients)))
    if counts is not None or findings is not None:
        merged: dict[str, Any] = {}
        if counts is None or findings is None:
            existing = await get(period_key)
            if existing:
                merged.update(existing["counts"])
                merged["findings"] = existing["findings"]
        if counts is not None:
            keep = merged.get("findings")
            merged = dict(counts)
            if keep is not None:
                merged["findings"] = keep
        if findings is not None:
            merged["findings"] = list(findings)
        sets.append("counts_json = ?")
        params.append(json.dumps(merged, ensure_ascii=False))
    if clear_file:
        sets += ["file_path = NULL", "file_sha256 = NULL"]
    else:
        if file_path is not None:
            sets.append("file_path = ?")
            params.append(file_path)
        if file_sha256 is not None:
            sets.append("file_sha256 = ?")
            params.append(file_sha256)
    if attachment_included is not None:
        sets.append("attachment_included = ?")
        params.append(1 if attachment_included else 0)
    if error is not None:
        sets.append("error = ?")
        params.append(error)
    params.append(period_key)
    async with db_session() as conn:
        await conn.execute(f"UPDATE weekly_reports SET {', '.join(sets)} WHERE period_key = ?", params)
        await conn.commit()


async def increment_resend(period_key: str) -> int:
    """Bumps resend_count for a manual re-send; returns the new count (0 if no row)."""
    async with db_session() as conn:
        await conn.execute(
            "UPDATE weekly_reports SET resend_count = COALESCE(resend_count, 0) + 1 WHERE period_key = ?",
            (period_key,),
        )
        await conn.commit()
        async with conn.execute(
            "SELECT resend_count FROM weekly_reports WHERE period_key = ?", (period_key,)
        ) as cursor:
            row = await cursor.fetchone()
    return int(row[0]) if row else 0
