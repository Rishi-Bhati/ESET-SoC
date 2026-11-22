"""
Hidden alerts: kept on the server (database rows, result files, emails, AI traces
all untouched) but left out of every dashboard view, the client portal, exports
and the weekly / on-demand reports. Used for test alerts. Unhiding brings an
alert back everywhere at once.

Where it is applied:
  * alert_index_store._where  -> client portal list, stats, export; weekly and
                                 on-demand reports (everything built on the index)
  * api/client.alert_detail    -> a hidden alert's portal detail page is 404
  * job_store.list_jobs        -> dashboard activity table and stats
  * api/dashboard              -> Alerts view, AI Content view, stats risk split
  * alert_export               -> dashboard spreadsheet export

The dashboard's per-alert detail (/dashboard/api/jobs/{id}) still opens a hidden
alert, so engineers can look at one by id.
"""
import time
from typing import Any, Iterable

import structlog

from src.storage.database import db_session

logger = structlog.get_logger(__name__)

# Appended to WHERE clauses on tables keyed by correlation_id.
NOT_HIDDEN_SQL = "correlation_id NOT IN (SELECT correlation_id FROM hidden_alerts)"


def _clean(ids: Iterable[str]) -> list[str]:
    return sorted({str(i).strip() for i in ids if str(i).strip()})


async def hide(ids: Iterable[str], hidden_by: str | None = None, reason: str | None = None) -> int:
    """Hides the alerts; returns how many were newly hidden (already hidden ones are left as they are)."""
    ids = _clean(ids)
    if not ids:
        return 0
    now = time.time()
    async with db_session() as conn:
        cursor = await conn.executemany(
            "INSERT INTO hidden_alerts (correlation_id, hidden_at, hidden_by, reason) VALUES (?,?,?,?) "
            "ON CONFLICT(correlation_id) DO NOTHING",
            [(i, now, hidden_by, reason) for i in ids],
        )
        await conn.commit()
        count = cursor.rowcount if cursor.rowcount is not None and cursor.rowcount >= 0 else len(ids)
    logger.info("alerts_hidden", count=count, hidden_by=hidden_by, reason=reason)
    return count


async def unhide(ids: Iterable[str]) -> int:
    """Brings the alerts back; returns how many were hidden."""
    ids = _clean(ids)
    if not ids:
        return 0
    async with db_session() as conn:
        cursor = await conn.execute(
            f"DELETE FROM hidden_alerts WHERE correlation_id IN ({','.join('?' * len(ids))})", ids
        )
        await conn.commit()
        count = cursor.rowcount
    logger.info("alerts_unhidden", count=count)
    return count


async def hidden_ids() -> set[str]:
    async with db_session() as conn:
        async with conn.execute("SELECT correlation_id FROM hidden_alerts") as cursor:
            return {row[0] async for row in cursor}


async def is_hidden(correlation_id: str) -> bool:
    async with db_session() as conn:
        async with conn.execute(
            "SELECT 1 FROM hidden_alerts WHERE correlation_id = ?", (correlation_id,)
        ) as cursor:
            return await cursor.fetchone() is not None


async def list_hidden() -> list[dict[str, Any]]:
    async with db_session() as conn:
        async with conn.execute(
            "SELECT correlation_id, hidden_at, hidden_by, reason FROM hidden_alerts ORDER BY hidden_at DESC"
        ) as cursor:
            return [
                {"correlation_id": r[0], "hidden_at": r[1], "hidden_by": r[2], "reason": r[3]}
                async for r in cursor
            ]
