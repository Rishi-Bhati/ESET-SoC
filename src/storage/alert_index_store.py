"""
Query index over alerts (table alert_index), so the client portal can filter, count
and page without opening every result file. The result JSON files and `jobs` table
remain the source of truth; this table is derived and can always be rebuilt with
reconcile().

An index row is a dict:
    correlation_id, source, received_at (float epoch), processed_at (float|None),
    pipeline_status, risk_level, eset_severity, eset_alert_id, detection_name,
    endpoint_name, has_ai_output (bool), updated_at

The client portal shows only finished alerts, hence the default `statuses`.
"""
import asyncio
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Collection
import structlog
from src.config import settings
from src.models.pipeline_result import PipelineResult
from src.storage.database import db_session

logger = structlog.get_logger(__name__)

DEFAULT_STATUSES: frozenset[str] = frozenset({"SUCCESS", "PARTIAL"})
RISK_ORDER: tuple[str, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

MAX_LIMIT = 10_000
_CHUNK = 500  # SQLite's bound-variable limit is 999 on older builds

_COLUMNS = (
    "correlation_id, source, received_at, processed_at, pipeline_status, risk_level, "
    "eset_severity, eset_alert_id, detection_name, endpoint_name, has_ai_output, updated_at"
)

_INSERT_SQL = f"""
    INSERT INTO alert_index ({_COLUMNS})
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""
_UPSERT_SQL = _INSERT_SQL + """
    ON CONFLICT(correlation_id) DO UPDATE SET
        source = excluded.source,
        received_at = excluded.received_at,
        processed_at = excluded.processed_at,
        pipeline_status = excluded.pipeline_status,
        risk_level = excluded.risk_level,
        eset_severity = excluded.eset_severity,
        eset_alert_id = excluded.eset_alert_id,
        detection_name = excluded.detection_name,
        endpoint_name = excluded.endpoint_name,
        has_ai_output = excluded.has_ai_output,
        updated_at = excluded.updated_at
"""


def iso_to_epoch(value: Any) -> float | None:
    """ISO 8601 string -> epoch seconds (a naive time is taken as UTC); None if unparseable."""
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _row_params(
    *, correlation_id: str, source: str | None, received_at: float, processed_at: float | None,
    pipeline_status: str | None, risk_level: str | None, normalized: dict[str, Any] | None,
    has_ai_output: bool,
) -> tuple[Any, ...]:
    n = normalized or {}
    return (
        correlation_id, source, received_at, processed_at, pipeline_status,
        (risk_level or "").upper() or None,
        n.get("severity"), n.get("alert_id"), n.get("detection_name"), n.get("endpoint_name"),
        1 if has_ai_output else 0, time.time(),
    )


def _params_from_result(result: PipelineResult, job_created_at: float) -> tuple[Any, ...]:
    return _row_params(
        correlation_id=result.correlation_id, source=result.source,
        received_at=float(job_created_at), processed_at=iso_to_epoch(result.processed_at),
        pipeline_status=result.pipeline_status, risk_level=result.risk_level,
        normalized=result.normalized_alert.model_dump(), has_ai_output=result.ai_output is not None,
    )


def _as_dict(row: Any) -> dict[str, Any]:
    return {
        "correlation_id": row[0], "source": row[1], "received_at": row[2], "processed_at": row[3],
        "pipeline_status": row[4], "risk_level": row[5], "eset_severity": row[6],
        "eset_alert_id": row[7], "detection_name": row[8], "endpoint_name": row[9],
        "has_ai_output": bool(row[10]), "updated_at": row[11],
    }


async def get_job_created_at(correlation_id: str) -> float | None:
    """When the platform accepted the alert (jobs.created_at), or None if there is no job."""
    async with db_session() as conn:
        async with conn.execute(
            "SELECT created_at FROM jobs WHERE correlation_id = ?", (correlation_id,)
        ) as cursor:
            row = await cursor.fetchone()
    return float(row[0]) if row and row[0] is not None else None


async def upsert_from_result(result: PipelineResult, job_created_at: float) -> None:
    """Inserts/updates the index row for a finished pipeline result (called from the
    pipeline after write_result, and by reconcile). received_at is `job_created_at`
    (when the platform accepted the alert), not the sender's timestamp.
    One row per correlation_id: a pipeline retry overwrites the earlier row."""
    async with db_session() as conn:
        await conn.execute(_UPSERT_SQL, _params_from_result(result, job_created_at))
        await conn.commit()


def _list_result_files(directory: str) -> dict[str, str]:
    """correlation_id -> path for every result file (index.json and temp files excluded)."""
    found: dict[str, str] = {}
    try:
        entries = os.listdir(directory)
    except FileNotFoundError:
        return found
    for name in entries:
        if not name.endswith(".json") or name == "index.json":
            continue
        found[name[:-5]] = os.path.join(directory, name)
    return found


def _read_result_file(path: str) -> dict[str, Any] | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or not data.get("correlation_id"):
            return None
        return data
    except Exception as e:
        logger.warning("alert_index_result_unreadable", path=path, error=str(e))
        return None


async def reconcile() -> dict[str, int]:
    """
    Brings the index in line with the result files / jobs table: indexes results that
    are missing. Existing rows are left alone (they are written on every pipeline
    completion). Idempotent and cheap at every startup: when nothing is missing only
    a directory listing and one id query run.
    Returns counts: {"scanned": result files, "inserted": n, "skipped": unreadable files}.
    """
    files = await asyncio.to_thread(_list_result_files, settings.output_dir)
    async with db_session() as conn:
        async with conn.execute("SELECT correlation_id FROM alert_index") as cursor:
            indexed = {r[0] async for r in cursor}
    missing = sorted(set(files) - indexed)
    counts = {"scanned": len(files), "inserted": 0, "skipped": 0}
    if not missing:
        return counts

    created_at: dict[str, float] = {}
    async with db_session() as conn:
        for i in range(0, len(missing), _CHUNK):
            chunk = missing[i:i + _CHUNK]
            marks = ",".join("?" * len(chunk))
            async with conn.execute(
                f"SELECT correlation_id, created_at FROM jobs WHERE correlation_id IN ({marks})", chunk
            ) as cursor:
                async for r in cursor:
                    if r[1] is not None:
                        created_at[r[0]] = float(r[1])

    rows: list[tuple[Any, ...]] = []
    for cid in missing:
        data = await asyncio.to_thread(_read_result_file, files[cid])
        if data is None or data["correlation_id"] != cid:
            counts["skipped"] += 1
            continue
        processed = iso_to_epoch(data.get("processed_at"))
        received = created_at.get(cid)
        if received is None:
            received = processed if processed is not None else iso_to_epoch(data.get("received_at"))
        if received is None:
            try:
                received = os.path.getmtime(files[cid])
            except OSError:
                counts["skipped"] += 1
                continue
        rows.append(_row_params(
            correlation_id=cid, source=data.get("source"), received_at=received,
            processed_at=processed, pipeline_status=data.get("pipeline_status"),
            risk_level=data.get("risk_level"), normalized=data.get("normalized_alert"),
            has_ai_output=bool(data.get("ai_output")),
        ))

    if rows:
        async with db_session() as conn:
            # DO NOTHING: a row written concurrently by the pipeline is newer than this backfill.
            await conn.executemany(
                _INSERT_SQL + " ON CONFLICT(correlation_id) DO NOTHING", rows
            )
            await conn.commit()
        counts["inserted"] = len(rows)
    logger.info("alert_index_reconciled", **counts)
    return counts


def _where(
    risk_levels: Collection[str] | None, received_from: float | None,
    received_to: float | None, statuses: Collection[str],
) -> tuple[str, list[Any]] | None:
    """WHERE clause + params, or None when the filters can match nothing (empty IN list)."""
    clauses: list[str] = []
    params: list[Any] = []
    status_list = sorted({str(s).upper() for s in statuses})
    if not status_list:
        return None
    clauses.append(f"pipeline_status IN ({','.join('?' * len(status_list))})")
    params += status_list
    if risk_levels is not None:
        risks = sorted({str(r).upper() for r in risk_levels})
        if not risks:
            return None
        clauses.append(f"risk_level IN ({','.join('?' * len(risks))})")
        params += risks
    if received_from is not None:
        clauses.append("received_at >= ?")
        params.append(received_from)
    if received_to is not None:
        clauses.append("received_at < ?")
        params.append(received_to)
    return " WHERE " + " AND ".join(clauses), params


async def query(
    risk_levels: Collection[str] | None = None,
    received_from: float | None = None,
    received_to: float | None = None,
    statuses: Collection[str] = DEFAULT_STATUSES,
    limit: int = 50,
    offset: int = 0,
    order: str = "desc",
) -> tuple[list[dict[str, Any]], int]:
    """
    Filtered, paged index rows ordered by received_at (`order` is "asc" or "desc"),
    plus the total number of matches ignoring limit/offset. risk_levels None = all.
    received_from is inclusive, received_to exclusive (epoch seconds).
    Ties on received_at are broken by correlation_id in the same direction, so paging is stable.
    """
    where = _where(risk_levels, received_from, received_to, statuses)
    if where is None:
        return [], 0
    clause, params = where
    direction = "ASC" if str(order).lower() == "asc" else "DESC"
    limit = max(1, min(int(limit), MAX_LIMIT))
    offset = max(0, int(offset))
    async with db_session() as conn:
        async with conn.execute(f"SELECT COUNT(*) FROM alert_index{clause}", params) as cursor:
            total = (await cursor.fetchone())[0]
        async with conn.execute(
            f"SELECT {_COLUMNS} FROM alert_index{clause} "
            f"ORDER BY received_at {direction}, correlation_id {direction} LIMIT ? OFFSET ?",
            params + [limit, offset],
        ) as cursor:
            rows = [_as_dict(r) async for r in cursor]
    return rows, total


async def counts_by_risk(
    received_from: float | None = None,
    received_to: float | None = None,
    statuses: Collection[str] = DEFAULT_STATUSES,
) -> dict[str, int]:
    """{"CRITICAL": n, "HIGH": n, "MEDIUM": n, "LOW": n} for the window; every level present (0 if none)."""
    counts = {level: 0 for level in RISK_ORDER}
    where = _where(None, received_from, received_to, statuses)
    if where is None:
        return counts
    clause, params = where
    async with db_session() as conn:
        async with conn.execute(
            f"SELECT risk_level, COUNT(*) FROM alert_index{clause} GROUP BY risk_level", params
        ) as cursor:
            async for level, n in cursor:
                if level in counts:
                    counts[level] = n
    return counts
