import json
import time
from typing import Any
import structlog
from src.storage.database import db_session
from src.utils import events

logger = structlog.get_logger(__name__)

async def create_job(correlation_id: str, source: str, raw_payload: dict[str, Any]) -> None:
    """
    Creates a new job in PENDING status in the SQLite database.
    """
    now = time.time()
    query = """
        INSERT INTO jobs (correlation_id, source, status, raw_payload, created_at, updated_at, error)
        VALUES (?, ?, ?, ?, ?, ?, NULL)
    """
    payload_str = json.dumps(raw_payload)

    async with db_session() as conn:
        await conn.execute(query, (correlation_id, source, "PENDING", payload_str, now, now))
        await conn.commit()
    logger.info("job_created", correlation_id=correlation_id, source=source)
    await events.emit("job_status_changed", {
        "correlation_id": correlation_id,
        "source": source,
        "status": "PENDING",
        "error": None,
        "updated_at": now,
    })

async def update_job_status(correlation_id: str, status: str, error: str | None = None) -> None:
    """
    Updates the status and error of a job.
    """
    now = time.time()
    query = """
        UPDATE jobs
        SET status = ?, error = ?, updated_at = ?
        WHERE correlation_id = ?
    """

    async with db_session() as conn:
        await conn.execute(query, (status, error, now, correlation_id))
        await conn.commit()
    logger.info("job_status_updated", correlation_id=correlation_id, status=status, error=error)
    await events.emit("job_status_changed", {
        "correlation_id": correlation_id,
        "status": status,
        "error": error,
        "updated_at": now,
    })

async def get_job(correlation_id: str) -> dict[str, Any] | None:
    """
    Retrieves a job by its correlation_id.
    """
    query = """
        SELECT correlation_id, source, status, raw_payload, created_at, updated_at, error
        FROM jobs
        WHERE correlation_id = ?
    """
    
    async with db_session() as conn:
        async with conn.execute(query, (correlation_id,)) as cursor:
            row = await cursor.fetchone()
            if row:
                return {
                    "correlation_id": row[0],
                    "source": row[1],
                    "status": row[2],
                    "raw_payload": json.loads(row[3]),
                    "created_at": row[4],
                    "updated_at": row[5],
                    "error": row[6]
                }
    return None

async def list_jobs(limit: int = 50, offset: int = 0, status: str | None = None) -> list[dict[str, Any]]:
    """
    Retrieves recent jobs ordered by most-recently-updated first, for the dashboard's
    live activity table. Optionally filtered by status.
    """
    query = """
        SELECT correlation_id, source, status, raw_payload, created_at, updated_at, error
        FROM jobs
    """
    params: list[Any] = []
    if status:
        query += " WHERE status = ?"
        params.append(status)
    query += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    jobs = []
    async with db_session() as conn:
        async with conn.execute(query, params) as cursor:
            async for row in cursor:
                jobs.append({
                    "correlation_id": row[0],
                    "source": row[1],
                    "status": row[2],
                    "raw_payload": json.loads(row[3]),
                    "created_at": row[4],
                    "updated_at": row[5],
                    "error": row[6]
                })
    return jobs

async def get_unfinished_jobs() -> list[dict[str, Any]]:
    """
    Retrieves all jobs in PENDING or PROCESSING status (used for crash recovery on startup).
    """
    query = """
        SELECT correlation_id, source, status, raw_payload, created_at, updated_at, error
        FROM jobs
        WHERE status IN ('PENDING', 'PROCESSING')
        ORDER BY created_at ASC
    """
    
    unfinished = []
    async with db_session() as conn:
        async with conn.execute(query) as cursor:
            async for row in cursor:
                unfinished.append({
                    "correlation_id": row[0],
                    "source": row[1],
                    "status": row[2],
                    "raw_payload": json.loads(row[3]),
                    "created_at": row[4],
                    "updated_at": row[5],
                    "error": row[6]
                })
    return unfinished
