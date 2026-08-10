import time
import structlog
from src.storage.database import db_session

logger = structlog.get_logger(__name__)

async def is_duplicate(composite_key: str) -> bool:
    """
    Checks if a composite key already exists in the dedup_log and is not expired.
    """
    now = time.time()
    query = "SELECT 1 FROM dedup_log WHERE composite_key = ? AND expires_at > ?"
    
    async with db_session() as conn:
        async with conn.execute(query, (composite_key, now)) as cursor:
            row = await cursor.fetchone()
            if row is not None:
                logger.info("deduplication_match", composite_key=composite_key)
                return True
    return False

async def record_seen(composite_key: str, ttl_seconds: int) -> None:
    """
    Inserts a composite key with expiration time.
    """
    now = time.time()
    expires_at = now + ttl_seconds
    query = """
        INSERT OR REPLACE INTO dedup_log (composite_key, received_at, expires_at)
        VALUES (?, ?, ?)
    """
    
    async with db_session() as conn:
        await conn.execute(query, (composite_key, now, expires_at))
        await conn.commit()
    logger.debug("deduplication_recorded", composite_key=composite_key, expires_at=expires_at)

async def cleanup_expired() -> int:
    """
    Deletes expired deduplication logs. Returns number of rows deleted.
    """
    now = time.time()
    query = "DELETE FROM dedup_log WHERE expires_at <= ?"
    
    async with db_session() as conn:
        async with conn.execute(query, (now,)) as cursor:
            rows_deleted = cursor.rowcount
        await conn.commit()
    
    if rows_deleted > 0:
        logger.info("deduplication_cleanup", count=rows_deleted)
    return rows_deleted
