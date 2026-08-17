import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator
import aiosqlite
import structlog
from src.config import settings

logger = structlog.get_logger(__name__)

@asynccontextmanager
async def db_session() -> AsyncGenerator[aiosqlite.Connection, None]:
    """
    Async context manager yielding an active database connection.
    Ensures WAL mode is enabled and connection is closed on exit.
    """
    db_path = settings.sqlite_db_path
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
        
    conn = await aiosqlite.connect(db_path)
    try:
        # Configure connection
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA foreign_keys=ON")
        yield conn
    finally:
        await conn.close()

async def init_db() -> None:
    """
    Initializes database schemas for jobs and deduplication tracking.
    """
    logger.info("database_init_start", path=settings.sqlite_db_path)
    
    async with db_session() as conn:
        # Create jobs table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                correlation_id TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                status TEXT NOT NULL, -- PENDING, PROCESSING, SUCCESS, PARTIAL, FAILED
                raw_payload TEXT NOT NULL, -- JSON string
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL,
                error TEXT
            )
        """)
        
        # Create deduplication log table
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS dedup_log (
                composite_key TEXT PRIMARY KEY, -- alert_id + occurred_at hash or composite
                received_at REAL NOT NULL,
                expires_at REAL NOT NULL
            )
        """)

        # Dashboard-editable configuration overriding .env (see storage/settings_store.py)
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        """)

        # Outbound email delivery history (see storage/delivery_store.py).
        # outbox.json only holds what still needs sending; outcomes live here.
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS email_deliveries (
                email_id TEXT PRIMARY KEY,
                correlation_id TEXT NOT NULL,
                notification_type TEXT NOT NULL,
                recipients TEXT NOT NULL,      -- JSON array
                subject TEXT NOT NULL,
                status TEXT NOT NULL,          -- PENDING, SENT, FAILED
                attempts INTEGER NOT NULL DEFAULT 0,
                remote_id TEXT,                -- id returned by the mail service
                error TEXT,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
        """)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_email_deliveries_status ON email_deliveries(status)"
        )

        await conn.commit()
        
    logger.info("database_init_success")
