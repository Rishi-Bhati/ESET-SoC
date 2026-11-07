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

async def _add_missing_columns(conn: aiosqlite.Connection, table: str,
                               columns: dict[str, str]) -> list[str]:
    """Idempotent migration for a table created by an older release: adds each
    column of `columns` ({name: SQL type}) that the table lacks. CREATE TABLE IF
    NOT EXISTS never changes an existing table, so new columns go through here.
    Returns the names of the columns it added (empty when already up to date)."""
    async with conn.execute(f"PRAGMA table_info({table})") as cur:
        existing = {row[1] for row in await cur.fetchall()}
    added = []
    for name, sql_type in columns.items():
        if name not in existing:
            await conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}")
            added.append(name)
    return added


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

        # AI Visibility traces (see src/models/ai_trace.py, src/services/ai/trace_recorder.py).
        # data_json holds the full, already-redacted trace; the other columns exist only
        # so the dashboard can list/filter/aggregate without parsing every row's JSON.
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS ai_traces (
                trace_id TEXT PRIMARY KEY,
                correlation_id TEXT NOT NULL,
                component TEXT NOT NULL,
                provider TEXT NOT NULL,
                model TEXT NOT NULL,
                status TEXT NOT NULL,              -- STARTED, SUCCESS, BLOCKED, FAILED, ERROR
                risk TEXT NOT NULL,                 -- SAFE, REVIEW, SENSITIVE_DATA_DETECTED,
                                                     -- SECRET_DETECTED, FAILED_SECURITY_CHECK, BLOCKED, ERROR
                started_at REAL NOT NULL,
                completed_at REAL,
                duration_ms REAL,
                security_findings_count INTEGER NOT NULL DEFAULT 0,
                external_data_transfer INTEGER NOT NULL DEFAULT 0,
                data_json TEXT NOT NULL             -- full AITrace, already redacted
            )
        """)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ai_traces_correlation ON ai_traces(correlation_id)"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_ai_traces_started ON ai_traces(started_at)"
        )

        # Recent detection sightings for the risk engine's multiple-endpoint rule
        # (see storage/observation_store.py).
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS alert_observations (
                correlation_id TEXT PRIMARY KEY,
                detection_name TEXT NOT NULL,
                endpoint_name TEXT NOT NULL,
                observed_at REAL NOT NULL
            )
        """)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alert_observations_detection "
            "ON alert_observations(detection_name, observed_at)"
        )

        # --- Client portal (read-only portal for the client's own staff) ---
        # Client accounts are created/managed by engineers from the dashboard
        # (see storage/user_store.py). role is fixed to 'client'; engineers use
        # the dashboard key, not these accounts.
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS client_users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                display_name TEXT,
                role TEXT NOT NULL DEFAULT 'client' CHECK(role = 'client'),
                password_hash TEXT NOT NULL,
                disabled INTEGER NOT NULL DEFAULT 0,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until REAL,
                created_at REAL NOT NULL,
                password_changed_at REAL,
                last_login_at REAL,
                failure_window_start REAL
            )
        """)
        # token_hash is a hash of the opaque cookie token; the token itself is
        # never stored. Rows are removed with their user (foreign_keys is ON in
        # db_session()).
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS client_sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES client_users(id) ON DELETE CASCADE,
                created_at REAL,
                last_seen_at REAL,
                expires_at REAL,
                client_ip TEXT
            )
        """)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_client_sessions_user ON client_sessions(user_id)"
        )
        # Sign-in lock-out model (see storage/user_store.py, verify_credentials):
        #  - client_login_failures: one row per (account, client address). Wrong
        #    passwords lock only that pair; the same account still signs in from
        #    other addresses. last_success_at marks a "known" address for the
        #    account. Rows are pruned (user_store.purge_login_failures).
        #  - client_users.failed_attempts / locked_until / failure_window_start:
        #    the account-wide BACKSTOP only — failures from every address in the
        #    current window, and the end of the current slow-down. It never
        #    applies to an address that signed in successfully recently.
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS client_login_failures (
                user_id TEXT NOT NULL REFERENCES client_users(id) ON DELETE CASCADE,
                client_ip TEXT NOT NULL,       -- address key (IPv6 grouped by /64)
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                last_failed_at REAL,
                locked_until REAL,
                last_success_at REAL,
                PRIMARY KEY (user_id, client_ip)
            )
        """)
        if await _add_missing_columns(conn, "client_users", {"failure_window_start": "REAL"}):
            # Upgrading from the account-wide hard lock: failed_attempts and
            # locked_until now mean the backstop window, so an old 15-minute
            # account lock must not carry over as a backstop slow-down.
            await conn.execute(
                "UPDATE client_users SET failed_attempts = 0, locked_until = NULL")
            logger.info("database_migrated", table="client_users",
                        change="per-address login lock-out")

        # Query index over alerts (storage/alert_index_store.py): one row per
        # correlation_id so the portal can filter/page without reading every
        # result file. The result JSON files stay the source of truth.
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS alert_index (
                correlation_id TEXT PRIMARY KEY,
                source TEXT,
                received_at REAL NOT NULL,
                processed_at REAL,
                pipeline_status TEXT,
                risk_level TEXT,
                eset_severity TEXT,
                eset_alert_id TEXT,
                detection_name TEXT,
                endpoint_name TEXT,
                has_ai_output INTEGER,
                updated_at REAL
            )
        """)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alert_index_risk_received "
            "ON alert_index(risk_level, received_at)"
        )
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alert_index_received ON alert_index(received_at)"
        )

        # Engineer recommendations shown to the client on an alert
        # (storage/recommendation_store.py). Retracted, never deleted.
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS alert_recommendations (
                id TEXT PRIMARY KEY,
                correlation_id TEXT NOT NULL,
                body TEXT NOT NULL,
                author TEXT NOT NULL,
                created_at REAL NOT NULL,
                retracted_at REAL,
                retracted_by TEXT,
                retract_reason TEXT,
                notification_email_id TEXT
            )
        """)
        await conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_alert_recommendations_alert "
            "ON alert_recommendations(correlation_id, created_at)"
        )

        # Weekly report runs (storage/weekly_report_store.py); period_key is the
        # idempotency key so a restart or second instance cannot double-send.
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS weekly_reports (
                period_key TEXT PRIMARY KEY,
                period_start REAL,
                period_end REAL,
                status TEXT,
                trigger TEXT,
                claimed_at REAL,
                completed_at REAL,
                email_id TEXT,
                recipients TEXT,
                counts_json TEXT,
                file_path TEXT,
                file_sha256 TEXT,
                attachment_included INTEGER DEFAULT 0,
                resend_count INTEGER DEFAULT 0,
                attempts INTEGER DEFAULT 0,
                error TEXT
            )
        """)

        await conn.commit()

    logger.info("database_init_success")
