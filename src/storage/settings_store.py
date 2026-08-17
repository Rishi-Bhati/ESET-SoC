"""
Runtime-editable configuration, persisted in SQLite.

Values set here are edited from the dashboard and override the corresponding
.env defaults, so an operator can change notification recipients without a
redeploy. Anything not set here falls back to src.config.settings.
"""
from typing import Any
import structlog
from src.storage.database import db_session
from src.config import settings

logger = structlog.get_logger(__name__)

# Dashboard-editable keys -> the settings attribute they fall back to.
RECIPIENT_KEYS = {
    "client_notification_emails": "client_notification_emails",
    "cthree_notification_emails": "cthree_notification_emails",
    "internal_notification_emails": "internal_notification_emails",
    "engineer_notification_emails": "engineer_notification_emails",
}


async def get_setting(key: str) -> str | None:
    """Returns the stored override for `key`, or None if it has never been set."""
    async with db_session() as conn:
        async with conn.execute("SELECT value FROM app_settings WHERE key = ?", (key,)) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else None


async def set_setting(key: str, value: str) -> None:
    async with db_session() as conn:
        await conn.execute(
            """
            INSERT INTO app_settings (key, value) VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
            """,
            (key, value),
        )
        await conn.commit()
    logger.info("setting_updated", key=key)


async def get_effective(key: str) -> str:
    """Stored override if present, else the .env value."""
    stored = await get_setting(key)
    if stored is not None:
        return stored
    return getattr(settings, RECIPIENT_KEYS.get(key, key), "") or ""


async def get_recipient_config() -> dict[str, Any]:
    """
    Current recipient configuration, with the source of each value so the UI can
    show whether it is a saved override or still the .env default.
    """
    result: dict[str, Any] = {}
    for key in RECIPIENT_KEYS:
        stored = await get_setting(key)
        result[key] = {
            "value": stored if stored is not None else (getattr(settings, key, "") or ""),
            "source": "dashboard" if stored is not None else "env",
        }
    return result


async def update_recipients(values: dict[str, str]) -> list[str]:
    """Persists recipient overrides. Returns the keys that were updated."""
    updated = []
    for key, value in values.items():
        if key not in RECIPIENT_KEYS:
            continue
        await set_setting(key, (value or "").strip())
        updated.append(key)
    return updated
