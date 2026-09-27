"""
Recent (detection, endpoint) sightings, for the risk engine's multiple-endpoint
rule: the same detection on OUTBREAK_ENDPOINT_THRESHOLD distinct endpoints
within OUTBREAK_WINDOW_SECONDS is an outbreak, even when each individual ESET
alert only ever names one endpoint.
"""
import time
from src.config import settings
from src.storage.database import db_session


async def record_and_count(correlation_id: str, detection_name: str, endpoint_name: str) -> int:
    """
    Records this alert's sighting and returns how many distinct endpoints the
    same detection has been seen on within the window, this one included.
    Returns 1 when either name is unknown — an unnamed detection or endpoint
    cannot be correlated.
    """
    if not detection_name or detection_name == "UNKNOWN" or not endpoint_name or endpoint_name == "UNKNOWN":
        return 1
    now = time.time()
    since = now - settings.outbreak_window_seconds
    async with db_session() as conn:
        # Keyed by correlation_id, so a dashboard retry of the same alert does
        # not count as a second sighting.
        await conn.execute(
            """
            INSERT INTO alert_observations (correlation_id, detection_name, endpoint_name, observed_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(correlation_id) DO UPDATE SET
                detection_name = excluded.detection_name,
                endpoint_name = excluded.endpoint_name
            """,
            (correlation_id, detection_name.strip().lower(), endpoint_name.strip().lower(), now),
        )
        await conn.execute("DELETE FROM alert_observations WHERE observed_at < ?",
                           (now - max(settings.outbreak_window_seconds, 86400),))
        await conn.commit()
        async with conn.execute(
            "SELECT COUNT(DISTINCT endpoint_name) FROM alert_observations "
            "WHERE detection_name = ? AND observed_at >= ?",
            (detection_name.strip().lower(), since),
        ) as cursor:
            row = await cursor.fetchone()
    return max(int(row[0]) if row else 1, 1)
