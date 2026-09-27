import os
from typing import Any
from fastapi import APIRouter, Request
import aiosqlite
import structlog
from src.config import settings
from src.services.ai.factory import ai_provider_configured


router = APIRouter(prefix="/health", tags=["Health"])
logger = structlog.get_logger(__name__)

@router.get("")
async def health_check(request: Request) -> dict[str, Any]:
    """
    Consolidated health check endpoint for database, storage, and configuration.
    """
    # 1. Database Check
    db_ok = False
    db_error = None
    try:
        db_path = settings.sqlite_db_path
        async with aiosqlite.connect(db_path) as conn:
            await conn.execute("SELECT 1")
        db_ok = True
    except Exception as e:
        db_error = str(e)
        logger.error("health_check_db_failed", error=db_error)

    # 2. Output Directory Writable Check
    dir_ok = False
    dir_error = None
    try:
        os.makedirs(settings.output_dir, exist_ok=True)
        temp_file = os.path.join(settings.output_dir, ".health_check_tmp")
        with open(temp_file, "w") as f:
            f.write("write_test")
        os.remove(temp_file)
        dir_ok = True
    except Exception as e:
        dir_error = str(e)
        logger.error("health_check_dir_failed", error=dir_error)

    # 3. AI provider configuration. Deliberately does not contact the provider or
    # Secrets Manager: this endpoint is polled by load balancers every few seconds.
    ai_configured = ai_provider_configured()

    # 4. Syslog Listener Check (embedded in this process, see src.services.syslog_runtime)
    syslog_handles = getattr(request.app.state, "syslog_handles", None)
    udp_ok = bool(syslog_handles and syslog_handles.udp_transport)
    tcp_ok = bool(syslog_handles and syslog_handles.tcp_server)

    # An unconfigured AI provider degrades notifications, not ingestion: alerts are
    # still recorded and the fallback notice still goes out. It is reported, but it
    # does not fail the probe (which would make a load balancer stop sending alerts).
    is_healthy = db_ok and dir_ok
    status = "ok" if is_healthy else "degraded"

    # This endpoint is deliberately unauthenticated so a load balancer or
    # container probe can reach it, which is exactly why it must not echo the
    # raw exception text: a sqlite or filesystem error carries absolute server
    # paths. The full detail is logged above for whoever is on the host.
    return {
        "status": status,
        "database": {
            "status": "ok" if db_ok else "error"
        },
        "output_directory": {
            "status": "ok" if dir_ok else "error"
        },
        "ai_provider": {
            "provider": settings.ai_provider,
            "status": "configured" if ai_configured else "missing"
        },
        "syslog_listener": {
            "udp": "ok" if udp_ok else "down",
            "tcp": "ok" if tcp_ok else "down"
        }
    }
