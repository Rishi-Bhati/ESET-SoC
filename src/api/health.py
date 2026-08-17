import os
from typing import Any
from fastapi import APIRouter, Request
import aiosqlite
import structlog
from src.config import settings

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

    # 3. Gemini Config Check
    gemini_configured = bool(settings.gemini_api_key)

    # 4. Syslog Listener Check (embedded in this process, see src.services.syslog_runtime)
    syslog_handles = getattr(request.app.state, "syslog_handles", None)
    udp_ok = bool(syslog_handles and syslog_handles.udp_transport)
    tcp_ok = bool(syslog_handles and syslog_handles.tcp_server)

    is_healthy = db_ok and dir_ok and gemini_configured
    status = "ok" if is_healthy else "degraded"

    return {
        "status": status,
        "database": {
            "status": "ok" if db_ok else "error",
            "error": db_error
        },
        "output_directory": {
            "status": "ok" if dir_ok else "error",
            "error": dir_error
        },
        "gemini_api": {
            "status": "configured" if gemini_configured else "missing"
        },
        "syslog_listener": {
            "udp": "ok" if udp_ok else "down",
            "tcp": "ok" if tcp_ok else "down"
        }
    }
