import asyncio
import os
from contextlib import asynccontextmanager
from typing import Any
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
import structlog
from src.config import settings
from src.utils.logging import setup_logging
from src.utils.broadcaster import EventBroadcaster
from src.utils import events
from src.storage.database import init_db
from src.storage import job_store
from src.services import syslog_runtime, email_dispatcher
from src.api.router import api_router

logger = structlog.get_logger(__name__)

# Resolve static assets relative to the project root, not the current working
# directory, so the service starts correctly from any cwd (systemd, supervisor, ...).
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(PROJECT_ROOT, "static")

def warn_on_insecure_exposure() -> None:
    """
    The dashboard exposes every ingested alert (hostnames, usernames, file paths,
    hashes) and can re-run pipelines. That is fine on a loopback bind, but binding
    a routable interface without DASHBOARD_ACCESS_KEY publishes it to the network.
    """
    if settings.app_host not in ("127.0.0.1", "localhost", "::1") and not settings.dashboard_access_key:
        logger.warning(
            "dashboard_exposed_without_key",
            host=settings.app_host,
            tip="Set DASHBOARD_ACCESS_KEY in .env, or bind APP_HOST=127.0.0.1 and reach it over a tunnel.",
        )

async def recover_unfinished_jobs() -> None:
    """
    Scans the database for jobs in PENDING or PROCESSING status
    and restarts their pipelines. This ensures no alerts are lost on crash/restart.
    """
    try:
        unfinished = await job_store.get_unfinished_jobs()
        if not unfinished:
            logger.info("recovery_no_unfinished_jobs")
            return
            
        logger.info("recovery_unfinished_jobs_found", count=len(unfinished))
        
        # We import here to avoid potential startup circular imports
        from src.api.webhook import run_pipeline_task
        
        for job in unfinished:
            logger.info("recovery_retriggering_job", correlation_id=job["correlation_id"])
            # Re-enqueue in background tasks
            asyncio.create_task(run_pipeline_task(job["correlation_id"], job["raw_payload"], job["source"]))
            
    except Exception as e:
        logger.error("recovery_failed", error=str(e))

@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Startup ---
    # Setup structlog
    setup_logging(settings.log_level)
    logger.info("app_starting", host=settings.app_host, port=settings.app_port)
    warn_on_insecure_exposure()

    # Initialize SQLite database schema
    await init_db()

    # Embed the syslog UDP/TCP listeners in this same process/event loop so the
    # whole platform starts with a single command (see src.services.syslog_runtime)
    app.state.syslog_handles = await syslog_runtime.start()

    # Trigger crash recovery process in the background
    asyncio.create_task(recover_unfinished_jobs())

    # Sweeper that retries emails which could not be handed to the mail service.
    # The service itself owns retrying actual delivery.
    app.state.dispatch_task = asyncio.create_task(email_dispatcher.run_dispatch_loop())

    yield
    # --- Shutdown ---
    app.state.dispatch_task.cancel()
    await syslog_runtime.stop(app.state.syslog_handles)
    logger.info("app_shutting_down")

app = FastAPI(
    title="ESET SOC Lite Webhook Ingress Service",
    description="Fault-tolerant alert ingestion, normalization and analysis pipeline.",
    version="0.1.0",
    lifespan=lifespan
)

# Live dashboard event bus. Wired at import rather than in lifespan so
# app.state.broadcaster always exists (the WebSocket route would otherwise raise
# AttributeError whenever lifespan has not run). It is a pure in-memory fan-out
# object with no I/O, and broadcasting with no subscribers is a no-op.
app.state.broadcaster = EventBroadcaster()
events.set_broadcaster(app.state.broadcaster)

# Attach all grouped routers
app.include_router(api_router)

# Live dashboard: static assets + root page
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/", include_in_schema=False)
async def dashboard_root() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "dashboard.html"))
