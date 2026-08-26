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
from src.storage import job_store, deduplication
from src.services import syslog_runtime, email_dispatcher
from src.api.router import api_router

logger = structlog.get_logger(__name__)

# Resolve static assets relative to the project root, not the current working
# directory, so the service starts correctly from any cwd (systemd, supervisor, ...).
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC_DIR = os.path.join(PROJECT_ROOT, "static")


def _resolved_route_paths(routes: Any) -> list[str]:
    """
    Recursively resolves every concrete path this app will actually answer on,
    unwrapping include_router()'s wrapper objects along the way. FastAPI does not
    flatten included routers into app.routes as plain APIRoute entries — it wraps
    each one, and the wrapper's attribute name for the underlying router has changed
    across versions (seen here: `.original_router`; older/other builds use `.router`
    or expose the sub-routes directly via `.routes`). This tries all of them rather
    than hard-coding one, since a diagnostic that silently reports zero routes on the
    next FastAPI upgrade is worse than not having it.
    """
    paths: list[str] = []
    for r in routes:
        path = getattr(r, "path", None)
        if isinstance(path, str):
            paths.append(path)
            continue
        nested = getattr(r, "original_router", None) or getattr(r, "router", None)
        if nested is not None and hasattr(nested, "routes"):
            paths.extend(_resolved_route_paths(nested.routes))
        elif hasattr(r, "routes"):
            paths.extend(_resolved_route_paths(r.routes))
    return paths

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

    # Python does not hot-reload source files: this process serves exactly the code
    # that was on disk when it started, in memory, until it is restarted. If a route
    # module is added or changed while an older instance of this process is still
    # running, every call into it 404s with no exception anywhere — the routes simply
    # don't exist in that process's memory yet. Logging exactly which AI Visibility
    # routes are live at startup turns that into a 10-second log check instead of a
    # process/file-mtime forensic investigation.
    ai_routes = sorted(p for p in _resolved_route_paths(app.routes) if p.startswith("/dashboard/api/ai"))
    logger.info("ai_visibility_routes_active", count=len(ai_routes), routes=ai_routes)

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

    # Periodic purge of expired dedup_log rows (previously dead code — see
    # docs/SOC_LITE_AUDIT.md §5/§17). Runs once per TTL window by default.
    app.state.dedup_cleanup_task = asyncio.create_task(
        deduplication.run_cleanup_loop(max(60, settings.dedup_ttl_seconds))
    )

    yield
    # --- Shutdown ---
    app.state.dispatch_task.cancel()
    app.state.dedup_cleanup_task.cancel()
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
