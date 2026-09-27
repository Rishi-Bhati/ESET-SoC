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
from src.services import syslog_runtime, email_dispatcher, pipeline_capacity, secrets
from src.services.ai.factory import PROVIDER_SETTINGS, ai_provider_configured, supported_providers
from src.api.router import api_router
from src.middleware.security import SecurityHeadersMiddleware, build_csp, inline_script_hashes

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

_PLACEHOLDER_SECRETS = {"", "test", "changeme", "change-me", "your_gemini_api_key_here",
                        "your_openai_api_key_here", "sk-...", "secret", "password"}
_MIN_SECRET_LENGTH = 16


def production_config_problems() -> list[str]:
    """
    Settings that are tolerable on a developer's laptop but must not reach a
    deployment. Empty list = fine. Only enforced when APP_ENV=production.
    """
    problems = []
    key = settings.dashboard_access_key
    if not key:
        problems.append("DASHBOARD_ACCESS_KEY is blank — the dashboard and its API would be open to anyone")
    elif len(key) < _MIN_SECRET_LENGTH:
        problems.append(f"DASHBOARD_ACCESS_KEY is shorter than {_MIN_SECRET_LENGTH} characters")
    token = settings.eset_webhook_auth_token
    if token.lower() in _PLACEHOLDER_SECRETS or len(token) < _MIN_SECRET_LENGTH:
        problems.append(f"ESET_WEBHOOK_AUTH_TOKEN is a placeholder or shorter than {_MIN_SECRET_LENGTH} characters")
    provider = settings.ai_provider.strip().lower()
    if provider not in supported_providers():
        problems.append(f"AI_PROVIDER '{settings.ai_provider}' is not one of {supported_providers()}")
    elif not ai_provider_configured():
        problems.append(f"AI_PROVIDER={provider} is missing its model name or API key / secret ID")
    else:
        key_attr = PROVIDER_SETTINGS[provider][1]
        if getattr(settings, key_attr) and getattr(settings, key_attr).lower() in _PLACEHOLDER_SECRETS:
            problems.append(f"{key_attr.upper()} is a placeholder")
    if settings.enable_api_docs:
        problems.append("ENABLE_API_DOCS must be false in production (docs cannot be gated by the dashboard key)")
    if settings.email_delivery_enabled and not (settings.email_api_url and settings.email_api_key):
        problems.append("EMAIL_DELIVERY_ENABLED is true but EMAIL_API_URL / EMAIL_API_KEY are missing")
    return problems


def check_production_config() -> None:
    """Refuses to start a production deployment with an unsafe configuration."""
    if settings.app_env.lower() != "production":
        return
    problems = production_config_problems()
    if problems:
        for p in problems:
            logger.error("unsafe_production_config", problem=p)
        raise RuntimeError("Refusing to start with APP_ENV=production: " + "; ".join(problems))
    if not settings.syslog_allowed_sources:
        logger.warning(
            "syslog_allowlist_blank_in_production",
            tip="Set SYSLOG_ALLOWED_SOURCES, or keep the syslog ports unreachable from outside.",
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
        
        # A single coordinator holds at most one reservation and awaits each
        # pipeline. Never create a waiting task for every saved job: a large
        # backlog must not bypass live-ingest capacity or exhaust the task queue.
        for job in unfinished:
            while True:
                try:
                    reservation = pipeline_capacity.capacity.reserve(job["correlation_id"])
                    break
                except pipeline_capacity.PipelineAlreadyActive:
                    reservation = None  # Already accepted by ingest/manual retry.
                    break
                except pipeline_capacity.CapacityExhausted:
                    await asyncio.sleep(0.1)
            if reservation is None:
                continue
            try:
                # The snapshot can become stale while waiting for capacity.
                current = await job_store.get_job(job["correlation_id"])
                if current is None or current["status"] not in ("PENDING", "PROCESSING"):
                    continue
                logger.info("recovery_retriggering_job", correlation_id=job["correlation_id"])
                await reservation.run(
                    run_pipeline_task, job["correlation_id"], current["raw_payload"], current["source"],
                )
            finally:
                reservation.release()
            
    except Exception as e:
        logger.error("recovery_failed", error=str(e))

@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Startup ---
    # Setup structlog
    setup_logging(
        settings.log_level,
        settings.log_file,
        max_bytes=settings.log_max_bytes,
        backup_count=settings.log_backup_count,
        quiet_dashboard_access=not settings.log_dashboard_access,
    )
    logger.info("app_starting", host=settings.app_host, port=settings.app_port, env=settings.app_env)
    # Platform credentials from AWS Secrets Manager (APP_SECRETS_SECRET_ID), before
    # anything reads them. A configured-but-unreadable secret stops startup here.
    applied = secrets.apply_app_secrets()
    if applied:
        logger.info("startup_secrets_loaded", count=len(applied))
    check_production_config()
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
    app.state.recovery_task = asyncio.create_task(recover_unfinished_jobs())

    # Sweeper that retries emails which could not be handed to the mail service.
    # The service itself owns retrying actual delivery.
    app.state.dispatch_task = asyncio.create_task(email_dispatcher.run_dispatch_loop())

    # Periodic purge of expired dedup_log rows (previously dead code — see
    # docs/SOC_LITE_AUDIT.md §5/§17). Runs once per TTL window by default.
    app.state.dedup_cleanup_task = asyncio.create_task(
        deduplication.run_cleanup_loop(max(60, settings.dedup_ttl_seconds))
    )

    try:
        yield
    finally:
        # --- Shutdown ---
        background = (
            app.state.recovery_task, app.state.dispatch_task, app.state.dedup_cleanup_task,
        )
        for task in background:
            task.cancel()
        await asyncio.gather(*background, return_exceptions=True)
        await syslog_runtime.stop(app.state.syslog_handles)
        logger.info("app_shutting_down")

app = FastAPI(
    title="ESET SOC Lite Webhook Ingress Service",
    description="Fault-tolerant alert ingestion, normalization and analysis pipeline.",
    version="0.1.0",
    lifespan=lifespan,
    # Closed unless ENABLE_API_DOCS is set. These three routes are served by
    # FastAPI itself, so _check_access() never sees them — left on, they publish
    # the full route inventory (ingest paths included) to any unauthenticated
    # caller who can reach the port.
    docs_url="/docs" if settings.enable_api_docs else None,
    redoc_url="/redoc" if settings.enable_api_docs else None,
    openapi_url="/openapi.json" if settings.enable_api_docs else None,
)

# Live dashboard event bus. Wired at import rather than in lifespan so
# app.state.broadcaster always exists (the WebSocket route would otherwise raise
# AttributeError whenever lifespan has not run). It is a pure in-memory fan-out
# object with no I/O, and broadcasting with no subscribers is a no-op.
app.state.broadcaster = EventBroadcaster()
events.set_broadcaster(app.state.broadcaster)

# Attach all grouped routers
app.include_router(api_router)

with open(os.path.join(STATIC_DIR, "dashboard.html"), encoding="utf-8") as _f:
    _CSP = build_csp(inline_script_hashes(_f.read()))
app.add_middleware(SecurityHeadersMiddleware, csp=_CSP)

# Live dashboard: static assets + root page
class _RevalidatingStaticFiles(StaticFiles):
    """
    With no Cache-Control header, browsers cache the dashboard's JS/CSS
    heuristically and can keep running an old dashboard.js for a while after
    an update — new HTML against stale script. `no-cache` still lets the
    browser keep its copy, but it must revalidate (a cheap 304 via the
    ETag/Last-Modified StaticFiles already sends) before using it.
    """

    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response


app.mount("/static", _RevalidatingStaticFiles(directory=STATIC_DIR), name="static")

@app.get("/", include_in_schema=False)
async def dashboard_root() -> FileResponse:
    return FileResponse(os.path.join(STATIC_DIR, "dashboard.html"), headers={"Cache-Control": "no-cache"})
