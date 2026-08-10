import asyncio
from contextlib import asynccontextmanager
from typing import Any
from fastapi import FastAPI
import structlog
from src.config import settings
from src.utils.logging import setup_logging
from src.storage.database import init_db
from src.storage import job_store
from src.api.router import api_router

logger = structlog.get_logger(__name__)

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
    
    # Initialize SQLite database schema
    await init_db()
    
    # Trigger crash recovery process in the background
    asyncio.create_task(recover_unfinished_jobs())
    
    yield
    # --- Shutdown ---
    logger.info("app_shutting_down")

app = FastAPI(
    title="ESET SOC Lite Webhook Ingress Service",
    description="Fault-tolerant alert ingestion, normalization and analysis pipeline.",
    version="0.1.0",
    lifespan=lifespan
)

# Attach all grouped routers
app.include_router(api_router)
