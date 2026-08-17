import asyncio
import hashlib
import json
from typing import Any
from fastapi import APIRouter, Depends, Request, BackgroundTasks
import structlog
from src.middleware.auth import validate_eset_token
from src.ingestion.webhook_handler import WebhookIngestionHandler
from src.models.raw_payload import EsetRawPayload
from src.ingestion.syslog_handler import SyslogIngestionHandler
from src.storage import deduplication, job_store
from src.utils.correlation import generate_correlation_id, set_correlation_id
from src.config import settings

# We will dynamically import the orchestrator to avoid circular dependency
# when setting up imports.
# In production, we wire it through background tasks.

router = APIRouter(prefix="/webhook", tags=["Webhook"])
logger = structlog.get_logger(__name__)
webhook_handler = WebhookIngestionHandler()
syslog_handler = SyslogIngestionHandler()

def compute_dedup_key(payload: EsetRawPayload) -> str:
    """
    Computes a deduplication fingerprint for the alert.
    Uses composite key (alert_id + occurred_at) if available,
    otherwise falls back to SHA256 of the sorted raw_payload dictionary.
    """
    if payload.alert_id and payload.occurred_at:
        return f"{payload.alert_id}:{payload.occurred_at}"
    
    serialized = json.dumps(payload.raw_payload, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

async def run_pipeline_task(correlation_id: str, raw_payload: dict[str, Any], source: str) -> None:
    """
    Background worker task wrapper to execute orchestrator.
    Imports orchestrator dynamically to avoid circular dependencies.
    """
    set_correlation_id(correlation_id)
    logger.info("background_pipeline_start", correlation_id=correlation_id)

    try:
        from src.pipeline.orchestrator import process_alert_pipeline
        await process_alert_pipeline(correlation_id, raw_payload, source)
    except Exception as e:
        logger.error("background_pipeline_uncaught_error", error=str(e), correlation_id=correlation_id)

async def ingest_alert(
    raw_json: dict[str, Any],
    handler: WebhookIngestionHandler | SyslogIngestionHandler,
    source: str,
    background_tasks: BackgroundTasks
) -> dict[str, Any]:
    """
    Shared ingestion path used by both the public /webhook/eset and /webhook/syslog
    routes below, and by the dashboard's "Send Test Alert"/"Send Test Syslog Event"
    controls (src/api/dashboard.py) — same parse -> dedup -> job -> pipeline flow either way.
    """
    correlation_id = generate_correlation_id()
    set_correlation_id(correlation_id)

    try:
        raw_payload = handler.parse(raw_json)
    except ValueError as e:
        logger.error("ingest_invalid_payload", error=str(e), source=source)
        return {"status": "error", "message": str(e), "correlation_id": correlation_id}

    dedup_key = compute_dedup_key(raw_payload)
    if await deduplication.is_duplicate(dedup_key):
        logger.info("ingest_duplicate_dropped", dedup_key=dedup_key, source=source)
        return {
            "status": "duplicate",
            "message": "Alert already processed",
            "correlation_id": correlation_id
        }

    await deduplication.record_seen(dedup_key, settings.dedup_ttl_seconds)

    payload_dict = raw_payload.model_dump()
    await job_store.create_job(correlation_id, source, payload_dict)

    background_tasks.add_task(run_pipeline_task, correlation_id, payload_dict, source)

    return {
        "status": "queued",
        "correlation_id": correlation_id
    }

@router.post("/eset", dependencies=[Depends(validate_eset_token)])
async def receive_eset_webhook(
    request: Request,
    background_tasks: BackgroundTasks
) -> dict[str, Any]:
    """
    Endpoint for ESET webhooks. Parses payload, performs deduplication,
    creates a job record, and fires the pipeline task in the background.
    """
    raw_json = await request.json()
    logger.info("webhook_received", payload_size=len(request.headers.get("content-length", "0")))
    return await ingest_alert(raw_json, webhook_handler, "WEBHOOK", background_tasks)

@router.post("/syslog", dependencies=[Depends(validate_eset_token)])
async def receive_syslog_payload(
    request: Request,
    background_tasks: BackgroundTasks
) -> dict[str, Any]:
    """
    Endpoint for incoming Syslog events forwarded by our Syslog server.
    Parses payload, performs deduplication, creates a job record, and fires background task.
    """
    raw_json = await request.json()
    logger.info("syslog_http_received", payload_size=len(request.headers.get("content-length", "0")))
    return await ingest_alert(raw_json, syslog_handler, "SYSLOG", background_tasks)
