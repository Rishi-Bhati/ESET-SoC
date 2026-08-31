import asyncio
import hashlib
import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, BackgroundTasks
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


def _reject_oversized_body(request: Request) -> int:
    """
    Defense-in-depth guard: rejects a request whose declared Content-Length exceeds
    MAX_INGEST_BODY_BYTES before the body is parsed. This is a header check, not a
    hard cap enforced on the wire (a sender could omit or lie about Content-Length),
    but it stops a straightforwardly oversized payload from reaching JSON parsing
    and the pipeline. Returns the parsed content length (0 if not provided) so
    callers can also use it for logging.
    """
    raw = request.headers.get("content-length")
    if not raw:
        return 0

    try:
        content_length = int(raw)
    except ValueError:
        return 0

    if content_length > settings.max_ingest_body_bytes:
        logger.warning(
            "ingest_payload_too_large",
            content_length=content_length,
            limit=settings.max_ingest_body_bytes,
        )
        raise HTTPException(status_code=413, detail="Payload too large")

    return content_length


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


async def run_pipeline_task(
    correlation_id: str,
    raw_payload: dict[str, Any],
    source: str,
) -> None:
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
        logger.error(
            "background_pipeline_uncaught_error",
            error=str(e),
            correlation_id=correlation_id,
        )


def scrub_unencodable(value: Any) -> Any:
    """
    Replaces UTF-8-unencodable code points anywhere in a decoded JSON structure.

    `json.loads` accepts lone surrogates (`"\\ud800"`), and a detection name or
    file path in an ESET alert ultimately reflects whatever an attacker managed
    to name a file or process. Such a string survives happily in memory but
    raises UnicodeEncodeError the moment anything durable touches it — the
    SQLite bind in delivery_store.record_pending(), or the compact-JSON
    serialisation of an outbound email. Because the alert is already persisted
    in the outbox by then, the same failure repeats on every later sweep.

    Scrubbing once at ingest keeps that class of payload from reaching any
    downstream stage, rather than defending each one separately.
    """
    if isinstance(value, str):
        return value.encode("utf-8", "replace").decode("utf-8")
    if isinstance(value, dict):
        return {scrub_unencodable(k): scrub_unencodable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub_unencodable(item) for item in value]
    return value


async def read_json_body(request: Request) -> dict[str, Any]:
    """
    Reads and validates the request body as a JSON object.

    A sender that emits a malformed frame (bad escape, truncated body, wrong
    content type) is a client error, not a server fault: answer 400 rather than
    letting json.JSONDecodeError bubble up as a 500 with a stack trace that
    leaks internal paths.
    """
    body = await request.body()

    try:
        parsed = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.warning(
            "ingest_malformed_json",
            error=str(e),
            byte_length=len(body),
        )
        raise HTTPException(
            status_code=400,
            detail=f"Request body is not valid JSON: {e}",
        )

    if not isinstance(parsed, dict):
        logger.warning(
            "ingest_non_object_body",
            type=type(parsed).__name__,
        )
        raise HTTPException(
            status_code=400,
            detail=f"Request body must be a JSON object, got {type(parsed).__name__}",
        )

    return scrub_unencodable(parsed)


async def ingest_alert(
    raw_json: dict[str, Any],
    handler: WebhookIngestionHandler | SyslogIngestionHandler,
    source: str,
    background_tasks: BackgroundTasks,
) -> dict[str, Any]:
    """
    Shared ingestion path used by both the public /webhook/eset and /webhook/syslog
    routes below: parse -> dedup -> job -> pipeline. Simulated alerts for local/manual
    testing go through this exact path too, via scripts/send_test_webhook.sh and
    scripts/send_test_syslog.py (there is no dashboard "send test alert" control today).
    """
    correlation_id = generate_correlation_id()
    set_correlation_id(correlation_id)

    try:
        raw_payload = handler.parse(raw_json)
    except ValueError as e:
        logger.warning(
            "ingest_invalid_payload",
            error=str(e),
            source=source,
        )
        raise HTTPException(status_code=400, detail=str(e))

    dedup_key = compute_dedup_key(raw_payload)

    if await deduplication.is_duplicate(dedup_key):
        logger.info(
            "ingest_duplicate_dropped",
            dedup_key=dedup_key,
            source=source,
        )
        return {
            "status": "duplicate",
            "message": "Alert already processed",
            "correlation_id": correlation_id,
        }

    await deduplication.record_seen(
        dedup_key,
        settings.dedup_ttl_seconds,
    )

    payload_dict = raw_payload.model_dump()

    await job_store.create_job(
        correlation_id,
        source,
        payload_dict,
    )

    background_tasks.add_task(
        run_pipeline_task,
        correlation_id,
        payload_dict,
        source,
    )

    return {
        "status": "queued",
        "correlation_id": correlation_id,
    }


@router.post("/eset", dependencies=[Depends(validate_eset_token)])
async def receive_eset_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
) -> dict[str, Any]:
    """
    Endpoint for ESET webhooks. Parses payload, performs deduplication,
    creates a job record, and fires the pipeline task in the background.
    """
    content_length = _reject_oversized_body(request)
    raw_json = await read_json_body(request)

    logger.info(
        "webhook_received",
        payload_size=content_length,
    )

    return await ingest_alert(
        raw_json,
        webhook_handler,
        "WEBHOOK",
        background_tasks,
    )


@router.post("/syslog", dependencies=[Depends(validate_eset_token)])
async def receive_syslog_payload(
    request: Request,
    background_tasks: BackgroundTasks,
) -> dict[str, Any]:
    """
    Endpoint for incoming Syslog events forwarded by our Syslog server.
    Parses payload, performs deduplication, creates a job record, and fires background task.
    """
    content_length = _reject_oversized_body(request)
    raw_json = await read_json_body(request)

    logger.info(
        "syslog_http_received",
        payload_size=content_length,
    )

    return await ingest_alert(
        raw_json,
        syslog_handler,
        "SYSLOG",
        background_tasks,
    )