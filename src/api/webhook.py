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
from src.services import pipeline_capacity
from src.utils.correlation import generate_correlation_id, set_correlation_id
from src.config import settings

# We will dynamically import the orchestrator to avoid circular dependency
# when setting up imports.
# In production, we wire it through background tasks.

router = APIRouter(prefix="/webhook", tags=["Webhook"])
logger = structlog.get_logger(__name__)
webhook_handler = WebhookIngestionHandler()
syslog_handler = SyslogIngestionHandler()

# Bound on how much of a REJECTED request's body is written to the log. A
# request that is dropped before a job exists (oversized, malformed, duplicate,
# over capacity) leaves no other trace of itself anywhere in this platform — no
# job row, no result file, no Alert Timeline — so the log is the only place an
# operator can ever answer "what did that request actually contain, and why
# didn't it become an alert". Capped well below the ingest size limit itself so
# a sender that is oversized ON PURPOSE cannot also make the log file grow
# without bound.
_LOG_BODY_PREVIEW_LIMIT = 4000


def _body_preview(value: Any) -> Any:
    """
    A bounded, loggable version of a rejected request's body.

    Passed through as the real parsed object (dict/list/etc.), not pre-
    stringified, whenever it fits under the cap — logging it as structured data
    means structlog's own key-based secret redaction (redact_secrets in
    src/utils/logging.py, applied to every log call before it reaches disk)
    still runs on it, the same as any other logged field. Only falls back to a
    truncated string once the serialized form is actually too large to log in
    full, or isn't JSON at all (a malformed body, logged from raw bytes).
    """
    try:
        serialized = json.dumps(value, ensure_ascii=False, default=str)
    except Exception:
        text = str(value)
        return text if len(text) <= _LOG_BODY_PREVIEW_LIMIT else text[:_LOG_BODY_PREVIEW_LIMIT] + "…[truncated]"
    if len(serialized) <= _LOG_BODY_PREVIEW_LIMIT:
        return value
    return serialized[:_LOG_BODY_PREVIEW_LIMIT] + "…[truncated]"


def _raw_body_preview(body: bytes) -> str:
    """Same bound, for a body that failed to parse as JSON at all — all that's
    left to show is the decoded bytes themselves.

    Slices the BYTES before decoding, not just the resulting string: a caller
    reporting an oversized single chunk can hand this tens of megabytes, and
    decoding all of it just to keep the first 4000 characters would spend CPU
    proportional to the full chunk on every oversized request — the exact cost
    the streaming read in read_json_body() exists to avoid. A UTF-8 sequence
    sliced mid-character at the boundary decodes safely to U+FFFD via
    errors="replace", so no extra care is needed there.
    """
    # A little headroom over the character cap for multi-byte UTF-8 sequences;
    # still a small, fixed slice regardless of how large `body` actually is.
    text = body[: _LOG_BODY_PREVIEW_LIMIT + 16].decode("utf-8", errors="replace")
    return text if len(text) <= _LOG_BODY_PREVIEW_LIMIT else text[:_LOG_BODY_PREVIEW_LIMIT] + "…[truncated]"


def _reject_oversized_body(request: Request) -> int:
    """
    Fast path: reject a request whose DECLARED Content-Length is already over
    MAX_INGEST_BODY_BYTES, before a single byte of body is read.

    This is only the cheap half of the cap. A sender can omit Content-Length
    entirely (Transfer-Encoding: chunked), in which case this returns 0 and
    nothing here applies — the enforced limit is the byte counter in
    read_json_body(), which is what actually bounds memory. Keep both: this one
    saves reading a body that has already announced it is too big.

    Returns the parsed content length (0 if not provided) so callers can also
    use it for logging.
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

    The body is streamed and counted rather than read with request.body(): a
    chunked request declares no Content-Length, so the header check in
    _reject_oversized_body() never fires for one, and request.body() would
    accumulate an unbounded stream into memory until the process was OOM-killed
    — taking the dashboard and the syslog listeners down with it, since they
    share this process. Counting as we go means an oversized sender is cut off
    at the limit instead of at the memory ceiling.
    """
    body = bytearray()
    async for chunk in request.stream():
        bytes_read = len(body) + len(chunk)
        if bytes_read > settings.max_ingest_body_bytes:
            logger.warning(
                "ingest_payload_too_large_stream",
                bytes_read=bytes_read,
                limit=settings.max_ingest_body_bytes,
                # `body` plus the ONE chunk that tripped the limit, not `body`
                # alone: most real requests arrive as a single ASGI chunk, so
                # previewing only what was accumulated BEFORE that chunk would
                # log an empty preview for exactly the common case. Still
                # bounded — _raw_body_preview caps it regardless of how large
                # this one chunk is, so the "never hold the full oversized body"
                # guarantee this streaming read exists for is unaffected.
                body_preview=_raw_body_preview(bytes(body) + chunk[:_LOG_BODY_PREVIEW_LIMIT + 16]),
            )
            raise HTTPException(status_code=413, detail="Payload too large")
        body.extend(chunk)
    body = bytes(body)

    try:
        parsed = json.loads(body)
        parsed = scrub_unencodable(parsed)
    except RecursionError:
        logger.warning(
            "ingest_too_deeply_nested",
            byte_length=len(body),
            body_preview=_raw_body_preview(body),
        )
        raise HTTPException(status_code=400, detail="Request body JSON is nested too deeply")
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.warning(
            "ingest_malformed_json",
            error=str(e),
            byte_length=len(body),
            body_preview=_raw_body_preview(body),
        )
        raise HTTPException(
            status_code=400,
            detail=f"Request body is not valid JSON: {e}",
        )

    if not isinstance(parsed, dict):
        logger.warning(
            "ingest_non_object_body",
            type=type(parsed).__name__,
            body_preview=_body_preview(parsed),
        )
        raise HTTPException(
            status_code=400,
            detail=f"Request body must be a JSON object, got {type(parsed).__name__}",
        )

    return parsed


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
            body_preview=_body_preview(raw_json),
        )
        raise HTTPException(status_code=400, detail=str(e))

    dedup_key = compute_dedup_key(raw_payload)

    if await deduplication.is_duplicate(dedup_key):
        logger.info(
            "ingest_duplicate_dropped",
            dedup_key=dedup_key,
            source=source,
            correlation_id=correlation_id,
            body_preview=_body_preview(raw_json),
        )
        return {
            "status": "duplicate",
            "message": "Alert already processed",
            "correlation_id": correlation_id,
        }

    try:
        reservation = pipeline_capacity.capacity.reserve(correlation_id, dedup_key)
    except (pipeline_capacity.CapacityExhausted, pipeline_capacity.PipelineAlreadyActive):
        # A concurrent request may have persisted this key while our initial
        # dedup check was in flight. It needs no additional pipeline slot.
        if await deduplication.is_duplicate(dedup_key):
            return {
                "status": "duplicate",
                "message": "Alert already processed",
                "correlation_id": correlation_id,
            }
        logger.warning(
            "ingest_capacity_exhausted",
            source=source,
            correlation_id=correlation_id,
            body_preview=_body_preview(raw_json),
        )
        raise pipeline_capacity.overloaded()

    try:
        await deduplication.record_seen(dedup_key, settings.dedup_ttl_seconds)
        payload_dict = raw_payload.model_dump()
        await job_store.create_job(correlation_id, source, payload_dict)
        background_tasks.add_task(
            reservation.run, run_pipeline_task, correlation_id, payload_dict, source,
        )
    except BaseException:
        reservation.release()
        raise

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
