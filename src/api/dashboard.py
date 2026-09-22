import base64
import collections
import hmac
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Any
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, field_validator
import structlog
from src.config import settings
from src.storage import job_store, settings_store, delivery_store
from src.services import email_outbox, email_dispatcher
from src.services.email_delivery import get_provider
from src.services import pipeline_capacity
from src.services import log_reader
from src.services.output_writer import alert_labels
from src.api.webhook import run_pipeline_task
from src.middleware.security import auth_limiter, client_key

router = APIRouter(prefix="/dashboard/api", tags=["Dashboard"])
logger = structlog.get_logger(__name__)

LOG_PATH = settings.log_file


def _check_access(request: Request) -> None:
    """
    If DASHBOARD_ACCESS_KEY is configured, require it on every dashboard API call
    via the X-Dashboard-Key header. Comparison is constant-time, matching the
    webhook token check in src/middleware/auth.py.

    When the key is blank the dashboard is fully open — acceptable for a trusted
    local bind, but see README's security notes before exposing the port.
    """
    if not settings.dashboard_access_key:
        return
    client_ip = client_key(request)
    wait = auth_limiter.retry_after(client_ip)
    if wait:
        raise HTTPException(status_code=429, detail="Too many failed attempts",
                            headers={"Retry-After": str(wait)})
    provided = request.headers.get("x-dashboard-key") or ""
    if not hmac.compare_digest(provided.encode("utf-8"), settings.dashboard_access_key.encode("utf-8")):
        if provided:
            auth_limiter.record_failure(client_ip)
        logger.warning("dashboard_auth_failed", client_ip=client_ip, path=request.url.path)
        raise HTTPException(status_code=401, detail="Invalid or missing dashboard key")


@router.get("/jobs")
async def get_jobs(request: Request, limit: int = 50, offset: int = 0, status: str | None = None) -> dict[str, Any]:
    _check_access(request)
    limit = max(1, min(limit, 500))
    offset = max(0, offset)
    jobs = await job_store.list_jobs(limit=limit, offset=offset, status=status)
    return {"jobs": jobs}


@router.get("/jobs/{correlation_id}")
async def get_job_detail(request: Request, correlation_id: str) -> dict[str, Any]:
    _check_access(request)
    job = await job_store.get_job(correlation_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    result: dict[str, Any] | None = None
    # correlation_id comes from the DB lookup above, so it is a known-good value
    output_path = os.path.join(settings.output_dir, f"{correlation_id}.json")
    if os.path.exists(output_path):
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                result = json.load(f)
        except Exception as e:
            logger.warning("dashboard_job_detail_output_read_failed", error=str(e))

    return {"job": job, "result": result}


@router.get("/alerts")
async def get_alerts(request: Request) -> dict[str, Any]:
    _check_access(request)
    index_path = os.path.join(settings.output_dir, "index.json")
    if not os.path.exists(index_path):
        return {"alerts": []}
    try:
        with open(index_path, "r", encoding="utf-8") as f:
            records = json.load(f)
    except Exception as e:
        logger.warning("dashboard_alerts_read_failed", error=str(e))
        records = []
    for record in records:
        if "detection_name" not in record and "endpoint_name" not in record:
            record.update(_labels_from_result(record.get("correlation_id", "")))
    return {"alerts": list(reversed(records))}


_label_cache: dict[str, dict[str, str]] = {}


def _labels_from_result(correlation_id: str) -> dict[str, str]:
    """
    Backfill for index.json records written before they carried the
    normalized detection/endpoint names. Result files never change once
    written, so each one is read at most once per process.
    """
    if correlation_id in _label_cache:
        return _label_cache[correlation_id]
    labels: dict[str, str] = {}
    if re.fullmatch(r"[A-Za-z0-9-]{1,64}", correlation_id or ""):
        path = os.path.join(settings.output_dir, f"{correlation_id}.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                labels = alert_labels(json.load(f).get("normalized_alert"))
        except Exception:
            labels = {}
    if len(_label_cache) < 20_000:
        _label_cache[correlation_id] = labels
    return labels


@router.get("/emails")
async def get_emails(request: Request) -> dict[str, Any]:
    _check_access(request)
    emails = await email_outbox.list_emails()
    return {"emails": list(reversed(emails))}


def _read_results(limit: int) -> list[dict[str, Any]]:
    """
    Loads the most recent pipeline result files, newest first, using index.json
    for ordering so we never have to stat every file in the directory.
    """
    index_path = os.path.join(settings.output_dir, "index.json")
    if not os.path.exists(index_path):
        return []
    try:
        with open(index_path, "r", encoding="utf-8") as f:
            records = json.load(f)
    except Exception:
        return []

    results = []
    for record in reversed(records):
        if len(results) >= limit:
            break
        path = os.path.join(settings.output_dir, f"{record['correlation_id']}.json")
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                results.append(json.load(f))
        except Exception:
            continue
    return results


@router.get("/ai-content")
async def get_ai_content(request: Request, limit: int = 25) -> dict[str, Any]:
    """
    The AI's assessment of recent alerts, plus the notifications it drafted from
    that assessment — browsable on its own without digging through alert detail.

    Carries the alert context the assessment was made from (the normalized facts,
    the deterministic risk level and its rationale, and the threat-intel
    verdicts) alongside the AI output. Without it the view can only show the
    drafted emails, which leaves the reader unable to judge whether what the AI
    wrote is supported by what the alert actually said.
    """
    _check_access(request)
    limit = max(1, min(limit, 100))

    items = []
    for result in _read_results(limit * 3):
        if not result.get("ai_output"):
            continue
        alert = result.get("normalized_alert", {})
        items.append({
            "correlation_id": result["correlation_id"],
            "processed_at": result.get("processed_at"),
            "pipeline_status": result.get("pipeline_status"),
            "risk_level": result.get("risk_level"),
            # Why the risk engine decided that, so the AI's summary can be read
            # against the determination it was given rather than in isolation.
            "risk_rationale": result.get("risk_rationale"),
            "detection_name": alert.get("detection_name"),
            "endpoint_name": alert.get("endpoint_name"),
            "alert": alert,
            "threat_intel": result.get("threat_intel"),
            "ai_output": result["ai_output"],
        })
        if len(items) >= limit:
            break
    return {"items": items}


@router.get("/stats")
async def get_stats(request: Request, hours: int = 24) -> dict[str, Any]:
    """Aggregates for the dashboard charts: status/risk/source splits and a time series."""
    _check_access(request)
    hours = max(1, min(hours, 168))

    now = time.time()
    start = now - hours * 3600
    jobs = await job_store.list_jobs(limit=2000, created_after=start, created_before=now)
    by_status = collections.Counter(j["status"] for j in jobs)
    by_source = collections.Counter(j["source"] for j in jobs)
    window_ids = {j["correlation_id"] for j in jobs}

    # Risk levels live in the result files, not the jobs table
    by_risk = collections.Counter()
    for result in _read_results(2000):
        if result.get("correlation_id") in window_ids and result.get("risk_level"):
            by_risk[result["risk_level"]] += 1

    # Hourly buckets over the requested window, oldest first
    buckets: dict[int, int] = {i: 0 for i in range(hours)}
    for job in jobs:
        created = job.get("created_at") or 0
        if created < start:
            continue
        idx = min(hours - 1, int((created - start) // 3600))
        buckets[idx] = buckets.get(idx, 0) + 1

    series = [
        {
            "t": datetime.fromtimestamp(start + i * 3600, tz=timezone.utc).isoformat(),
            "count": buckets[i],
        }
        for i in range(hours)
    ]

    outbox = await email_outbox.list_emails()
    return {
        "totals": {
            "jobs": len(jobs),
            "emails_pending": len(outbox),
        },
        "by_status": dict(by_status),
        "by_risk": dict(by_risk),
        "by_source": dict(by_source),
        "series": series,
        "window_hours": hours,
    }


@router.get("/logs")
async def get_logs(
    request: Request,
    page: int = 1,
    page_size: int | None = None,
    limit: int | None = None,
    level: str | None = None,
    source: str | None = None,
    event: str | None = None,
    q: str | None = None,
    since_minutes: int | None = None,
    sort: str = "desc",
) -> dict[str, Any]:
    """
    One page of the structured JSON log, filtered and sorted server-side.

    `level` and `source` take comma-separated lists (e.g. `warning,error`).
    `limit` is the pre-pagination name for `page_size`, still accepted.
    Parsing is incremental and cached (src/services/log_reader.py), so the
    dashboard's polling only pays for lines appended since its last call.
    """
    _check_access(request)
    size = max(1, min(page_size or limit or 100, 500))

    if not os.path.exists(LOG_PATH):
        return {"lines": [], "total": 0, "page": 1, "pages": 1, "page_size": size,
                "note": "the log file does not exist yet"}

    result = log_reader.query(
        LOG_PATH,
        page=page,
        page_size=size,
        levels=_log_csv(level, log_reader.LEVELS),
        sources=_log_csv(source, log_reader.SOURCES),
        event=event or None,
        q=q,
        since_minutes=since_minutes,
        sort="asc" if sort == "asc" else "desc",
    )
    result["total_scanned"] = result["total"]
    return result


LOG_EXPORT_MAX = 50_000


@router.get("/logs/export")
async def export_logs(
    request: Request,
    level: str | None = None,
    source: str | None = None,
    event: str | None = None,
    q: str | None = None,
    since_minutes: int | None = None,
    sort: str = "desc",
) -> Response:
    """
    Every entry matching the Logs view's current filters (up to
    LOG_EXPORT_MAX, newest first by default) as NDJSON — one JSON object per
    line, the same shape the log file itself uses. Already redacted.
    """
    _check_access(request)
    if not os.path.exists(LOG_PATH):
        lines: list[dict[str, Any]] = []
    else:
        lines = log_reader.query(
            LOG_PATH, page=1, page_size=LOG_EXPORT_MAX,
            levels=_log_csv(level, log_reader.LEVELS),
            sources=_log_csv(source, log_reader.SOURCES),
            event=event or None, q=q, since_minutes=since_minutes,
            sort="asc" if sort == "asc" else "desc",
        )["lines"]
    body = "".join(
        json.dumps({k: v for k, v in e.items() if not k.startswith("_")}, ensure_ascii=False, default=str) + "\n"
        for e in lines
    )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return Response(
        content=body, media_type="application/x-ndjson",
        headers={"Content-Disposition": f'attachment; filename="soc-lite-logs-{stamp}.ndjson"'},
    )


def _log_csv(value: str | None, allowed: tuple[str, ...]) -> set[str] | None:
    if not value:
        return None
    picked = {v.strip().lower() for v in value.split(",")} & set(allowed)
    return picked or None


# Deliberately strict rather than RFC-complete: this field decides where every
# future SOC notification is delivered, so the cost of rejecting an exotic-but-
# legal address is a support question, while the cost of accepting a malformed
# one is alerts going somewhere nobody reads — or somewhere they should not go.
_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


class RecipientUpdate(BaseModel):
    client_notification_emails: str | None = None
    cthree_notification_emails: str | None = None
    internal_notification_emails: str | None = None
    engineer_notification_emails: str | None = None

    @field_validator("*")
    @classmethod
    def _validate_recipient_list(cls, value: str | None) -> str | None:
        """
        Every element of the comma-separated list must look like an email address.

        Without this the field was free text written verbatim to the settings
        table: one authenticated write could point every client/C-Three/internal/
        engineer notification — subject line, AI assessment, endpoint, user and
        file detail — at an arbitrary mailbox, persistently and across restarts.
        The stored value is also normalized here (whitespace trimmed, empties
        dropped) so what the settings page reads back is what will actually be
        used by src/services/email_composer.py.
        """
        if value is None:
            return None
        addresses = [part.strip() for part in value.split(",")]
        cleaned = [addr for addr in addresses if addr]
        for addr in cleaned:
            if not _EMAIL_RE.match(addr):
                raise ValueError(f"Not a valid email address: {addr!r}")
        return ", ".join(cleaned)


@router.get("/settings")
async def get_settings(request: Request) -> dict[str, Any]:
    """Current email recipient configuration, and where each value came from."""
    _check_access(request)
    return {
        "recipients": await settings_store.get_recipient_config(),
        "runtime": {
            "dedup_ttl_seconds": settings.dedup_ttl_seconds,
            "ai_timeout_seconds": settings.ai_timeout_seconds,
            "threat_intel_timeout_seconds": settings.threat_intel_timeout_seconds,
            "use_mock_threat_intel": settings.use_mock_threat_intel,
            "output_dir": settings.output_dir,
            "syslog_udp_port": settings.syslog_udp_port,
            "syslog_tcp_port": settings.syslog_tcp_port,
            "dashboard_protected": bool(settings.dashboard_access_key),
        },
        "delivery": email_dispatcher.delivery_status(),
        "security": _security_posture(request),
    }


def _security_posture(request: Request) -> list[dict[str, str]]:
    """
    Deployment checklist for Settings: one entry per control, each "ok",
    "warn" or "bad". Reports only whether something is configured, never a
    secret or its length.
    """
    def strong(secret: str) -> bool:
        return len(secret) >= 16 and secret.lower() not in {"test", "change-me", "changeme"}

    key, token = settings.dashboard_access_key, settings.eset_webhook_auth_token
    return [
        {"id": "env", "status": "ok" if settings.app_env.lower() == "production" else "warn"},
        {"id": "dashboard_key", "status": "ok" if strong(key) else ("warn" if key else "bad")},
        {"id": "webhook_token", "status": "ok" if strong(token) else "bad"},
        {"id": "https", "status": "ok" if request.url.scheme == "https" else "warn"},
        {"id": "api_docs", "status": "warn" if settings.enable_api_docs else "ok"},
        {"id": "auth_throttle", "status": "ok" if settings.auth_max_failures > 0 else "warn"},
        {"id": "syslog_allowlist", "status": "ok" if settings.syslog_allowed_sources.strip() else "warn"},
        {"id": "ai_masking", "status": "ok" if settings.ai_masking_enabled else "warn"},
        {"id": "email_delivery", "status": "ok" if settings.email_delivery_enabled else "warn"},
    ]


@router.put("/settings/recipients")
async def update_recipients(request: Request, payload: RecipientUpdate) -> dict[str, Any]:
    """Saves notification recipients; takes effect on the next alert, no restart."""
    _check_access(request)
    values = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not values:
        raise HTTPException(status_code=400, detail="No recipient fields supplied")

    # Capture the outgoing values before the write: "notifications stopped
    # arriving" is only diagnosable if the log says what the addresses were
    # changed FROM, not just which fields were touched.
    previous = await settings_store.get_recipient_config()
    updated = await settings_store.update_recipients(values)
    logger.info(
        "dashboard_recipients_updated",
        keys=updated,
        previous={k: (previous.get(k) or {}).get("value") for k in values},
        new=values,
        client_ip=request.client.host if request.client else "unknown",
    )
    return {"status": "saved", "updated": updated, "recipients": await settings_store.get_recipient_config()}


@router.get("/delivery")
async def get_delivery_overview(
    request: Request, limit: int = 100, status: str | None = None,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    """
    Handoff state: configuration, per-email history, and the mail service's own
    queue counters (the part of the lifecycle it owns after accepting a message).

    `correlation_id` narrows the history to one alert's own emails — used by the
    Pipeline Flow EMAIL/SEND stage detail and the alert detail modal to show what
    happened to THIS alert's notifications, instead of the operator having to
    scan the full Emails view for a matching subject line.
    """
    _check_access(request)
    limit = max(1, min(limit, 500))
    return {
        "config": email_dispatcher.delivery_status(),
        "counts": await delivery_store.counts_by_status(),
        "deliveries": await delivery_store.list_deliveries(
            limit=limit, status=status, correlation_id=correlation_id,
        ),
        "pending_in_outbox": len(await email_outbox.list_emails()),
        # Notifications handoff has permanently given up on. Surfaced here
        # because a dead letter that nobody can see is just a quieter way of
        # losing the alert.
        "dead_lettered": await email_outbox.list_dead_letters(),
    }


@router.get("/delivery/service-status")
async def get_mail_service_status(request: Request) -> dict[str, Any]:
    """Live queue counters from the mail service itself."""
    _check_access(request)
    provider = get_provider()
    fetch = getattr(provider, "fetch_service_status", None)
    if fetch is None:
        return {"available": False, "error": f"{provider.name} exposes no status endpoint"}
    return await fetch()


@router.post("/delivery/dispatch")
async def trigger_dispatch(request: Request) -> dict[str, Any]:
    """Hands off everything currently queued, now, instead of waiting for the sweeper."""
    _check_access(request)
    result = await email_dispatcher.dispatch_pending()
    logger.info("dashboard_dispatch_triggered", **{k: v for k, v in result.items() if k != "skipped"})
    return result


@router.delete("/emails/{email_id}")
async def delete_email(request: Request, email_id: str) -> dict[str, Any]:
    """Discards a pending email from the outbox."""
    _check_access(request)
    before = len(await email_outbox.list_emails())
    await email_outbox.remove_email(email_id)
    after = len(await email_outbox.list_emails())
    if before == after:
        raise HTTPException(status_code=404, detail="Email not found in outbox")
    return {"status": "removed", "email_id": email_id}


@router.post("/jobs/{correlation_id}/retry")
async def retry_job(request: Request, correlation_id: str, background_tasks: BackgroundTasks) -> dict[str, Any]:
    """
    Re-runs the pipeline for a FAILED/PARTIAL job using its already-stored raw_payload.
    """
    _check_access(request)
    job = await job_store.get_job(correlation_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job["status"] not in ("FAILED", "PARTIAL"):
        raise HTTPException(status_code=400, detail=f"Only FAILED/PARTIAL jobs can be retried (current status: {job['status']})")

    try:
        reservation = pipeline_capacity.capacity.reserve(correlation_id)
    except pipeline_capacity.PipelineAlreadyActive:
        raise HTTPException(status_code=409, detail="This job already has an active pipeline")
    except pipeline_capacity.CapacityExhausted:
        raise pipeline_capacity.overloaded()

    try:
        await job_store.update_job_status(correlation_id, "PENDING")
        background_tasks.add_task(
            reservation.run, run_pipeline_task, correlation_id, job["raw_payload"], job["source"],
        )
    except BaseException:
        reservation.release()
        raise
    return {"status": "retrying", "correlation_id": correlation_id}


def _origin_allowed(websocket: WebSocket) -> bool:
    """
    Rejects cross-site WebSocket connections. Browsers do not apply the same-origin
    policy to WebSockets, so without this any page the operator visits could open a
    socket to this server and stream every alert (CSWSH).
    """
    origin = websocket.headers.get("origin")
    if origin is None:
        return True  # non-browser client (scripts/tests) — not a CSWSH vector
    host = websocket.headers.get("host", "")
    return origin.split("://")[-1] == host


# The dashboard key travels as a WebSocket subprotocol offer, base64url-encoded
# so it is always a legal subprotocol token whatever characters the key contains.
_WS_KEY_PREFIX = "socpass."


def _ws_supplied_key(websocket: WebSocket) -> str:
    """
    Extracts the dashboard key a client offered on the WebSocket handshake.

    Why not a query parameter, which is what this used to be: uvicorn logs the
    handshake line including the full query string, run.py routes uvicorn's
    loggers into logs/app.log, and /dashboard/api/logs serves that same file back
    through the dashboard. The key ended up in cleartext in a world-readable log
    that the product itself publishes — plus browser history and any intermediary
    proxy. A subprotocol offer is a request header: not logged in the access
    line, not in history, not in a Referer.

    Falls back to ?key= so an operator's existing script or bookmark keeps
    working; the bundled dashboard no longer uses it.
    """
    offered = websocket.headers.get("sec-websocket-protocol", "")
    for token in (t.strip() for t in offered.split(",")):
        if token.startswith(_WS_KEY_PREFIX):
            encoded = token[len(_WS_KEY_PREFIX):]
            try:
                padding = "=" * (-len(encoded) % 4)
                return base64.urlsafe_b64decode(encoded + padding).decode("utf-8")
            except Exception:
                return ""
    return websocket.query_params.get("key") or ""


@router.websocket("/ws")
async def dashboard_ws(websocket: WebSocket) -> None:
    if not _origin_allowed(websocket):
        logger.warning("dashboard_ws_origin_rejected", origin=websocket.headers.get("origin"))
        await websocket.close(code=4403)
        return

    if settings.dashboard_access_key:
        client_ip = client_key(websocket)
        if auth_limiter.retry_after(client_ip):
            await websocket.close(code=4429)
            return
        provided = _ws_supplied_key(websocket)
        if not hmac.compare_digest(provided.encode("utf-8"), settings.dashboard_access_key.encode("utf-8")):
            if provided:
                auth_limiter.record_failure(client_ip)
            logger.warning("dashboard_ws_auth_failed", client_ip=client_ip)
            await websocket.close(code=4401)
            return

    broadcaster = websocket.app.state.broadcaster
    # A client that offered a subprotocol must be answered with one it offered,
    # or the browser drops the connection right after the handshake.
    offered = websocket.headers.get("sec-websocket-protocol", "")
    accepted = next(
        (t.strip() for t in offered.split(",") if t.strip().startswith(_WS_KEY_PREFIX)),
        None,
    )
    await broadcaster.connect(websocket, subprotocol=accepted)
    try:
        while True:
            # Dashboard clients don't send anything; this just keeps the
            # connection open and detects disconnects.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        broadcaster.disconnect(websocket)
