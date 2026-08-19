import collections
import hmac
import json
import os
import time
from datetime import datetime, timezone
from typing import Any
from fastapi import APIRouter, BackgroundTasks, HTTPException, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel
import structlog
from src.config import settings
from src.storage import job_store, settings_store, delivery_store
from src.services import email_outbox, email_dispatcher
from src.services.email_delivery import get_provider
from src.api.webhook import run_pipeline_task

router = APIRouter(prefix="/dashboard/api", tags=["Dashboard"])
logger = structlog.get_logger(__name__)

LOG_PATH = "logs/app.log"


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
    provided = request.headers.get("x-dashboard-key") or ""
    if not hmac.compare_digest(provided, settings.dashboard_access_key):
        client_ip = request.client.host if request.client else "unknown"
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
    return {"alerts": list(reversed(records))}


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
    The AI-generated notifications for recent alerts — the content that becomes
    outbound email, browsable on its own without digging through alert detail.
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
            "risk_level": result.get("risk_level"),
            "detection_name": alert.get("detection_name"),
            "endpoint_name": alert.get("endpoint_name"),
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

    jobs = await job_store.list_jobs(limit=2000)
    by_status = collections.Counter(j["status"] for j in jobs)
    by_source = collections.Counter(j["source"] for j in jobs)

    # Risk levels live in the result files, not the jobs table
    by_risk = collections.Counter()
    for result in _read_results(2000):
        if result.get("risk_level"):
            by_risk[result["risk_level"]] += 1

    # Hourly buckets over the requested window, oldest first
    now = time.time()
    start = now - hours * 3600
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
    limit: int = 200,
    level: str | None = None,
    q: str | None = None,
) -> dict[str, Any]:
    """
    Tails the structured JSON log. Reads only the end of the file so a large log
    never blows up memory.
    """
    _check_access(request)
    limit = max(1, min(limit, 1000))

    if not os.path.exists(LOG_PATH):
        return {"lines": [], "note": "logs/app.log does not exist yet"}

    # Read the trailing chunk rather than the whole file
    max_bytes = 2_000_000
    with open(LOG_PATH, "rb") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        f.seek(max(0, size - max_bytes))
        raw = f.read().decode("utf-8", errors="ignore")

    lines = []
    for text in raw.splitlines():
        text = text.strip()
        if not text:
            continue
        try:
            entry = json.loads(text)
        except Exception:
            continue  # partial first line, or non-JSON console output
        if level and (entry.get("level") or "").lower() != level.lower():
            continue
        if q and q.lower() not in text.lower():
            continue
        lines.append(entry)

    return {"lines": lines[-limit:], "total_scanned": len(lines)}


class RecipientUpdate(BaseModel):
    client_notification_emails: str | None = None
    cthree_notification_emails: str | None = None
    internal_notification_emails: str | None = None
    engineer_notification_emails: str | None = None


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
    }


@router.put("/settings/recipients")
async def update_recipients(request: Request, payload: RecipientUpdate) -> dict[str, Any]:
    """Saves notification recipients; takes effect on the next alert, no restart."""
    _check_access(request)
    values = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not values:
        raise HTTPException(status_code=400, detail="No recipient fields supplied")

    updated = await settings_store.update_recipients(values)
    logger.info("dashboard_recipients_updated", keys=updated)
    return {"status": "saved", "updated": updated, "recipients": await settings_store.get_recipient_config()}


@router.get("/delivery")
async def get_delivery_overview(request: Request, limit: int = 100, status: str | None = None) -> dict[str, Any]:
    """
    Handoff state: configuration, per-email history, and the mail service's own
    queue counters (the part of the lifecycle it owns after accepting a message).
    """
    _check_access(request)
    limit = max(1, min(limit, 500))
    return {
        "config": email_dispatcher.delivery_status(),
        "counts": await delivery_store.counts_by_status(),
        "deliveries": await delivery_store.list_deliveries(limit=limit, status=status),
        "pending_in_outbox": len(await email_outbox.list_emails()),
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

    await job_store.update_job_status(correlation_id, "PENDING")
    background_tasks.add_task(run_pipeline_task, correlation_id, job["raw_payload"], job["source"])
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


@router.websocket("/ws")
async def dashboard_ws(websocket: WebSocket) -> None:
    if not _origin_allowed(websocket):
        logger.warning("dashboard_ws_origin_rejected", origin=websocket.headers.get("origin"))
        await websocket.close(code=4403)
        return

    if settings.dashboard_access_key:
        provided = websocket.query_params.get("key") or ""
        if not hmac.compare_digest(provided, settings.dashboard_access_key):
            await websocket.close(code=4401)
            return

    broadcaster = websocket.app.state.broadcaster
    await broadcaster.connect(websocket)
    try:
        while True:
            # Dashboard clients don't send anything; this just keeps the
            # connection open and detects disconnects.
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        broadcaster.disconnect(websocket)
